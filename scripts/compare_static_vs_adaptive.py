from __future__ import annotations

import argparse
import gc
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def generate_benchmark_dataset(path: Path, count: int) -> int:
    """Generate deterministic, realistic security telemetry records."""
    path.parent.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    hosts = [f"SRV-APP-{i:02d}" for i in range(1, 11)] + [f"WS-USER-{i:02d}" for i in range(1, 41)]
    users = ["admin", "alice", "bob", "carol", "service_account", "system"]
    actions = [
        ("authentication", "failure", "low"),
        ("authentication", "success", "low"),
        ("process_creation", "start", "medium"),
        ("file_modification", "write", "medium"),
        ("network_traffic", "connect", "low"),
    ]

    with path.open("w", encoding="utf-8", buffering=8 * 1024 * 1024) as f:
        for i in range(count):
            t = base_time + timedelta(seconds=i * 0.1)
            cat, act, sev = actions[i % len(actions)]
            host = hosts[i % len(hosts)]
            user = users[i % len(users)]
            rec = {
                "@timestamp": t.isoformat(),
                "event": {"id": f"bench-evt-{i:07d}", "category": [cat], "action": act, "severity": sev},
                "host": {"name": host},
                "user": {"name": user},
                "source": {"ip": f"10.0.{i % 250}.{1 + (i % 254)}"},
                "destination": {"ip": f"172.16.1.{1 + (i % 254)}"},
                "process": {"name": "powershell.exe" if i % 100 == 0 else "svchost.exe", "pid": str(1000 + (i % 5000))},
            }
            if cat == "file_modification" and (i % 200 < 60):
                # Ransomware simulation pattern: mass modifications on same host
                rec["file"] = {"path": f"C:\\Users\\{user}\\Documents\\file_{i % 100}.enc"}
                rec["host"]["name"] = "WS-USER-01"
            f.write(json.dumps(rec) + "\n")
    return path.stat().st_size


def run_single_benchmark(source_file: Path, db_file: Path, adaptive: bool) -> dict:
    os.environ["CHAINSIGHT_ADAPTIVE_TUNING"] = "true" if adaptive else "false"
    if not adaptive:
        os.environ["CHAINSIGHT_BATCH_SIZE"] = "10000"
        os.environ["CHAINSIGHT_INGEST_BATCH_SIZE"] = "10000"

    gc.collect()
    db_file.unlink(missing_ok=True)

    from backend.ingestion.service import IngestionService
    from backend.ingestion.storage import Storage

    storage = Storage(db_file)
    service = IngestionService(storage)
    proc = psutil.Process(os.getpid())

    start_rss = proc.memory_info().rss
    t0 = time.perf_counter()
    status = service.process_sync(source_file)
    elapsed = max(time.perf_counter() - t0, 0.001)

    peak_rss = max(status.get("peak_memory_bytes", 0), proc.memory_info().rss)
    total_records = status.get("total_records", 0)
    eps = round(total_records / elapsed, 1)
    mb_s = round((source_file.stat().st_size / (1024 * 1024)) / elapsed, 2)

    result = {
        "engine": "Adaptive Self-Optimizing" if adaptive else "Static Batch",
        "records": total_records,
        "duration_seconds": round(elapsed, 2),
        "throughput_eps": eps,
        "throughput_mb_s": mb_s,
        "peak_rss_mb": round(peak_rss / (1024 * 1024), 1),
        "duckdb_memory_mb": round(status.get("duckdb_memory_bytes", 0) / (1024 * 1024), 1),
        "valid_records": status.get("valid_records", 0),
        "detections": status.get("detections", 0),
        "incidents": status.get("incidents", 0),
        "final_batch_size": status.get("batch_records", 10000),
        "bottleneck": status.get("bottleneck", "Balanced"),
    }
    db_file.unlink(missing_ok=True)
    return result


def main():
    parser = argparse.ArgumentParser(description="Compare Static vs Adaptive Ingestion Engine")
    parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 100_000, 1_000_000],
                        help="Record counts to benchmark (e.g. 10000 100000 1000000)")
    args = parser.parse_args()

    bench_dir = PROJECT_ROOT / "data" / "benchmarks"
    bench_dir.mkdir(parents=True, exist_ok=True)

    results = []
    print("=" * 80)
    print("ChainSight AI: Static vs Adaptive Engine Ingestion Benchmark")
    print("=" * 80)

    for count in args.sizes:
        print(f"\n[+] Preparing dataset with {count:,} records...")
        jsonl_path = bench_dir / f"bench_{count}.jsonl"
        size_bytes = generate_benchmark_dataset(jsonl_path, count)
        print(f"    Dataset created: {size_bytes / (1024*1024):.1f} MB on disk")

        db_static = bench_dir / f"db_static_{count}.duckdb"
        db_adaptive = bench_dir / f"db_adaptive_{count}.duckdb"

        print(f"    --> Running Static Engine benchmark...")
        static_res = run_single_benchmark(jsonl_path, db_static, adaptive=False)
        print(f"        Static:   {static_res['duration_seconds']}s | {static_res['throughput_eps']:,} eps | {static_res['throughput_mb_s']} MB/s | Peak RAM: {static_res['peak_rss_mb']} MB | Detections: {static_res['detections']}")

        print(f"    --> Running Adaptive Engine benchmark...")
        adaptive_res = run_single_benchmark(jsonl_path, db_adaptive, adaptive=True)
        speedup = round(adaptive_res["throughput_eps"] / max(static_res["throughput_eps"], 0.1), 2)
        print(f"        Adaptive: {adaptive_res['duration_seconds']}s | {adaptive_res['throughput_eps']:,} eps | {adaptive_res['throughput_mb_s']} MB/s | Peak RAM: {adaptive_res['peak_rss_mb']} MB | Detections: {adaptive_res['detections']} | Optimal Batch: {adaptive_res['final_batch_size']:,}")
        print(f"        Speedup:  {speedup}x")

        # Verify detection consistency
        assert static_res["valid_records"] == adaptive_res["valid_records"], "Mismatch in valid records!"
        assert static_res["detections"] == adaptive_res["detections"], "Mismatch in detections count!"
        assert static_res["incidents"] == adaptive_res["incidents"], "Mismatch in incident count!"

        results.append({
            "record_count": count,
            "dataset_mb": round(size_bytes / (1024*1024), 1),
            "static": static_res,
            "adaptive": adaptive_res,
            "speedup": speedup,
        })

        # Clean up source file
        jsonl_path.unlink(missing_ok=True)

    print("\n" + "=" * 96)
    print("BENCHMARK COMPARISON SUMMARY TABLE")
    print("=" * 96)
    print(f"{'Records':<10} | {'Size':<8} | {'Static Speed':<14} | {'Adaptive Speed':<16} | {'Static RAM':<12} | {'Adaptive RAM':<14} | {'Speedup':<8}")
    print("-" * 96)
    for r in results:
        s = r["static"]
        a = r["adaptive"]
        print(f"{r['record_count']:<10,d} | {r['dataset_mb']:>5.1f} MB | {s['throughput_eps']:>10,.1f} eps | {a['throughput_eps']:>12,.1f} eps | {s['peak_rss_mb']:>8.1f} MB | {a['peak_rss_mb']:>10.1f} MB | {r['speedup']:>6.2f}x")
    print("=" * 96)

    # Save summary json
    out_file = PROJECT_ROOT / "data" / "benchmark_comparison.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[+] Results saved to {out_file}")


if __name__ == "__main__":
    main()
