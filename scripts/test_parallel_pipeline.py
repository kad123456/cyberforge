from __future__ import annotations

import argparse
import gc
import os
import sys
import time
from pathlib import Path
import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.compare_static_vs_adaptive import generate_benchmark_dataset
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage


def run_benchmark_for_workers(source_file: Path, worker_count: int, db_file: Path) -> dict:
    os.environ["CHAINSIGHT_PARSER_WORKERS"] = str(worker_count)
    os.environ["CHAINSIGHT_ADAPTIVE_TUNING"] = "true"
    gc.collect()
    db_file.unlink(missing_ok=True)

    storage = Storage(db_file)
    service = IngestionService(storage)
    proc = psutil.Process(os.getpid())

    t0 = time.perf_counter()
    status = service.process_sync(source_file)
    elapsed = max(time.perf_counter() - t0, 0.001)

    peak_rss = max(status.get("peak_memory_bytes", 0), proc.memory_info().rss)
    total_records = status.get("total_records", 0)
    eps = round(total_records / elapsed, 1)
    mb_s = round((source_file.stat().st_size / (1024 * 1024)) / elapsed, 2)

    db_file.unlink(missing_ok=True)
    return {
        "workers": worker_count,
        "records": total_records,
        "valid_records": status.get("valid_records", 0),
        "invalid_records": status.get("invalid_records", 0),
        "duplicate_records": status.get("duplicate_records", 0),
        "detections": status.get("detections", 0),
        "incidents": status.get("incidents", 0),
        "duration_seconds": round(elapsed, 3),
        "throughput_eps": eps,
        "throughput_mb_s": mb_s,
        "peak_rss_mb": round(peak_rss / (1024 * 1024), 1),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100_000)
    args = parser.parse_args()

    data_dir = PROJECT_ROOT / "data" / "benchmarks"
    data_dir.mkdir(parents=True, exist_ok=True)
    source_file = data_dir / f"bench_parallel_{args.count}.jsonl"
    print(f"Generating benchmark dataset of {args.count:,} records...")
    size = generate_benchmark_dataset(source_file, args.count)
    print(f"Dataset generated: {size / (1024*1024):.2f} MB")

    results = []
    for w in [1, 2, 3]:
        print(f"\n[+] Running benchmark with {w} worker(s)...")
        db_file = data_dir / f"test_w{w}.duckdb"
        res = run_benchmark_for_workers(source_file, w, db_file)
        results.append(res)
        print(f"    --> {w} Worker(s): {res['duration_seconds']} s | {res['throughput_eps']:,.1f} eps | {res['throughput_mb_s']} MB/s | RAM: {res['peak_rss_mb']} MB | Detections: {res['detections']} | Incidents: {res['incidents']}")

    source_file.unlink(missing_ok=True)

    print("\n" + "=" * 90)
    print("PARALLEL PARSER WORKERS BENCHMARK SUMMARY")
    print("=" * 90)
    print(f"{'Workers':<10} | {'Duration (s)':<14} | {'Throughput (eps)':<18} | {'Throughput (MB/s)':<18} | {'Peak RAM (MB)':<14} | {'Speedup':<10}")
    print("-" * 90)
    base_eps = results[0]["throughput_eps"]
    for r in results:
        speedup = f"{r['throughput_eps'] / base_eps:.2f}x"
        print(f"{r['workers']:<10} | {r['duration_seconds']:<14} | {r['throughput_eps']:<18,f} | {r['throughput_mb_s']:<18.2f} | {r['peak_rss_mb']:<14.1f} | {speedup:<10}")
    print("=" * 90)


if __name__ == "__main__":
    main()
