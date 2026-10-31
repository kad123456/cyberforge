from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark ChainSight ingestion on a local log file.")
    parser.add_argument("source", type=Path, help="JSONL, CEF, FortiGate or CSV input file")
    parser.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "benchmark.duckdb")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    database = args.database.expanduser().resolve()
    if not source.is_file():
        parser.error(f"Source file does not exist: {source}")

    data_dir = database.parent
    os.environ["CHAINSIGHT_DATA_DIR"] = str(data_dir)
    os.environ["CHAINSIGHT_DB_PATH"] = str(database)
    os.environ["CHAINSIGHT_DUCKDB_TEMP_DIR"] = str(data_dir / "duckdb_tmp")

    import psutil

    from backend.config import CHUNK_SIZE, DUCKDB_MEMORY_LIMIT, DUCKDB_THREADS, PARSER_WORKERS
    from backend.ingestion.service import IngestionService
    from backend.ingestion.storage import Storage

    storage = Storage(database)
    service = IngestionService(storage)
    process = psutil.Process(os.getpid())
    db_size_before = database.stat().st_size if database.exists() else 0
    temp_size_before = directory_size(data_dir / "duckdb_tmp")
    stop_sampling = threading.Event()
    cpu_samples = []
    peak_rss = [process.memory_info().rss]

    def sample_process():
        while not stop_sampling.wait(0.25):
            cpu_samples.append(process.cpu_percent(interval=None))
            peak_rss[0] = max(peak_rss[0], process.memory_info().rss)

    process.cpu_percent(interval=None)
    sampler = threading.Thread(target=sample_process, daemon=True)
    sampler.start()
    started = time.perf_counter()
    try:
        status = service.process_sync(source)
    finally:
        stop_sampling.set()
        sampler.join()
    elapsed = max(time.perf_counter() - started, 0.001)

    query_latencies = {}
    for label, query in (
        ("dashboard_counts", storage.dashboard_counts),
        ("first_event_page", lambda: storage.event_page(limit=200, offset=0)),
        ("incident_overview", storage.incident_overview),
    ):
        query_started = time.perf_counter()
        query()
        query_latencies[label] = round((time.perf_counter() - query_started) * 1000, 2)

    database_bytes = database.stat().st_size if database.exists() else 0
    temp_bytes = directory_size(data_dir / "duckdb_tmp")
    report = {
        "source": str(source),
        "source_bytes": source.stat().st_size,
        "database": str(database),
        "database_bytes_before": db_size_before,
        "database_bytes_after": database_bytes,
        "database_bytes_added": max(0, database_bytes - db_size_before),
        "duckdb_temp_bytes_before": temp_size_before,
        "duckdb_temp_bytes_after": temp_bytes,
        "configuration": {
            "batch_records": CHUNK_SIZE,
            "parser_workers": PARSER_WORKERS,
            "duckdb_threads": DUCKDB_THREADS,
            "duckdb_memory_limit": DUCKDB_MEMORY_LIMIT,
        },
        "records": {
            "processed": status.get("total_records", 0),
            "valid": status.get("valid_records", 0),
            "invalid": status.get("invalid_records", 0),
            "duplicates": status.get("duplicate_records", 0),
            "detections": status.get("detections", 0),
            "incidents": status.get("incidents", 0),
        },
        "duration_seconds": round(elapsed, 3),
        "ingestion_phase_seconds": round(status.get("ingestion_duration_seconds", 0.0), 3),
        "analysis_phase_seconds": round(status.get("analysis_duration_seconds", 0.0), 3),
        "events_per_second": round(status.get("total_records", 0) / elapsed, 1),
        "peak_process_rss_bytes": max(status.get("peak_memory_bytes", 0), peak_rss[0], process.memory_info().rss),
        "average_cpu_percent": round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else status.get("cpu_percent", 0.0),
        "peak_cpu_percent": round(max(cpu_samples), 1) if cpu_samples else status.get("cpu_percent", 0.0),
        "investigation_query_latency_ms": query_latencies,
        "accuracy": None,
        "accuracy_note": "Requires organizer ground-truth labels; no accuracy value was fabricated.",
    }
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
