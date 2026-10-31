from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the bounded ChainSight stream-upload pipeline.")
    parser.add_argument("source", type=Path, help="JSONL, CEF or line-oriented log input file")
    parser.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "stream-benchmark.duckdb")
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
    from fastapi.testclient import TestClient

    from backend.config import CHUNK_SIZE, DUCKDB_MEMORY_LIMIT, DUCKDB_THREADS
    from backend.main import app
    from backend.api.routes import store

    process = psutil.Process(os.getpid())
    peak_rss = [process.memory_info().rss]
    cpu_samples: list[float] = []
    stop_sampling = threading.Event()

    def sample_process():
        while not stop_sampling.wait(0.25):
            cpu_samples.append(process.cpu_percent(interval=None))
            peak_rss[0] = max(peak_rss[0], process.memory_info().rss)

    process.cpu_percent(interval=None)
    sampler = threading.Thread(target=sample_process, daemon=True)
    sampler.start()
    upload_name = f"{source.stem}-{uuid4().hex[:8]}{source.suffix}"
    uploaded_path = data_dir / upload_name
    started = time.perf_counter()
    finished = None
    query_latencies = {}
    try:
        def body_chunks():
            with source.open("rb", buffering=4 * 1024 * 1024) as stream:
                while chunk := stream.read(4 * 1024 * 1024):
                    yield chunk

        with TestClient(app) as client:
            response = client.post(
                "/api/ingest/stream",
                content=body_chunks(),
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-File-Name": upload_name,
                    "X-File-Size": str(source.stat().st_size),
                },
            )
            response.raise_for_status()
            job_id = response.json()["job_id"]
            while True:
                status = client.get(f"/api/ingest/jobs/{job_id}").json()
                if status["state"] in {"complete", "failed"}:
                    break
                time.sleep(0.25)
        if status["state"] != "complete":
            raise RuntimeError(status.get("message", "Streaming benchmark job failed"))
        finished = time.perf_counter()

        for label, query in (
            ("dashboard_counts", store.dashboard_counts),
            ("first_event_page", lambda: store.event_page(limit=200, offset=0)),
            ("incident_overview", store.incident_overview),
        ):
            query_started = time.perf_counter()
            query()
            query_latencies[label] = round((time.perf_counter() - query_started) * 1000, 2)
    finally:
        stop_sampling.set()
        sampler.join()
        uploaded_path.unlink(missing_ok=True)

    elapsed = max((finished or time.perf_counter()) - started, 0.001)
    report = {
        "mode": "HTTP streaming route via FastAPI TestClient and bounded 4 MiB source chunks",
        "source": str(source),
        "source_bytes": source.stat().st_size,
        "database": str(database),
        "configuration": {
            "batch_records": CHUNK_SIZE,
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
        "upload_parse_detection_seconds": round(status.get("ingestion_duration_seconds", 0.0), 3),
        "events_per_second": round(status.get("total_records", 0) / elapsed, 1),
        "peak_process_rss_bytes": max(status.get("peak_memory_bytes", 0), peak_rss[0], process.memory_info().rss),
        "average_cpu_percent": round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else status.get("cpu_percent", 0.0),
        "peak_cpu_percent": round(max(cpu_samples), 1) if cpu_samples else status.get("cpu_percent", 0.0),
        "investigation_query_latency_ms": query_latencies,
        "accuracy": None,
        "accuracy_note": "Requires organizer ground-truth labels; the benchmark compares no attack labels.",
    }
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
