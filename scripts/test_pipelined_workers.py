from __future__ import annotations

import gc
import os
import queue
import sys
import threading
import time
from pathlib import Path
import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.compare_static_vs_adaptive import generate_benchmark_dataset
from backend.ingestion.reader import stream_jsonl_records
from backend.ingestion.service import _normalize_payload_batch
from backend.ingestion.storage import Storage, _events_to_arrow_table
from backend.detection.engine import DetectionEngine
from backend.correlation.correlator import StreamingCorrelator


def run_pipelined_ingestion(source_file: Path, db_file: Path, worker_count: int, batch_size: int = 10_000) -> dict:
    gc.collect()
    db_file.unlink(missing_ok=True)

    storage = Storage(db_file)
    storage.create_streaming_staging("test-run")
    proc = psutil.Process(os.getpid())

    t0 = time.perf_counter()
    detection_engine = DetectionEngine()
    correlator = StreamingCorrelator()

    total_records = 0
    valid_records = 0
    invalid_records = 0
    duplicate_records = 0
    total_detections = 0
    db_write_time = 0.0

    with storage.writer(staging=True) as writer:
        if worker_count <= 1:
            # Baseline single-worker
            raw_batch = []
            for number, end_offset, line in stream_jsonl_records(source_file):
                if not line.strip():
                    continue
                raw_batch.append((number, end_offset, "line", line))
                if len(raw_batch) >= batch_size:
                    total_records += len(raw_batch)
                    payloads = [(kind, payload) for _, _, kind, payload in raw_batch]
                    parsed = _normalize_payload_batch(payloads)
                    events = []
                    for (num, _, _, _), (evt, err) in zip(raw_batch, parsed):
                        if err:
                            invalid_records += 1
                        else:
                            events.append(evt)
                            valid_records += 1
                    raw_batch.clear()

                    t_w0 = time.perf_counter()
                    accepted = writer.insert_stream_events(events)
                    db_write_time += time.perf_counter() - t_w0
                    duplicate_records += len(events) - len(accepted)

                    detections = detection_engine.detect_batch(accepted)
                    if detections:
                        writer.save_detections(detections)
                        total_detections += len(detections)
                        for d in detections:
                            correlator.add(d, accepted[0])

            if raw_batch:
                total_records += len(raw_batch)
                payloads = [(kind, payload) for _, _, kind, payload in raw_batch]
                parsed = _normalize_payload_batch(payloads)
                events = []
                for (num, _, _, _), (evt, err) in zip(raw_batch, parsed):
                    if err:
                        invalid_records += 1
                    else:
                        events.append(evt)
                        valid_records += 1
                raw_batch.clear()

                t_w0 = time.perf_counter()
                accepted = writer.insert_stream_events(events)
                db_write_time += time.perf_counter() - t_w0
                duplicate_records += len(events) - len(accepted)

                detections = detection_engine.detect_batch(accepted)
                if detections:
                    writer.save_detections(detections)
                    total_detections += len(detections)
                    for d in detections:
                        correlator.add(d, accepted[0])

        else:
            # Multi-worker pipelined with bounded queues
            in_q: queue.Queue = queue.Queue(maxsize=worker_count)
            out_q: queue.Queue = queue.Queue(maxsize=worker_count)

            def parser_worker():
                while True:
                    item = in_q.get()
                    if item is None:
                        in_q.task_done()
                        out_q.put(None)
                        break
                    seq_id, raw_b, end_offset, line_num = item
                    payloads = [(kind, payload) for _, _, kind, payload in raw_b]
                    parsed = _normalize_payload_batch(payloads)
                    evts = []
                    invalids = 0
                    for (num, _, _, _), (evt, err) in zip(raw_b, parsed):
                        if err:
                            invalids += 1
                        else:
                            evts.append(evt)
                    out_q.put((seq_id, evts, invalids, len(raw_b), end_offset, line_num))
                    in_q.task_done()

            workers = [threading.Thread(target=parser_worker, daemon=True) for _ in range(worker_count)]
            for w in workers:
                w.start()

            def file_producer():
                seq = 0
                raw_b = []
                for number, end_offset, line in stream_jsonl_records(source_file):
                    if not line.strip():
                        continue
                    raw_b.append((number, end_offset, "line", line))
                    if len(raw_b) >= batch_size:
                        in_q.put((seq, raw_b, end_offset, number))
                        seq += 1
                        raw_b = []
                if raw_b:
                    in_q.put((seq, raw_b, end_offset, number))
                    seq += 1
                for _ in range(worker_count):
                    in_q.put(None)

            producer = threading.Thread(target=file_producer, daemon=True)
            producer.start()

            pending_results = {}
            expected_seq = 0
            finished_workers = 0

            while finished_workers < worker_count or pending_results:
                item = out_q.get()
                if item is None:
                    finished_workers += 1
                    out_q.task_done()
                else:
                    seq_id, evts, invalids, raw_count, end_offset, line_num = item
                    pending_results[seq_id] = (evts, invalids, raw_count, end_offset, line_num)
                    out_q.task_done()

                while expected_seq in pending_results:
                    evts, invalids, raw_count, end_offset, line_num = pending_results.pop(expected_seq)
                    total_records += raw_count
                    invalid_records += invalids
                    valid_records += len(evts)

                    t_w0 = time.perf_counter()
                    accepted = writer.insert_stream_events(evts)
                    db_write_time += time.perf_counter() - t_w0
                    duplicate_records += len(evts) - len(accepted)

                    detections = detection_engine.detect_batch(accepted)
                    if detections:
                        writer.save_detections(detections)
                        total_detections += len(detections)
                        for d in detections:
                            correlator.add(d, accepted[0])

                    expected_seq += 1

            producer.join()
            for w in workers:
                w.join(timeout=1.0)

    incidents = correlator.finalize_all()
    elapsed = max(time.perf_counter() - t0, 0.001)
    peak_rss = proc.memory_info().rss
    db_file.unlink(missing_ok=True)

    return {
        "workers": worker_count,
        "records": total_records,
        "valid_records": valid_records,
        "invalid_records": invalid_records,
        "duplicate_records": duplicate_records,
        "detections": total_detections,
        "incidents": len(incidents),
        "duration_seconds": round(elapsed, 3),
        "db_write_seconds": round(db_write_time, 3),
        "throughput_eps": round(total_records / elapsed, 1),
        "throughput_mb_s": round((source_file.stat().st_size / (1024 * 1024)) / elapsed, 2),
        "peak_rss_mb": round(peak_rss / (1024 * 1024), 1),
    }


def main():
    data_dir = PROJECT_ROOT / "data" / "benchmarks"
    data_dir.mkdir(parents=True, exist_ok=True)
    source_file = data_dir / "bench_pipeline_100k.jsonl"
    print("Generating benchmark dataset (100,000 records)...")
    size = generate_benchmark_dataset(source_file, 100_000)
    print(f"Dataset generated: {size / (1024*1024):.2f} MB\n")

    results = []
    for w in [1, 2, 3]:
        print(f"[+] Testing with {w} worker(s)...")
        db = data_dir / f"pipe_w{w}.duckdb"
        r = run_pipelined_ingestion(source_file, db, w)
        results.append(r)
        print(f"    {w} Worker(s): {r['duration_seconds']} s | {r['throughput_eps']:,.1f} eps | DB Write: {r['db_write_seconds']} s | RAM: {r['peak_rss_mb']} MB | Detections: {r['detections']} | Incidents: {r['incidents']}")

    source_file.unlink(missing_ok=True)

    print("\n" + "=" * 95)
    print("COMPARATIVE WORKER BENCHMARK (100,000 EVENTS)")
    print("=" * 95)
    print(f"{'Workers':<8} | {'Total Time (s)':<16} | {'DB Write Time (s)':<18} | {'Throughput (eps)':<18} | {'Peak RAM':<12} | {'Speedup':<8}")
    print("-" * 95)
    base_eps = results[0]["throughput_eps"]
    for r in results:
        speedup = f"{r['throughput_eps'] / base_eps:.2f}x"
        print(f"{r['workers']:<8} | {r['duration_seconds']:<16} | {r['db_write_seconds']:<18} | {r['throughput_eps']:<18,f} | {r['peak_rss_mb']:<6.1f} MB | {speedup:<8}")
    print("=" * 95)


if __name__ == "__main__":
    main()
