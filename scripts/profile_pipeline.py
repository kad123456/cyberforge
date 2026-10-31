from __future__ import annotations

import gc
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.compare_static_vs_adaptive import generate_benchmark_dataset
from backend.ingestion.reader import stream_jsonl_records
from backend.ingestion.parser import parse_line, normalize
from backend.ingestion.storage import Storage, _events_to_arrow_table
from backend.detection.engine import DetectionEngine
from backend.correlation.correlator import StreamingCorrelator


def profile_pipeline(count: int = 100_000):
    data_dir = PROJECT_ROOT / "data" / "profiling"
    data_dir.mkdir(parents=True, exist_ok=True)
    source_file = data_dir / f"profile_{count}.jsonl"
    db_file = data_dir / "profile.duckdb"

    print(f"Generating {count:,} events dataset...")
    size_bytes = generate_benchmark_dataset(source_file, count)
    print(f"File created: {size_bytes / (1024*1024):.2f} MB")

    db_file.unlink(missing_ok=True)
    storage = Storage(db_file)
    storage.create_streaming_staging("test-profile-run")

    # 1. Measure pure reading
    t0 = time.perf_counter()
    lines = []
    read_bytes = 0
    with source_file.open("rb") as f:
        for line in f:
            read_bytes += len(line)
            lines.append(line)
    t_read = time.perf_counter() - t0
    print(f"1. Pure Disk Read:        {t_read:.3f} s ({count/t_read:,.0f} lps, {size_bytes/(1024*1024)/t_read:.2f} MB/s)")

    # 2. Measure JSON parsing
    t0 = time.perf_counter()
    raw_dicts = [parse_line(l, source_format="jsonl") for l in lines]
    t_parse = time.perf_counter() - t0
    print(f"2. JSON Parsing (orjson): {t_parse:.3f} s ({count/t_parse:,.0f} eps)")

    # 3. Measure Normalization
    t0 = time.perf_counter()
    events = [normalize(d) for d in raw_dicts]
    t_norm = time.perf_counter() - t0
    print(f"3. Normalization:         {t_norm:.3f} s ({count/t_norm:,.0f} eps)")

    # 4. Measure Arrow Conversion
    t0 = time.perf_counter()
    arrow_table = _events_to_arrow_table(events)
    t_arrow = time.perf_counter() - t0
    print(f"4. Arrow Table Build:     {t_arrow:.3f} s ({count/t_arrow:,.0f} eps)")

    # 5. Measure DuckDB Bulk Insertion
    t0 = time.perf_counter()
    with storage.writer(staging=True) as writer:
        accepted = writer.insert_stream_events(events)
    t_db = time.perf_counter() - t0
    print(f"5. DuckDB Bulk Insert:    {t_db:.3f} s ({count/t_db:,.0f} eps)")

    # 6. Measure Detection
    engine = DetectionEngine()
    t0 = time.perf_counter()
    detections = engine.detect_batch(accepted)
    t_detect = time.perf_counter() - t0
    print(f"6. Rule Evaluation:       {t_detect:.3f} s ({count/t_detect:,.0f} eps) [Found {len(detections)} hits]")

    # 7. Measure Detections DB Insert
    t0 = time.perf_counter()
    with storage.writer(staging=True) as writer:
        writer.save_detections(detections)
    t_det_db = time.perf_counter() - t0
    print(f"7. Detections DB Insert:  {t_det_db:.3f} s")

    # 8. Measure Correlation
    correlator = StreamingCorrelator()
    t0 = time.perf_counter()
    memberships = []
    for d, e in zip(detections, accepted[:len(detections)]):
        inc_id = correlator.add(d, e)
        memberships.append((inc_id, e.event_id))
    incidents = correlator.finalize_all()
    t_corr = time.perf_counter() - t0
    print(f"8. Correlation & Incidents: {t_corr:.3f} s [Incidents: {len(incidents)}]")

    total_pipeline = t_read + t_parse + t_norm + t_arrow + t_db + t_detect + t_det_db + t_corr
    print("=" * 60)
    print("PIPELINE TIME BREAKDOWN:")
    print(f"  Disk Read:       {t_read:6.3f} s ({100*t_read/total_pipeline:5.1f}%)")
    print(f"  JSON Parsing:    {t_parse:6.3f} s ({100*t_parse/total_pipeline:5.1f}%)")
    print(f"  Normalization:   {t_norm:6.3f} s ({100*t_norm/total_pipeline:5.1f}%)")
    print(f"  Arrow Building:  {t_arrow:6.3f} s ({100*t_arrow/total_pipeline:5.1f}%)")
    print(f"  DuckDB Insert:   {t_db:6.3f} s ({100*t_db/total_pipeline:5.1f}%)")
    print(f"  Detection:       {t_detect:6.3f} s ({100*t_detect/total_pipeline:5.1f}%)")
    print(f"  Detections DB:   {t_det_db:6.3f} s ({100*t_det_db/total_pipeline:5.1f}%)")
    print(f"  Correlation:     {t_corr:6.3f} s ({100*t_corr/total_pipeline:5.1f}%)")
    print(f"  Total Active:    {total_pipeline:6.3f} s (Overall EPS: {count/total_pipeline:,.1f})")
    print("=" * 60)

    # Cleanup
    source_file.unlink(missing_ok=True)
    db_file.unlink(missing_ok=True)


if __name__ == "__main__":
    profile_pipeline(100_000)
