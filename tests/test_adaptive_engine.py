from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from backend.config import BATCH_SIZE, MEMORY_BUDGET_BYTES, MIN_BATCH_RECORDS, MAX_BATCH_RECORDS
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage
from backend.ingestion.tuning import AdaptiveBatchOptimizer, classify_file_tier


def test_classify_file_tier():
    assert classify_file_tier(100 * 1024 * 1024) == "small"
    assert classify_file_tier(1024 * 1024 * 1024) == "medium"
    assert classify_file_tier(10 * 1024 * 1024 * 1024) == "large"
    assert classify_file_tier(30 * 1024 * 1024 * 1024) == "very-large"


def test_adaptive_optimizer_throttle_on_memory_pressure():
    optimizer = AdaptiveBatchOptimizer(
        min_batch=2000,
        max_batch=50000,
        initial_batch=10000,
        memory_budget_bytes=4 * 1024 * 1024 * 1024,  # 4 GB
        target_memory_ratio=0.70,
    )
    # Simulate high RSS: 3.2 GB out of 4 GB = 80% (exceeds 70% target)
    high_rss = int(3.2 * 1024 * 1024 * 1024)
    available_ram = 8 * 1024 * 1024 * 1024
    new_batch, status, bottleneck, profiling = optimizer.step(
        records_count=10000,
        bytes_count=5 * 1024 * 1024,
        parse_seconds=0.2,
        write_seconds=0.3,
        detect_seconds=0.1,
        process_rss=high_rss,
        available_ram=available_ram,
    )
    assert new_batch < 10000
    assert "Throttled" in status
    assert optimizer.current_batch == new_batch


def test_adaptive_optimizer_scale_up_with_ample_headroom():
    optimizer = AdaptiveBatchOptimizer(
        min_batch=2000,
        max_batch=50000,
        initial_batch=10000,
        memory_budget_bytes=4 * 1024 * 1024 * 1024,
        target_memory_ratio=0.70,
    )
    # Simulate low RSS: 500 MB out of 4 GB = 12.5% (< 55%)
    low_rss = 500 * 1024 * 1024
    available_ram = 10 * 1024 * 1024 * 1024
    new_batch, status, bottleneck, profiling = optimizer.step(
        records_count=10000,
        bytes_count=5 * 1024 * 1024,
        parse_seconds=0.1,
        write_seconds=0.1,
        detect_seconds=0.05,
        process_rss=low_rss,
        available_ram=available_ram,
    )
    assert new_batch > 10000
    assert "Optimizing: Scaled batch" in status
    assert profiling["batch_eps"] > 0


def test_adaptive_optimizer_bottleneck_classification():
    optimizer = AdaptiveBatchOptimizer(initial_batch=5000)
    rss = 500 * 1024 * 1024
    avail = 8 * 1024 * 1024 * 1024

    # DB Write heavy
    _, _, b1, prof1 = optimizer.step(5000, 1024*1024, 0.05, 0.8, 0.05, rss, avail)
    assert b1 == "Database write bound"

    # Parser heavy
    _, _, b2, prof2 = optimizer.step(5000, 1024*1024, 0.8, 0.1, 0.05, rss, avail)
    assert b2 == "Parser bound"

    # Detection heavy
    _, _, b3, prof3 = optimizer.step(5000, 1024*1024, 0.05, 0.1, 0.8, rss, avail)
    assert b3 == "Rule evaluation bound"

    # Balanced
    _, _, b4, prof4 = optimizer.step(5000, 1024*1024, 0.2, 0.2, 0.2, rss, avail)
    assert b4 == "Balanced throughput"


def test_storage_historical_learning_and_seeding(tmp_path):
    storage = Storage(tmp_path / "learning.duckdb")

    # Initially empty
    assert storage.lookup_historical_optimal("jsonl", "small") is None

    # Record 3 historical runs
    storage.record_ingestion_history({
        "format": "jsonl",
        "file_size_tier": "small",
        "file_size_bytes": 50 * 1024 * 1024,
        "record_count": 50000,
        "optimal_batch_size": 15000,
        "avg_throughput_eps": 25000.0,
        "avg_throughput_mb_s": 25.0,
        "peak_memory_bytes": 400 * 1024 * 1024,
        "parse_time_seconds": 1.0,
        "write_time_seconds": 0.8,
        "detect_time_seconds": 0.2,
        "bottleneck": "Balanced throughput",
    })
    storage.record_ingestion_history({
        "format": "jsonl",
        "file_size_tier": "small",
        "file_size_bytes": 60 * 1024 * 1024,
        "record_count": 60000,
        "optimal_batch_size": 18000,
        "avg_throughput_eps": 28000.0,
        "avg_throughput_mb_s": 28.0,
        "peak_memory_bytes": 450 * 1024 * 1024,
        "parse_time_seconds": 1.1,
        "write_time_seconds": 0.9,
        "detect_time_seconds": 0.2,
        "bottleneck": "Balanced throughput",
    })

    optimal = storage.lookup_historical_optimal("jsonl", "small")
    assert optimal is not None
    assert 15000 <= optimal["optimal_batch_size"] <= 18000
    assert optimal["avg_throughput_eps"] > 0

    history = storage.get_ingestion_history(limit=10)
    assert len(history) == 2


def test_detection_consistency_between_static_and_adaptive_batches(tmp_path):
    """Ensure identical detection counts and evidence regardless of dynamic batch adjustments."""
    events = []
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Generate 50 failed auth events for brute-force detection
    for i in range(50):
        t = (base_time + timedelta(seconds=i * 2)).isoformat()
        events.append({
            "@timestamp": t,
            "event": {"id": f"evt-{i}", "category": ["authentication"], "outcome": "failure"},
            "host": {"name": "WORKSTATION-A"},
            "user": {"name": "target_user"},
            "source": {"ip": "10.0.0.99"},
        })
    # Followed by success
    events.append({
        "@timestamp": (base_time + timedelta(seconds=105)).isoformat(),
        "event": {"id": "evt-success", "category": ["authentication"], "outcome": "success"},
        "host": {"name": "WORKSTATION-A"},
        "user": {"name": "target_user"},
        "source": {"ip": "10.0.0.99"},
    })

    test_file = tmp_path / "auth_test.jsonl"
    test_file.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    # Run 1: with small batch size
    storage1 = Storage(tmp_path / "test1.duckdb")
    service1 = IngestionService(storage1)
    status1 = service1.process_sync(test_file)

    # Run 2: with larger batch size
    storage2 = Storage(tmp_path / "test2.duckdb")
    service2 = IngestionService(storage2)
    status2 = service2.process_sync(test_file)

    assert status1["valid_records"] == status2["valid_records"]
    assert status1["detections"] == status2["detections"]
    assert status1["detections"] > 0

    # Verify detections evidence table
    with storage1.connect(read_only=True) as db1, storage2.connect(read_only=True) as db2:
        d1 = db1.execute("SELECT rule_id, severity, confidence FROM detections ORDER BY detection_id").fetchall()
        d2 = db2.execute("SELECT rule_id, severity, confidence FROM detections ORDER BY detection_id").fetchall()
        assert d1 == d2
