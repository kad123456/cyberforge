import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from backend.detection.engine import DetectionEngine
from backend.ingestion.parser import normalize
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage


def test_ransomware_mass_file_renames_detected_across_batches():
    engine = DetectionEngine()
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Batch 1: 1 file encrypted
    batch1 = [
        normalize({
            "@timestamp": now.isoformat(),
            "event": {"id": "f-1", "category": ["file"], "action": "file_rename"},
            "host": {"name": "VICTIM-01"},
            "file": {"path": "C:\\Data\\doc1.docx.encrypted"},
        })
    ]
    det1 = engine.detect_batch(batch1)
    # Individual rule CS-FILE-001 fires, but not mass ransomware rule yet
    rule_ids1 = {d.rule_id for d in det1}
    assert "CS-FILE-001" in rule_ids1
    assert "CS-RANSOM-001" not in rule_ids1

    # Batch 2: 1 file encrypted
    batch2 = [
        normalize({
            "@timestamp": (now + timedelta(minutes=2)).isoformat(),
            "event": {"id": "f-2", "category": ["file"], "action": "file_rename"},
            "host": {"name": "VICTIM-01"},
            "file": {"path": "C:\\Data\\doc2.xlsx.encrypted"},
        })
    ]
    det2 = engine.detect_batch(batch2)
    rule_ids2 = {d.rule_id for d in det2}
    assert "CS-RANSOM-001" not in rule_ids2

    # Batch 3: 3rd file encrypted -> triggers CS-RANSOM-001
    batch3 = [
        normalize({
            "@timestamp": (now + timedelta(minutes=5)).isoformat(),
            "event": {"id": "f-3", "category": ["file"], "action": "file_rename"},
            "host": {"name": "VICTIM-01"},
            "file": {"path": "C:\\Data\\doc3.pdf.encrypted"},
        })
    ]
    det3 = engine.detect_batch(batch3)
    rule_ids3 = {d.rule_id for d in det3}
    assert "CS-RANSOM-001" in rule_ids3
    ransom_det = next(d for d in det3 if d.rule_id == "CS-RANSOM-001")
    assert ransom_det.severity == "critical"
    assert "f-1" in ransom_det.evidence["evidence_event_ids"]
    assert "f-2" in ransom_det.evidence["evidence_event_ids"]
    assert "f-3" in ransom_det.evidence["evidence_event_ids"]


def test_different_batch_sizes_produce_equivalent_results(tmp_path: Path):
    test_file = tmp_path / "equivalence.jsonl"
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    records = []

    # 5 failed auths
    for i in range(5):
        records.append({
            "@timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "event": {"id": f"auth-{i}", "category": ["authentication"], "outcome": "failure"},
            "host": {"name": "FINANCE-01"},
            "user": {"name": "alice"},
        })
    # 1 success after failures
    records.append({
        "@timestamp": (base_time + timedelta(minutes=5)).isoformat(),
        "event": {"id": "auth-succ", "category": ["authentication"], "outcome": "success"},
        "host": {"name": "FINANCE-01"},
        "user": {"name": "alice"},
    })
    # 3 ransomware renames
    for i in range(3):
        records.append({
            "@timestamp": (base_time + timedelta(minutes=6+i)).isoformat(),
            "event": {"id": f"enc-{i}", "category": ["file"], "action": "rename"},
            "host": {"name": "FINANCE-01"},
            "file": {"path": f"C:\\finance\\sheet_{i}.xlsx.locked"},
        })

    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    # Run with small batch size 3
    storage1 = Storage(tmp_path / "run_b3.duckdb")
    service1 = IngestionService(storage1)
    run1 = service1._prepare_run(test_file)[0]
    run1["batch_records"] = 3
    service1._ingest_source(test_file, run1, 0.0)
    service1._analyze_staging(run1, 0.0)
    storage1.publish_staging(run1)

    # Run with batch size 20
    storage2 = Storage(tmp_path / "run_b20.duckdb")
    service2 = IngestionService(storage2)
    run2 = service2._prepare_run(test_file)[0]
    run2["batch_records"] = 20
    service2._ingest_source(test_file, run2, 0.0)
    service2._analyze_staging(run2, 0.0)
    storage2.publish_staging(run2)

    # Compare detections and incidents between both runs
    det1 = sorted([d.rule_id for d in storage1.detections()])
    det2 = sorted([d.rule_id for d in storage2.detections()])
    assert det1 == det2
    assert "CS-AUTH-001" in det1
    assert "CS-AUTH-002" in det1
    assert "CS-RANSOM-001" in det1

    inc1 = storage1.incidents()
    inc2 = storage2.incidents()
    assert len(inc1) == len(inc2)
