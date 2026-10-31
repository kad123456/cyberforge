import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.ingestion.reader import stream_csv_records
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage


def _auth_record(event_id: str, minute: int, outcome: str = "failure") -> dict:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return {
        "@timestamp": timestamp.isoformat(),
        "event": {"id": event_id, "category": ["authentication"], "outcome": outcome},
        "host": {"name": "AUTH-01"},
        "user": {"name": "admin"},
    }


def test_incident_membership_bulk_insert_is_idempotent(tmp_path):
    storage = Storage(tmp_path / "memberships.duckdb")

    with storage.writer() as writer:
        inserted = writer.add_incident_events([
            ("incident-1", "event-1"),
            ("incident-1", "event-1"),
            ("incident-1", "event-2"),
        ])

    assert inserted == 2
    assert storage.add_incident_events([
        ("incident-1", "event-2"),
        ("incident-2", "event-1"),
    ]) == 1
    assert storage.add_incident_event("incident-2", "event-1") == 0

    with storage.connect() as db:
        memberships = db.execute(
            "SELECT incident_id,event_id FROM incident_events ORDER BY incident_id,event_id"
        ).fetchall()
    assert memberships == [
        ("incident-1", "event-1"),
        ("incident-1", "event-2"),
        ("incident-2", "event-1"),
    ]


def test_csv_reader_handles_multiline_rows_and_resumes_at_record_boundary(tmp_path):
    path = tmp_path / "source.csv"
    path.write_text('event.id,command\n1,"first\nsecond"\n2,third\n', encoding="utf-8")

    rows = list(stream_csv_records(path))
    assert rows[0][2] == {"event.id": "1", "command": "first\r\nsecond"}
    resumed = list(stream_csv_records(path, start_offset=rows[0][1], start_line=rows[0][0]))
    assert [row[2]["event.id"] for row in resumed] == ["2"]


def test_pipeline_reports_invalid_and_duplicate_records_and_auth_sequence(tmp_path, monkeypatch, caplog):
    import backend.ingestion.service as service_module

    source = tmp_path / "auth.jsonl"
    records = [_auth_record(f"auth-{minute}", minute) for minute in range(5)]
    records.append(_auth_record("auth-success", 5, "success"))
    records.append(records[0])  # explicit duplicate event ID
    source.write_text("\n".join([*(json.dumps(record) for record in records), "{bad json"]), encoding="utf-8")

    monkeypatch.setattr(service_module, "CHUNK_SIZE", 2)
    storage = Storage(tmp_path / "analysis.duckdb")
    status = IngestionService(storage).process_sync(source)

    assert status["state"] == "complete"
    assert status["total_records"] == 8
    assert status["valid_records"] == 7
    assert status["invalid_records"] == 1
    assert "Malformed source record" in caplog.text
    assert status["duplicate_records"] == 1
    assert status["skipped_records"] == 2
    assert storage.dashboard_counts()["total_events"] == 6
    assert {item.rule_id for item in storage.detections()} == {"CS-AUTH-001", "CS-AUTH-002"}
    assert len(storage.incidents()) == 1
    overview = storage.incident_overview()
    assert overview["total"] == 1 and overview["critical"] == 0 and len(overview["recent"]) == 1
    assert storage.mitre_summary()[0]["incident_count"] == 1


def test_final_partial_batch_is_processed_and_raw_evidence_is_preserved(tmp_path, monkeypatch):
    import backend.ingestion.service as service_module

    source = tmp_path / "partial.jsonl"
    records = [
        {
            "@timestamp": f"2026-01-01T00:00:0{second}Z",
            "event": {"id": f"boundary-{second}", "category": ["process"], "action": "process_created"},
            "host": {"name": f"WS-{second}"},
            "process": {"name": "powershell.exe", "command_line": f"powershell -enc {second}"},
            "threat": {"technique": {"id": ["T1059.001"], "name": ["PowerShell"]}},
        }
        for second in range(5)
    ]
    source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    monkeypatch.setattr(service_module, "CHUNK_SIZE", 2)
    storage = Storage(tmp_path / "partial.duckdb")

    status = IngestionService(storage).process_sync(source)

    assert status["total_records"] == status["valid_records"] == 5
    assert storage.dashboard_counts()["total_events"] == 5
    stored = {event.event_id: event for event in storage.events(limit=10)}
    assert stored["boundary-4"].host == "WS-4"
    assert stored["boundary-4"].process_name == "powershell.exe"
    assert stored["boundary-4"].raw_event["threat"]["technique"]["id"] == ["T1059.001"]


def test_failed_job_keeps_last_dataset_and_resumes_at_committed_offset(tmp_path, monkeypatch):
    import backend.ingestion.service as service_module

    storage = Storage(tmp_path / "resume.duckdb")
    service = IngestionService(storage)
    old_source = tmp_path / "old.jsonl"
    old_source.write_text(json.dumps(_auth_record("old", 0)), encoding="utf-8")
    service.process_sync(old_source)

    source = tmp_path / "large.jsonl"
    source.write_text("\n".join(json.dumps(_auth_record(f"new-{n}", n)) for n in range(5)), encoding="utf-8")
    monkeypatch.setattr(service_module, "CHUNK_SIZE", 2)
    original = service_module.stream_jsonl_records

    def fail_after_first_checkpoint(path, *, start_offset=0, start_line=0, **kwargs):
        if start_offset:
            yield from original(path, start_offset=start_offset, start_line=start_line, **kwargs)
            return
        for index, record in enumerate(original(path, start_offset=start_offset, start_line=start_line, **kwargs)):
            if index == 3:
                raise OSError("simulated interruption")
            yield record

    monkeypatch.setattr(service_module, "stream_jsonl_records", fail_after_first_checkpoint)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        service.process_sync(source)
    assert [event.event_id for event in storage.events(limit=10)] == ["old"]
    assert service.status()["total_records"] == 2

    monkeypatch.setattr(service_module, "stream_jsonl_records", original)
    result = service.process_sync(source)
    assert result["state"] == "complete"
    assert result["resuming"] is True
    assert result["total_records"] == 5
    assert result["valid_records"] == 5
    assert result["duplicate_records"] == 0
    assert result["detections"] == 1
    assert {item.rule_id for item in storage.detections()} == {"CS-AUTH-001"}
    assert storage.dashboard_counts()["total_events"] == 5


def test_csv_pipeline_maps_common_fields_and_retains_raw_columns(tmp_path):
    source = tmp_path / "flat.csv"
    source.write_text(
        "timestamp,event.id,category,hostname,username,source_ip,command_line\n"
        "2026-01-01T00:00:00Z,csv-1,process,WS-01,analyst,10.0.0.1,whoami\n",
        encoding="utf-8",
    )
    storage = Storage(tmp_path / "csv.duckdb")
    status = IngestionService(storage).process_sync(source)

    event = storage.event_page()[1][0]
    assert status["valid_records"] == 1
    assert (event.event_id, event.host, event.user, event.source_ip) == ("csv-1", "WS-01", "analyst", "10.0.0.1")
    assert event.raw_event["command_line"] == "whoami"


def test_flat_jsonl_accepts_scalar_host_and_user_fields(tmp_path):
    source = tmp_path / "flat.jsonl"
    source.write_text(
        json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "process",
            "host": "WS-01",
            "user": "analyst",
            "source_ip": "10.0.0.1",
            "process_name": "cmd.exe",
            "command_line": "whoami",
        }),
        encoding="utf-8",
    )
    storage = Storage(tmp_path / "flat-jsonl.duckdb")

    status = IngestionService(storage).process_sync(source)
    event = storage.event_page()[1][0]

    assert status["valid_records"] == 1
    assert (event.category, event.host, event.user, event.source_ip, event.process_name) == (
        "process", "WS-01", "analyst", "10.0.0.1", "cmd.exe",
    )


def test_out_of_order_source_uses_event_time_order_for_detection(tmp_path):
    source = tmp_path / "late.jsonl"
    records = [_auth_record(f"failure-{minute}", minute) for minute in (0, 2, 4, 6, 8)]
    records.append(_auth_record("success-7", 7, "success"))
    source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    storage = Storage(tmp_path / "late.duckdb")

    status = IngestionService(storage).process_sync(source)

    assert status["timestamps_ordered"] is False
    assert {item.rule_id for item in storage.detections()} == {"CS-AUTH-001"}


def test_fortigate_raw_rule_uses_compact_context_in_database_analysis(tmp_path):
    source = tmp_path / "fortigate.log"
    source.write_text(
        'date=2026-01-01 time=00:00:00 tz="+0000" type=utm subtype=webfilter level=warning '
        'catdesc="phishing" action="blocked" user="analyst" srcip=10.0.0.1 dstip=203.0.113.2\n',
        encoding="utf-8",
    )
    storage = Storage(tmp_path / "fortigate.duckdb")
    status = IngestionService(storage).process_sync(source)
    assert status["detections"] == 1
    assert storage.detections()[0].rule_id == "CS-FGT-PHISH-001"
