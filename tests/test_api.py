from fastapi.testclient import TestClient
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from backend.main import app
from backend.config import DATA_DIR
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage

def test_health_endpoint():
    response=TestClient(app).get("/api/health")
    assert response.status_code==200 and response.json()["offline"] is True


def test_upload_endpoint_persists_complete_file():
    name = f"codex-upload-{uuid4().hex}.jsonl"
    payload = b'{"event":{"id":"upload-event"}}\n'
    with TestClient(app) as client:
        response = client.post(
            "/api/ingest/upload",
            files={"file": (name, payload, "application/x-ndjson")},
        )

    assert response.status_code == 200, response.text
    result = response.json()
    destination = DATA_DIR / result["file"]
    try:
        assert result["bytes"] == len(payload)
        assert destination.read_bytes() == payload
    finally:
        destination.unlink(missing_ok=True)


def test_ingestion_job_can_be_started_and_polled(tmp_path, monkeypatch):
    import backend.api.routes as routes

    name = f"codex-job-{uuid4().hex}.jsonl"
    source = DATA_DIR / name
    source.write_text(json.dumps({"@timestamp":"2026-01-01T00:00:00Z","event":{"id":"job-event"}}), encoding="utf-8")
    storage = Storage(tmp_path / "jobs.duckdb")
    service = IngestionService(storage)
    monkeypatch.setattr(routes, "store", storage)
    monkeypatch.setattr(routes, "ingestion", service)
    try:
        with TestClient(app) as client:
            response = client.post("/api/ingest/jobs", json={"filename": name})
            assert response.status_code == 200
            job_id = response.json()["job_id"]
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                status = client.get(f"/api/ingest/jobs/{job_id}").json()
                if status["state"] in {"complete", "failed"}:
                    break
                time.sleep(0.05)
            assert status["state"] == "complete"
            assert storage.dashboard_counts()["total_events"] == 1
    finally:
        source.unlink(missing_ok=True)


def test_streaming_upload_parses_complete_lines_and_keeps_counts(tmp_path, monkeypatch):
    import backend.api.routes as routes
    from collections import Counter

    name = f"codex-stream-{uuid4().hex}.jsonl"
    destination = DATA_DIR / name
    records = [
        {
            "@timestamp": f"2026-01-01T00:00:0{minute}Z",
            "event": {"id": f"auth-{minute}", "category": ["authentication"], "outcome": "failure"},
            "host": {"name": "AUTH-01"},
            "user": {"name": "admin"},
        }
        for minute in range(5)
    ]
    records.append({
        "@timestamp": "2026-01-01T00:00:05Z",
        "event": {"id": "auth-success", "category": ["authentication"], "outcome": "success"},
        "host": {"name": "AUTH-01"},
        "user": {"name": "admin"},
    })
    records.append(records[0])
    payload = b"\n".join([*(json.dumps(record).encode() for record in records), b"{malformed json"])
    source = tmp_path / "path-input.jsonl"
    source.write_bytes(payload)
    path_storage = Storage(tmp_path / "path-input.duckdb")
    path_status = IngestionService(path_storage).process_sync(source)
    storage = Storage(tmp_path / "stream-upload.duckdb")
    service = IngestionService(storage)
    monkeypatch.setattr(routes, "store", storage)
    monkeypatch.setattr(routes, "ingestion", service)

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/ingest/stream",
                content=payload,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-File-Name": name,
                    "X-File-Size": str(len(payload)),
                },
            )
            assert response.status_code == 200, response.text
            job_id = response.json()["job_id"]
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                status = client.get(f"/api/ingest/jobs/{job_id}").json()
                if status["state"] in {"complete", "failed"}:
                    break
                time.sleep(0.05)

        assert status["state"] == "complete"
        assert status["total_records"] == 8
        assert status["valid_records"] == 7
        assert status["invalid_records"] == 1
        assert status["duplicate_records"] == 1
        assert status["detections"] == path_status["detections"]
        assert storage.dashboard_counts()["total_events"] == 6

        def event_fingerprint(db: Storage):
            return sorted((
                event.event_id,
                event.timestamp.isoformat(),
                event.host,
                event.user,
                event.action,
                event.technique_id,
                event.tactic,
                json.dumps(event.raw_event, sort_keys=True, default=str),
            ) for event in db.events(limit=None))

        def detection_fingerprint(db: Storage):
            return sorted((
                detection.detection_id,
                detection.event_id,
                detection.rule_id,
                detection.technique_id,
                detection.tactic,
                json.dumps(detection.evidence, sort_keys=True, default=str),
            ) for detection in db.detections())

        def membership_groups(db: Storage):
            with db.connect() as connection:
                rows = connection.execute("SELECT incident_id,event_id FROM incident_events").fetchall()
            groups: dict[str, list[str]] = {}
            for incident_id, event_id in rows:
                groups.setdefault(incident_id, []).append(event_id)
            return sorted(tuple(sorted(event_ids)) for event_ids in groups.values())

        assert event_fingerprint(storage) == event_fingerprint(path_storage)
        assert detection_fingerprint(storage) == detection_fingerprint(path_storage)
        assert membership_groups(storage) == membership_groups(path_storage)
        assert Counter((item.technique_id, item.tactic) for item in storage.detections()) == Counter(
            (item.technique_id, item.tactic) for item in path_storage.detections()
        )
    finally:
        destination.unlink(missing_ok=True)


def test_processing_endpoint_persists_incident_evidence(tmp_path, monkeypatch):
    import backend.api.routes as routes

    name = f"codex-process-{uuid4().hex}.jsonl"
    source = DATA_DIR / name
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [
        {
            "@timestamp": (timestamp + timedelta(minutes=minute)).isoformat(),
            "event": {
                "id": f"auth-{minute}",
                "category": ["authentication"],
                "outcome": "success" if minute == 5 else "failure",
            },
            "host": {"name": "AUTH-01"},
            "user": {"name": "admin"},
        }
        for minute in range(6)
    ]
    source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    storage = Storage(tmp_path / "process-endpoint.duckdb")
    service = IngestionService(storage)
    monkeypatch.setattr(routes, "store", storage)
    monkeypatch.setattr(routes, "ingestion", service)

    try:
        with TestClient(app) as client:
            response = client.post("/api/ingest/process", params={"filename": name})

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "complete"
        incidents = storage.incidents()
        assert len(incidents) == 1
        assert storage.events_for_incident(incidents[0].incident_id)
    finally:
        source.unlink(missing_ok=True)


def test_streaming_upload_detects_complete_batches_before_upload_finishes(tmp_path, monkeypatch):
    from queue import Queue
    from threading import Thread

    import backend.ingestion.service as service_module

    monkeypatch.setattr(service_module, "CHUNK_SIZE", 2)
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = [
        {
            "@timestamp": (timestamp + timedelta(minutes=index)).isoformat(),
            "event": {"id": f"live-auth-{index}", "category": ["authentication"], "outcome": "failure"},
            "host": {"name": "AUTH-LIVE"},
            "user": {"name": "analyst"},
        }
        for index in range(5)
    ]
    records.append({
        "@timestamp": (timestamp + timedelta(minutes=5)).isoformat(),
        "event": {"id": "live-auth-success", "category": ["authentication"], "outcome": "success"},
        "host": {"name": "AUTH-LIVE"},
        "user": {"name": "analyst"},
    })
    duplicate = {**records[0], "@timestamp": (timestamp + timedelta(minutes=6)).isoformat()}
    lines = [json.dumps(record).encode() + b"\n" for record in records]
    payload = b"".join([*lines, json.dumps(duplicate).encode() + b"\n", b"{malformed\n"])
    source = tmp_path / "stream-live.jsonl"
    partial = tmp_path / ".stream-live.partial"
    reference = tmp_path / "reference.jsonl"
    reference.write_bytes(payload)

    streamed_storage = Storage(tmp_path / "stream-live.duckdb")
    streamed_service = IngestionService(streamed_storage)
    run, started_at = streamed_service.start_streaming_upload(source, len(payload))
    chunks = Queue(maxsize=2)
    worker = Thread(target=streamed_service.consume_upload_stream, args=(partial, run, chunks, started_at), daemon=True)
    worker.start()
    chunks.put(b"".join(lines))

    deadline = time.monotonic() + 30
    interim = streamed_service.status()
    while time.monotonic() < deadline and interim["detections"] == 0:
        time.sleep(0.02)
        interim = streamed_service.status()

    assert interim["phase"] == "ingestion"
    assert interim["detections"] > 0
    assert interim["bytes_processed"] < len(payload)

    chunks.put(b"".join([json.dumps(duplicate).encode() + b"\n", b"{malformed\n"]))
    chunks.put(None)
    worker.join(timeout=10)
    assert not worker.is_alive()
    streamed_service.finish_streaming_upload(source, partial, run, started_at)

    deadline = time.monotonic() + 30
    streamed = streamed_service.status()
    while time.monotonic() < deadline and streamed["state"] not in {"complete", "failed"}:
        time.sleep(0.02)
        streamed = streamed_service.status()

    reference_storage = Storage(tmp_path / "stream-reference.duckdb")
    reference_status = IngestionService(reference_storage).process_sync(reference)
    assert streamed["state"] == "complete", streamed
    assert streamed["detections"] == reference_status["detections"]
    assert streamed["valid_records"] == 7
    assert streamed["invalid_records"] == 1
    assert streamed["duplicate_records"] == 1

    def evidence(db: Storage):
        return sorted((event.event_id, event.timestamp.isoformat(), event.host, event.user,
                       json.dumps(event.raw_event, sort_keys=True, default=str)) for event in db.events(limit=None))

    def detections(db: Storage):
        return sorted((item.detection_id, item.event_id, item.rule_id, item.technique_id, item.tactic,
                       json.dumps(item.evidence, sort_keys=True, default=str)) for item in db.detections())

    def memberships(db: Storage):
        with db.connect() as connection:
            rows = connection.execute("SELECT incident_id,event_id FROM incident_events").fetchall()
        groups: dict[str, list[str]] = {}
        for incident_id, event_id in rows:
            groups.setdefault(incident_id, []).append(event_id)
        return sorted(tuple(sorted(event_ids)) for event_ids in groups.values())

    assert evidence(streamed_storage) == evidence(reference_storage)
    assert detections(streamed_storage) == detections(reference_storage)
    assert memberships(streamed_storage) == memberships(reference_storage)
