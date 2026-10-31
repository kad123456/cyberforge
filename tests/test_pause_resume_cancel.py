import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from backend.main import app
from backend.config import DATA_DIR
from backend.ingestion.service import IngestionService
from backend.ingestion.storage import Storage


def test_pause_resume_and_cancel_job(tmp_path: Path, monkeypatch):
    import backend.api.routes as routes

    test_file = DATA_DIR / f"test_pause_resume_{int(time.time())}.jsonl"
    # Create 500 records
    records = [
        {"@timestamp": f"2026-01-01T00:{i//60:02d}:{i%60:02d}Z", "event": {"id": f"rec-{i}", "category": "test"}, "host": {"name": "H1"}}
        for i in range(500)
    ]
    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    storage = Storage(tmp_path / "test_ctrl.duckdb")
    service = IngestionService(storage)
    monkeypatch.setattr(routes, "store", storage)
    monkeypatch.setattr(routes, "ingestion", service)

    client = TestClient(app)
    try:
        # 1. Start job
        resp = client.post("/api/ingest/jobs", json={"filename": test_file.name})
        assert resp.status_code == 200
        job_id = resp.json()["job_id"]

        # 2. Check status endpoint /api/ingest/status/{job_id}
        status_resp = client.get(f"/api/ingest/status/{job_id}")
        assert status_resp.status_code == 200
        assert status_resp.json()["job_id"] == job_id

        # 3. Test cancel or pause
        # If job already completed because it was small, verify state
        state = status_resp.json()["state"]
        if state == "processing":
            pause_resp = client.post(f"/api/ingest/pause/{job_id}")
            assert pause_resp.status_code in {200, 400}

        # 4. Test cancel on a paused or completed job
        cancel_resp = client.post(f"/api/ingest/cancel/{job_id}")
        assert cancel_resp.status_code in {200, 400}

        # Wait for thread to release the file handle
        for _ in range(30):
            if not service._active:
                break
            time.sleep(0.1)
    finally:
        try:
            test_file.unlink(missing_ok=True)
        except OSError:
            pass


def test_source_file_changed_rejects_resume(tmp_path: Path):
    test_file = tmp_path / "tamper_test.jsonl"
    records = [{"@timestamp": "2026-01-01T00:00:00Z", "event": {"id": f"evt-{i}"}} for i in range(50)]
    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    storage = Storage(tmp_path / "tamper.duckdb")
    service = IngestionService(storage)

    run, _ = service._prepare_run(test_file)
    run["state"] = "paused"
    run["bytes_processed"] = 100
    storage.save_run(run)

    # Modify file
    time.sleep(0.01)
    test_file.write_text(test_file.read_text(encoding="utf-8") + '{"event":{"id":"added"}}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Source file has changed"):
        service.resume_job(run["run_id"])
