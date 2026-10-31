from __future__ import annotations

import asyncio
import os
import queue
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.config import DATA_DIR
from backend.graph.attack_graph import build_graph, reachability
from backend.ingestion.service import IngestionService, SUPPORTED_SUFFIXES
from backend.ingestion.storage import Storage
from backend.reporting.incident_report import report

router = APIRouter(prefix="/api")
store = Storage()
ingestion = IngestionService(store)


class IngestionJobRequest(BaseModel):
    filename: str | None = None
    source_path: str | None = None


def _source_path(filename: str | None, source_path: str | None) -> Path:
    try:
        return ingestion.resolve_source(filename=filename, source_path=source_path)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/health")
def health():
    return {"status": "ok", "service": "ChainSight AI", "offline": True}


@router.post("/ingest/upload")
async def upload(file: UploadFile = File(...)):
    original = Path(file.filename or "upload.log").name
    suffix = Path(original).suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise HTTPException(400, f"Unsupported file extension: {suffix or '(none)'}")
    stem = Path(original).stem or "upload"
    safe = original
    destination = DATA_DIR / safe
    if destination.exists():
        safe = f"{stem}-{uuid4().hex[:8]}{suffix}"
        destination = DATA_DIR / safe
    temporary = DATA_DIR / f".{uuid4().hex}.upload"
    byte_count = 0
    try:
        with temporary.open("wb") as out:
            while chunk := await file.read(4 * 1024 * 1024):
                out.write(chunk)
                byte_count += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return {
        "file": safe,
        "bytes": byte_count,
        "message": "Saved locally. Start processing with /api/ingest/jobs for large files.",
    }


@router.post("/ingest/stream")
async def stream_upload(request: Request):
    """Receive raw file bytes while a bounded worker parses and stores complete records."""
    original = Path(unquote(request.headers.get("x-file-name", "upload.jsonl"))).name
    suffix = Path(original).suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise HTTPException(400, f"Unsupported file extension: {suffix or '(none)'}")
    if suffix in {".csv", ".tsv"}:
        raise HTTPException(400, "Streaming upload currently supports JSONL, JSON, CEF and line-oriented logs; use Process in place for CSV/TSV.")
    try:
        total_bytes = int(request.headers.get("x-file-size", "-1"))
    except ValueError as exc:
        raise HTTPException(400, "X-File-Size must be a non-negative integer.") from exc
    if total_bytes < 0:
        raise HTTPException(400, "X-File-Size must be a non-negative integer.")

    stem = Path(original).stem or "upload"
    destination = DATA_DIR / original
    if destination.exists():
        destination = DATA_DIR / f"{stem}-{uuid4().hex[:8]}{suffix}"
    partial_path = DATA_DIR / f".{uuid4().hex}.partial"
    try:
        run, started_at = ingestion.start_streaming_upload(destination, total_bytes)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc

    chunks: queue.Queue = queue.Queue(maxsize=2)
    loop = asyncio.get_running_loop()
    worker = loop.run_in_executor(None, ingestion.consume_upload_stream, partial_path, run, chunks, started_at)
    try:
        async for chunk in request.stream():
            if chunk:
                await asyncio.to_thread(chunks.put, bytes(chunk))
        await asyncio.to_thread(chunks.put, None)
        received = await worker
        status = ingestion.finish_streaming_upload(destination, partial_path, run, started_at)
    except Exception as exc:
        try:
            await asyncio.to_thread(chunks.put, None)
            await worker
        except Exception:
            pass
        ingestion.fail_streaming_upload(partial_path, run, exc, started_at)
        raise HTTPException(400 if isinstance(exc, ValueError) else 500, str(exc)) from exc
    return {
        "file": destination.name,
        "bytes": received,
        "job_id": status["run_id"],
        "state": status["state"],
        "phase": status.get("phase"),
        "detection_state": status.get("detection_state", "pending"),
        "status_url": f"/api/ingest/jobs/{status['run_id']}",
    }


@router.post("/ingest/process")
def process(filename: str | None = None, source_path: str | None = None):
    """Synchronous compatibility endpoint used by the existing dashboard."""
    path = _source_path(filename, source_path)
    try:
        return ingestion.process_sync(path)
    except RuntimeError as exc:
        if "already running" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(500, str(exc)) from exc


@router.post("/ingest/jobs")
@router.post("/ingestion/jobs")
def start_ingestion_job(request: IngestionJobRequest):
    path = _source_path(request.filename, request.source_path)
    try:
        state = ingestion.start_job(path)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {
        "job_id": state["run_id"],
        "state": state["state"],
        "phase": state.get("phase"),
        "status_url": f"/api/ingest/jobs/{state['run_id']}",
        "resuming": state.get("resuming", False),
    }


@router.get("/ingest/jobs/{job_id}")
@router.get("/ingestion/jobs/{job_id}")
@router.get("/ingest/status/{job_id}")
def ingestion_job(job_id: str):
    result = ingestion.job(job_id)
    if result is None:
        raise HTTPException(404, "Ingestion job not found")
    return result


@router.post("/ingest/pause/{job_id}")
def pause_ingestion_job(job_id: str):
    try:
        return ingestion.pause_job(job_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/ingest/resume/{job_id}")
def resume_ingestion_job(job_id: str):
    try:
        return ingestion.resume_job(job_id)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/ingest/cancel/{job_id}")
def cancel_ingestion_job(job_id: str):
    try:
        return ingestion.cancel_job(job_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/ingest/status")
def ingest_status():
    return ingestion.status()


@router.post("/ingest/reset")
@router.post("/reset")
def reset_database():
    store.clear_all()
    ingestion.reset_service()
    return {"status": "ok", "message": "All events, incidents, detections, and ingestion state have been reset to zero."}


@router.get("/ingest/history")
def ingestion_history(limit: int = 20):
    return store.get_ingestion_history(limit=limit)


@router.get("/dashboard/summary")
def summary():
    incident_summary = store.incident_overview()
    counts = store.dashboard_counts()
    severity_counts = {key: counts["severity_counts"].get(key, 0) for key in ["low", "medium", "high", "critical"]}
    return {
        "demo_data": ingestion.status().get("demo_data", False),
        **counts,
        "active_incidents": incident_summary["total"],
        "critical_incidents": incident_summary["critical"],
        "severity_counts": severity_counts,
        "recent_incidents": [item.model_dump(mode="json") for item in incident_summary["recent"]],
        "processing": ingestion.status(),
    }


@router.get("/events")
def events(limit: int = 200, offset: int = 0, severity: str | None = None):
    if limit < 1 or offset < 0:
        raise HTTPException(422, "limit must be positive and offset must be non-negative")
    total, values = store.event_page(min(limit, 1_000), offset, severity)
    return {"total": total, "items": [event.model_dump(mode="json") for event in values]}


@router.get("/incidents")
def incidents(severity: str | None = None):
    values = store.incidents()
    if severity:
        values = [item for item in values if item.risk_label.lower() == severity.lower() or item.severity == severity.lower()]
    return {"items": [item.model_dump(mode="json") for item in sorted(values, key=lambda item: item.risk_score, reverse=True)]}


def incident_or_404(incident_id: str):
    item = store.incident(incident_id)
    if item is None:
        raise HTTPException(404, "Incident not found")
    return item


def incident_data(incident):
    return store.events_for_incident(incident.incident_id), store.detections_for_incident(incident.incident_id)


@router.get("/incidents/{incident_id}")
def incident(incident_id: str):
    return incident_or_404(incident_id).model_dump(mode="json")


@router.get("/incidents/{incident_id}/timeline")
def timeline(incident_id: str):
    values, _ = incident_data(incident_or_404(incident_id))
    return {"items": [event.model_dump(mode="json") for event in values]}


@router.get("/incidents/{incident_id}/graph")
def graph(incident_id: str):
    item = incident_or_404(incident_id)
    events, detections = incident_data(item)
    return build_graph(item, events, detections)


@router.get("/incidents/{incident_id}/reachability")
def reachable(incident_id: str):
    item = incident_or_404(incident_id)
    events, detections = incident_data(item)
    return {"items": reachability(build_graph(item, events, detections))}


@router.get("/incidents/{incident_id}/path")
def incident_path(incident_id: str):
    item = incident_or_404(incident_id)
    events, detections = incident_data(item)
    graph_data = build_graph(item, events, detections)
    reachable_targets = reachability(graph_data)

    seen_tactics = []
    path_hops = []
    for idx, e in enumerate(events, 1):
        if e.tactic and e.tactic not in seen_tactics:
            seen_tactics.append(e.tactic)
        
        hop_desc = (
            f"{e.source_ip} -> {e.destination_ip}"
            if (e.source_ip and e.destination_ip and e.source_ip != e.destination_ip)
            else (e.host or "Unknown host")
        )
        tech_label = f"{e.technique_id} ({e.technique_name})" if e.technique_id else None
        path_hops.append({
            "step": idx,
            "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
            "host": e.host,
            "user": e.user,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "process": e.process_name,
            "action": e.action,
            "technique": tech_label,
            "kill_chain_stage": e.tactic,
            "severity": e.severity,
            "hop": hop_desc,
        })

    return {
        "incident_id": item.incident_id,
        "attack_type": item.attack_type,
        "risk_score": item.risk_score,
        "risk_label": item.risk_label,
        "confidence": item.confidence,
        "first_seen": item.first_observed.isoformat() if hasattr(item.first_observed, "isoformat") else str(item.first_observed),
        "last_seen": item.last_observed.isoformat() if hasattr(item.last_observed, "isoformat") else str(item.last_observed),
        "hosts_involved": item.hosts,
        "users_involved": item.users,
        "kill_chain_stages": seen_tactics,
        "behavior_summary": item.behavior_summary,
        "attack_path": path_hops,
        "look_ahead": {
            "description": "Defensive reachability leads: systems/addresses reachable from observed footholds",
            "next_reachable_targets": reachable_targets,
            "target_count": len(reachable_targets),
        },
        "graph": graph_data,
    }


@router.get("/mitre/techniques")
def techniques():
    return {"items": store.mitre_summary()}


@router.get("/reports/{incident_id}")
def get_report(incident_id: str, format: str = "json"):
    item = incident_or_404(incident_id)
    events, detections = incident_data(item)
    graph_data = build_graph(item, events, detections)
    detection_summary = store.detection_summary_for_incident(incident_id)
    payload, html = report(item, events, detections, reachability(graph_data), detection_summary)
    return HTMLResponse(html) if format.lower() == "html" else JSONResponse(payload)
