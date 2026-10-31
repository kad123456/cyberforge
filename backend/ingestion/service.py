from __future__ import annotations

import copy
import logging
import math
import multiprocessing
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import psutil

from backend.config import (
    ADAPTIVE_TUNING_ENABLED,
    AUTO_INGEST_TUNING,
    BATCH_SIZE,
    CHUNK_SIZE,
    CHUNK_SIZE_OVERRIDE,
    CORRELATION_WINDOW_MINUTES,
    DATA_DIR,
    MAX_BATCH_RECORDS,
    MEMORY_BUDGET_BYTES,
    MIN_BATCH_RECORDS,
    PARSER_WORKERS,
    PARSER_WORKERS_OVERRIDE,
    READ_BUFFER_BYTES,
    READ_BUFFER_BYTES_OVERRIDE,
    ROOT,
    TARGET_MEMORY_RATIO,
)
from backend.correlation.correlator import StreamingCorrelator
from backend.detection.engine import DetectionEngine
from backend.ingestion.parser import detect_format, normalize, normalize_fortigate_line, parse_line
from backend.ingestion.reader import stream_csv_records, stream_jsonl_records, stream_records
from backend.ingestion.storage import Storage
from backend.ingestion.tuning import (
    AdaptiveBatchOptimizer,
    classify_file_tier,
    select_ingestion_profile,
)

logger = logging.getLogger(__name__)

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".log", ".cef", ".txt", ".csv", ".tsv"}


def _normalize_payload_batch(payloads):
    results = []
    for kind, payload in payloads:
        try:
            if kind == "invalid":
                raise ValueError(payload.get("__parse_error__", "invalid CSV record"))
            if kind == "csv":
                event = normalize({"_format": "csv", "record": payload})
            elif kind == "line":
                if isinstance(payload, bytes):
                    if payload.lstrip().startswith(b"{"):
                        event = normalize(parse_line(payload, source_format="jsonl"))
                        event.raw_event_json = payload
                    elif b"date=" in payload and b"type=" in payload:
                        event = normalize_fortigate_line(payload)
                    else:
                        event = normalize(parse_line(payload))
                else:
                    stripped = payload.lstrip()
                    if stripped.startswith("{"):
                        event = normalize(parse_line(payload, source_format="jsonl"))
                    elif "date=" in payload and "type=" in payload:
                        event = normalize_fortigate_line(payload)
                    else:
                        event = normalize(parse_line(payload))
            else:
                event = normalize(parse_line(payload))
            results.append((event, None))
        except Exception as exc:
            results.append((None, f"{type(exc).__name__}: {exc}"))
    return results


def _parse_payload_batch(payloads, executor, workers: int):
    if executor is None or len(payloads) < 2:
        return _normalize_payload_batch(payloads), executor
    chunk_size = math.ceil(len(payloads) / workers)
    futures = [
        executor.submit(_normalize_payload_batch, payloads[start:start + chunk_size])
        for start in range(0, len(payloads), chunk_size)
    ]
    try:
        return [result for future in futures for result in future.result()], executor
    except Exception:
        logger.exception("Parallel log parsing failed; continuing this job in the main process")
        executor.shutdown(wait=False, cancel_futures=True)
        return _normalize_payload_batch(payloads), None


class IngestionService:
    """Single-machine ingestion coordinator with bounded work and resumable jobs."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._active = False
        self._pause_requested = threading.Event()
        self._cancel_requested = threading.Event()
        self._status = self._idle_status()
        self._committed_stats = {}
        self._resource_process = psutil.Process(os.getpid())
        self._resource_process.cpu_percent(interval=None)
        self._last_resource_sample = 0.0
        self._last_cpu_percent = 0.0
        self._sampled_peak_memory = 0
        self.storage.mark_interrupted_runs()
        latest = self.storage.latest_run()
        if latest:
            self._status = latest

    @staticmethod
    def _idle_status() -> dict:
        return {
            "state": "idle", "phase": None, "demo_data": False,
            "total_records": 0, "valid_records": 0, "invalid_records": 0,
            "duplicate_records": 0, "skipped_records": 0, "detections": 0,
            "incidents": 0, "duration_seconds": 0.0, "throughput_eps": 0.0,
            "throughput_mb_s": 0.0, "eta_seconds": 0.0, "current_batch_number": 0,
            "bytes_total": 0, "bytes_processed": 0, "percent_complete": 0.0,
            "analysis_records": 0, "analysis_total": 0, "cpu_percent": 0.0,
            "memory_rss_bytes": 0, "peak_memory_bytes": 0,
            "duckdb_memory_bytes": 0, "duckdb_size_bytes": 0,
            "last_file": None, "errors": [],
            "optimization_status": "Adaptive dynamic tuning initialized",
            "bottleneck": "Balanced throughput",
            "batch_records": BATCH_SIZE,
            "profiling": {},
        }

    def status(self) -> dict:
        with self._state_lock:
            status = self._status.copy()
            if "profiling" in self._status and isinstance(self._status["profiling"], dict):
                status["profiling"] = self._status["profiling"].copy()
            if "errors" in self._status and isinstance(self._status["errors"], list):
                status["errors"] = list(self._status["errors"])
            return status

    def reset_service(self):
        with self._lock:
            with self._state_lock:
                self._active = False
                self._pause_requested.clear()
                self._cancel_requested.clear()
                self._status = self._idle_status()
                self._committed_stats = {}
                self._sampled_peak_memory = 0

    def _apply_ingestion_profile(self, run: dict, file_size_bytes: int, file_format: str = "jsonl") -> None:
        if run.get("tuning_profile") and run.get("batch_records"):
            return
        tier = classify_file_tier(file_size_bytes)
        historical = None
        if ADAPTIVE_TUNING_ENABLED:
            historical = self.storage.lookup_historical_optimal(file_format, tier)

        effective_max = min(CHUNK_SIZE, MAX_BATCH_RECORDS)
        effective_override = CHUNK_SIZE_OVERRIDE or (historical["optimal_batch_size"] if historical else None)
        if effective_override is not None:
            effective_override = min(effective_override, effective_max)
        elif CHUNK_SIZE < MAX_BATCH_RECORDS:
            effective_override = CHUNK_SIZE

        profile = select_ingestion_profile(
            file_size_bytes,
            cpu_count=os.cpu_count() or 1,
            available_memory_bytes=psutil.virtual_memory().available,
            max_batch_records=effective_max,
            max_parser_workers=PARSER_WORKERS,
            batch_override=effective_override,
            worker_override=PARSER_WORKERS_OVERRIDE,
            buffer_override=READ_BUFFER_BYTES_OVERRIDE,
            enabled=AUTO_INGEST_TUNING,
        )
        opt_status = (
            f"Seeded batch {profile.batch_records:,} from historical {file_format} runs ({historical['bottleneck']})"
            if historical
            else f"Adaptive dynamic tuning initialized ({profile.name})"
        )
        run.update({
            "tuning_profile": profile.name,
            "tuning_reason": profile.reason,
            "file_format": file_format,
            "file_size_tier": tier,
            "batch_records": profile.batch_records,
            "parser_workers": profile.parser_workers,
            "read_buffer_bytes": profile.read_buffer_bytes,
            "auto_tuning": AUTO_INGEST_TUNING,
            "adaptive_tuning": ADAPTIVE_TUNING_ENABLED,
            "optimization_status": opt_status,
            "bottleneck": historical["bottleneck"] if historical else "Balanced throughput",
            "profiling": {},
        })

    def job(self, run_id: str) -> dict | None:
        with self._state_lock:
            if self._status.get("run_id") == run_id and self._status.get("state") == "processing":
                return copy.deepcopy(self._status)
        run = self.storage.get_run(run_id)
        if run:
            return run
        return None

    @staticmethod
    def _source_signature(path: Path) -> tuple[str, int, int, str]:
        stat = path.stat()
        return str(path.resolve()), stat.st_size, stat.st_mtime_ns, f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"

    def resolve_source(self, filename: str | None = None, source_path: str | None = None) -> Path:
        if source_path:
            candidate = Path(source_path).expanduser().resolve()
            downloads_dir = (Path.home() / "Downloads").resolve()
            allowed = (DATA_DIR.resolve(), ROOT.parent.resolve(), downloads_dir)
            if not candidate.is_file() or not any(candidate.is_relative_to(root) for root in allowed):
                raise ValueError("Source must be a local file inside the data directory or Downloads.")
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                raise ValueError(f"Unsupported file extension: {candidate.suffix or '(none)'}")
            return candidate

        if filename:
            candidate = DATA_DIR / Path(filename).name
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                raise ValueError(f"Unsupported file extension: {candidate.suffix or '(none)'}")
            if not candidate.is_file():
                raise FileNotFoundError(f"No compatible local log file found in data/: {candidate.name}")
            return candidate.resolve()

        files = [path for path in DATA_DIR.iterdir() if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES]
        if not files:
            raise FileNotFoundError("No compatible local log file found in data/.")
        return max(files, key=lambda path: path.stat().st_mtime).resolve()

    def pause_job(self, job_id: str) -> dict:
        with self._lock:
            with self._state_lock:
                current_id = self._status.get("run_id") or self._status.get("job_id")
                if current_id == job_id and self._status.get("state") in {"processing", "queued"}:
                    self._pause_requested.set()
                    self._status["state"] = "paused"
                    self._status["message"] = "Ingestion paused by user."
                    try:
                        self.storage.save_run(self._status)
                    except Exception:
                        pass
                    return copy.deepcopy(self._status)
            run = self.storage.get_run(job_id)
            if not run:
                raise ValueError(f"Job {job_id} not found.")
            if run.get("state") in {"complete", "cancelled"}:
                raise ValueError(f"Cannot pause a job in state '{run.get('state')}'.")
            run["state"] = "paused"
            run["message"] = "Ingestion paused by user."
            self.storage.save_run(run)
            return run

    def resume_job(self, job_id: str) -> dict:
        with self._lock:
            if self._active:
                raise RuntimeError("Another ingestion job is currently running.")
            run = self.storage.get_run(job_id)
            if not run:
                raise ValueError(f"Job {job_id} not found.")
            if run.get("state") not in {"paused", "interrupted", "failed"}:
                raise ValueError(f"Cannot resume a job with state '{run.get('state')}'; only paused/interrupted jobs can be resumed.")
            source_path = Path(run["source_path"])
            if not source_path.is_file():
                raise FileNotFoundError(f"Source file {source_path} not found.")
            sig = self._source_signature(source_path)
            if sig[3] != run["source_signature"]:
                raise ValueError("Source file has changed since ingestion started. Cannot resume.")

            self._pause_requested.clear()
            self._cancel_requested.clear()
            run["state"] = "processing"
            run["resuming"] = True
            run["message"] = f"Resuming from record {run.get('total_records', 0)} (byte offset {run.get('bytes_processed', 0)})."
            run["updated_at"] = datetime.now(timezone.utc).isoformat()
            self.storage.create_staging(run["run_id"], resume=True)
            self.storage.save_run(run)
            self._active = True
            self._set_status(run)
            thread = threading.Thread(target=self._run_job, args=(source_path, run), daemon=True, name=f"resume-{run['run_id'][:8]}")
            thread.start()
            return self.status()

    def cancel_job(self, job_id: str) -> dict:
        with self._lock:
            with self._state_lock:
                current_id = self._status.get("run_id") or self._status.get("job_id")
                if current_id == job_id and self._status.get("state") in {"processing", "queued", "paused"}:
                    self._cancel_requested.set()
                    self._status["state"] = "cancelled"
                    self._status["message"] = "Ingestion cancelled by user."
                    try:
                        self.storage.save_run(self._status)
                    except Exception:
                        pass
                    return copy.deepcopy(self._status)
            run = self.storage.get_run(job_id)
            if not run:
                raise ValueError(f"Job {job_id} not found.")
            run["state"] = "cancelled"
            run["message"] = "Ingestion cancelled by user."
            self.storage.save_run(run)
            return run

    def _prepare_run(self, path: Path) -> tuple[dict, bool]:
        resolved, size, mtime_ns, signature = self._source_signature(path)
        previous = self.storage.find_resumable_run(signature)
        resume = bool(previous and self.storage.has_staging(previous["run_id"]))
        if resume:
            run = previous
            self.storage.create_staging(run["run_id"], resume=True)
            if run.get("deduplicated_during_ingestion") and run.get("bytes_processed", 0) < size:
                # A restarted rule engine has lost stateful windows (for example,
                # failed-login sequences). Rebuild detections from the staged
                # events after ingestion resumes rather than reusing partial results.
                self.storage.clear_staging_analysis()
                run["detections"] = 0
                run["analysis_records"] = 0
                run["analysis_total"] = 0
                run["detections_precomputed"] = False
                run["stream_detection_provisional"] = False
                run["detection_state"] = "pending"
                run["force_full_detection"] = True
        else:
            run_id = str(uuid4())
            run = {
                **self._idle_status(),
                "run_id": run_id,
                "job_id": run_id,
                "state": "queued",
                "phase": "ingestion",
                "source_path": resolved,
                "source_signature": signature,
                "bytes_total": size,
                "bytes_processed": 0,
                "line_number": 0,
                "total_records": 0,
                "valid_records": 0,
                "invalid_records": 0,
                "duplicate_records": 0,
                "skipped_records": 0,
                "detections": 0,
                "incidents": 0,
                "analysis_records": 0,
                "analysis_total": 0,
                "deduplicated_during_ingestion": True,
                "detections_precomputed": False,
                "stream_detection_provisional": False,
                "detection_state": "provisional",
                "timestamps_ordered": True,
                "last_event_timestamp": None,
                "duration_seconds": 0.0,
                "throughput_eps": 0.0,
                "peak_memory_bytes": 0,
                "errors": [],
                "last_file": path.name,
                "demo_data": "synthetic" in path.name.lower() or path.name.lower().startswith("edr_"),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self.storage.create_streaming_staging(run_id)
        suffix = path.suffix.lower()
        file_format = "csv" if suffix in {".csv", ".tsv"} else ("jsonl" if suffix in {".json", ".jsonl"} else "cef")
        self._apply_ingestion_profile(run, size, file_format=file_format)
        run.update({
            "state": "processing",
            "phase": "analysis" if run.get("bytes_processed", 0) >= size else "ingestion",
            "bytes_total": size,
            "resuming": resume,
            "message": "Resuming from the last committed batch." if resume else "Processing started.",
        })
        run["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.storage.save_run(run)
        return run, resume

    def start_job(self, path: Path) -> dict:
        with self._lock:
            if self._active:
                raise RuntimeError("An ingestion job is already running. Wait for it to finish before starting another.")
            self._pause_requested.clear()
            self._cancel_requested.clear()
            run, _ = self._prepare_run(path)
            self._active = True
            self._set_status(run)
            thread = threading.Thread(target=self._run_job, args=(path, run), daemon=True, name=f"ingest-{run['run_id'][:8]}")
            try:
                thread.start()
            except Exception:
                self._active = False
                raise
            return self.status()

    def start_streaming_upload(self, path: Path, total_bytes: int) -> tuple[dict, float]:
        """Create an isolated run that accepts bounded byte chunks as they arrive."""
        with self._lock:
            if self._active:
                raise RuntimeError("An ingestion job is already running. Wait for it to finish before uploading another source.")
            self._pause_requested.clear()
            self._cancel_requested.clear()
            run_id = str(uuid4())
            run = {
                **self._idle_status(),
                "run_id": run_id,
                "job_id": run_id,
                "state": "processing",
                "phase": "ingestion",
                "source_path": str(path.resolve()),
                "source_signature": f"streaming-upload:{run_id}",
                "bytes_total": total_bytes,
                "bytes_processed": 0,
                "upload_bytes_received": 0,
                "total_records": 0,
                "valid_records": 0,
                "invalid_records": 0,
                "duplicate_records": 0,
                "detections": 0,
                "incidents": 0,
                "analysis_records": 0,
                "analysis_total": 0,
                "deduplicated_during_ingestion": True,
                "detections_precomputed": False,
                "stream_detection_provisional": False,
                "detection_state": "provisional",
                "timestamps_ordered": True,
                "last_event_timestamp": None,
                "duration_seconds": 0.0,
                "ingestion_duration_seconds": 0.0,
                "throughput_eps": 0.0,
                "peak_memory_bytes": 0,
                "errors": [],
                "last_file": path.name,
                "demo_data": "synthetic" in path.name.lower() or path.name.lower().startswith("edr_"),
                "parser_workers": 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "message": "Receiving and parsing the source stream.",
            }
            self.storage.create_streaming_staging(run_id)
            suffix = path.suffix.lower()
            file_format = "csv" if suffix in {".csv", ".tsv"} else ("jsonl" if suffix in {".json", ".jsonl"} else "cef")
            self._apply_ingestion_profile(run, total_bytes, file_format=file_format)
            self.storage.save_run(run)
            started_at = time.perf_counter()
            self._active = True
            self._set_status(run)
            return run, started_at

    def consume_upload_stream(self, partial_path: Path, run: dict, chunks: queue.Queue, started_at: float) -> int:
        """Write and normalize upload chunks concurrently, retaining bounded batches."""
        pending = bytearray()
        raw_batch: list[tuple[int, int, str, bytes]] = []
        event_batch = []
        received = 0
        line_number = 0
        last_saved_at = time.monotonic()
        detection_engine = DetectionEngine()
        worker_count = max(1, int(run.get("parser_workers", 1)))
        batch_limit = max(1, min(int(run.get("batch_records", CHUNK_SIZE)), CHUNK_SIZE))
        optimizer = AdaptiveBatchOptimizer(
            min_batch=min(MIN_BATCH_RECORDS, batch_limit),
            max_batch=max(MAX_BATCH_RECORDS, batch_limit) if CHUNK_SIZE >= MAX_BATCH_RECORDS else batch_limit,
            initial_batch=batch_limit,
            memory_budget_bytes=MEMORY_BUDGET_BYTES,
            target_memory_ratio=TARGET_MEMORY_RATIO,
        )
        batch_limit = optimizer.current_batch
        executor = None
        if worker_count > 1:
            try:
                executor = ThreadPoolExecutor(max_workers=worker_count)
            except Exception:
                logger.exception("Could not start upload parser workers; using the main process")
                worker_count = 1
                run["parser_workers"] = 1

        try:
            with partial_path.open("wb", buffering=4 * 1024 * 1024) as output:
                with self.storage.writer(staging=True) as writer:
                    def flush(final_offset: int, final_line: int) -> None:
                        nonlocal executor, worker_count, batch_limit
                        records_in_batch = len(raw_batch)
                        bytes_in_batch = max(0, final_offset - run.get("bytes_processed", 0))

                        t_parse_sec = 0.0
                        if raw_batch:
                            t0 = time.perf_counter()
                            run["total_records"] = run.get("total_records", 0) + len(raw_batch)
                            payloads = [(kind, payload) for _, _, kind, payload in raw_batch]
                            parsed, executor = _parse_payload_batch(payloads, executor, worker_count)
                            if executor is None and worker_count > 1:
                                worker_count = 1
                                run["parser_workers"] = 1
                            for (number, _, _, _), (event, error) in zip(raw_batch, parsed):
                                if error:
                                    run["invalid_records"] = run.get("invalid_records", 0) + 1
                                    self._record_error(run, number, ValueError(error))
                                    continue
                                self._append_event(run, event_batch, event)
                                run["valid_records"] = run.get("valid_records", 0) + 1
                            raw_batch.clear()
                            t_parse_sec = time.perf_counter() - t0

                        run["current_batch_number"] = run.get("current_batch_number", 0) + 1
                        run["bytes_processed"] = final_offset
                        run["upload_bytes_received"] = received
                        run["line_number"] = final_line
                        run["percent_complete"] = round(min(100.0, 100.0 * received / max(1, run["bytes_total"])), 2)
                        self._metrics(run, started_at)

                        t0 = time.perf_counter()
                        accepted_events = writer.insert_stream_events(event_batch, checkpoint=run)
                        event_batch.clear()
                        t_write_sec = time.perf_counter() - t0

                        t_detect_sec = 0.0
                        if run.get("timestamps_ordered", True):
                            t0 = time.perf_counter()
                            detections = detection_engine.detect_batch(accepted_events)
                            t_detect_sec = time.perf_counter() - t0
                            if detections:
                                t_w = time.perf_counter()
                                writer.save_detections(detections)
                                t_write_sec += time.perf_counter() - t_w
                                run["detections"] = run.get("detections", 0) + len(detections)
                            run["analysis_records"] = run.get("analysis_records", 0) + len(accepted_events)
                            run["analysis_total"] = run["analysis_records"]
                            run["detections_precomputed"] = True
                            run["stream_detection_provisional"] = True
                            run["detection_state"] = "provisional"
                            run["message"] = "Parsing, deduplicating and detecting each complete batch during upload."
                        else:
                            if run.get("stream_detection_provisional"):
                                writer.clear_detections()
                                run["detections"] = 0
                                run["analysis_records"] = 0
                                run["analysis_total"] = 0
                            run["detections_precomputed"] = False
                            run["stream_detection_provisional"] = False
                            run["detection_state"] = "deferred_until_timestamp_sort"
                            run["message"] = "Source timestamps are out of order; exact detection will run after upload in timestamp order."

                        if ADAPTIVE_TUNING_ENABLED and records_in_batch > 0:
                            current_rss = run.get("memory_rss_bytes", 0)
                            available_ram = psutil.virtual_memory().available
                            duckdb_mem = run.get("duckdb_memory_bytes", 0)
                            new_batch, opt_status, bottleneck, profiling = optimizer.step(
                                records_count=records_in_batch,
                                bytes_count=bytes_in_batch,
                                parse_seconds=t_parse_sec,
                                write_seconds=t_write_sec,
                                detect_seconds=t_detect_sec,
                                process_rss=current_rss,
                                available_ram=available_ram,
                                duckdb_mem=duckdb_mem,
                            )
                            batch_limit = new_batch
                            run["batch_records"] = new_batch
                            run["optimization_status"] = opt_status
                            run["bottleneck"] = bottleneck
                            run["profiling"] = profiling

                        self._committed_stats = self._checkpoint_snapshot(run)
                        self._set_status(run)

                    while True:
                        chunk = chunks.get()
                        if chunk is None:
                            break
                        if not isinstance(chunk, bytes):
                            raise TypeError("Upload stream yielded a non-byte chunk.")
                        received += len(chunk)
                        if received > run["bytes_total"]:
                            raise ValueError("Uploaded bytes exceed the declared file size.")
                        output.write(chunk)
                        pending.extend(chunk)
                        start = 0
                        while True:
                            newline = pending.find(b"\n", start)
                            if newline < 0:
                                break
                            line = bytes(pending[start:newline + 1])
                            start = newline + 1
                            line_number += 1
                            if line.strip():
                                raw_batch.append((line_number, received, "line", line))
                            if len(raw_batch) >= batch_limit:
                                flush(received, line_number)
                        if start:
                            del pending[:start]
                        run["upload_bytes_received"] = received
                        run["bytes_processed"] = received
                        run["line_number"] = line_number
                        run["percent_complete"] = round(min(100.0, 100.0 * received / max(1, run["bytes_total"])), 2)
                        self._metrics(run, started_at)
                        now = time.monotonic()
                        if now - last_saved_at >= 0.5:
                            writer.save_run(run)
                            last_saved_at = now
                            self._set_status(run)

                    if pending:
                        line_number += 1
                        if pending.strip():
                            raw_batch.append((line_number, received, "line", bytes(pending)))
                    if received != run["bytes_total"]:
                        raise ValueError(f"Upload ended at {received} bytes; expected {run['bytes_total']}.")
                    flush(received, line_number)
                    if ADAPTIVE_TUNING_ENABLED and optimizer.batch_count > 0:
                        hist_entry = {
                            "format": run.get("file_format", "jsonl"),
                            "file_size_tier": classify_file_tier(run.get("bytes_total", 0)),
                            "file_size_bytes": run.get("bytes_total", 0),
                            **optimizer.summary(),
                        }
                        self.storage.record_ingestion_history(hist_entry)
                    output.flush()
                    writer.save_run(run)
            return received
        except BaseException:
            # Keep the bounded producer from hanging if parsing/storage fails.
            while chunks.get() is not None:
                pass
            raise
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)

    def finish_streaming_upload(self, path: Path, partial_path: Path, run: dict, started_at: float) -> dict:
        """Promote the complete upload then launch the existing detect/correlate stages."""
        partial_path.replace(path)
        signature = self._source_signature(path)
        if signature[1] != run["bytes_total"]:
            self.fail_streaming_upload(path, run, ValueError("Uploaded file size does not match its declared size."), started_at)
            raise ValueError("Uploaded file size does not match its declared size.")
        run["source_path"] = signature[0]
        run["source_signature"] = signature[3]
        run["bytes_total"] = signature[1]
        run["bytes_processed"] = signature[1]
        run["upload_bytes_received"] = signature[1]
        run["phase"] = "correlation" if run.get("detections_precomputed") else "analysis"
        run["percent_complete"] = 100.0
        run["ingestion_duration_seconds"] = max(0.0, time.perf_counter() - started_at)
        run["detection_state"] = "complete" if run.get("detections_precomputed") else "pending"
        run["message"] = (
            "Upload complete; detections are ready and correlation is starting."
            if run.get("detections_precomputed")
            else "Upload complete; deduplication, detection and correlation are starting."
        )
        self._metrics(run, started_at)
        self.storage.save_run(run)
        self._set_status(run)
        thread = threading.Thread(target=self._run_job, args=(path, run), daemon=True, name=f"analyze-upload-{run['run_id'][:8]}")
        try:
            thread.start()
        except Exception as exc:
            self.fail_streaming_upload(path, run, exc, started_at)
            raise
        return self.status()

    def fail_streaming_upload(self, partial_path: Path, run: dict, error: Exception, started_at: float) -> None:
        run["state"] = "failed"
        run["phase"] = "failed"
        run["message"] = f"{type(error).__name__}: {error}"
        run.setdefault("errors", []).append(run["message"])
        self._metrics(run, started_at)
        try:
            self.storage.save_run(run)
        except Exception:
            logger.exception("Could not persist failed streaming upload status")
        self._set_status(run)
        partial_path.unlink(missing_ok=True)
        with self._lock:
            self._active = False

    def process_sync(self, path: Path) -> dict:
        with self._lock:
            if self._active:
                raise RuntimeError("An ingestion job is already running. Wait for it to finish before starting another.")
            run, _ = self._prepare_run(path)
            self._active = True
            self._set_status(run)
        self._run_job(path, run)
        result = self.status()
        if result.get("state") == "failed":
            raise RuntimeError(result.get("message", "Ingestion failed"))
        return result

    def _set_status(self, run: dict):
        with self._state_lock:
            status = run.copy()
            if "profiling" in run and isinstance(run["profiling"], dict):
                status["profiling"] = run["profiling"].copy()
            if "errors" in run and isinstance(run["errors"], list):
                status["errors"] = run["errors"][-20:]
            self._status = status

    def _metrics(self, run: dict, started_at: float):
        elapsed = run.get("prior_duration_seconds", 0.0) + max(0.0, time.perf_counter() - started_at)
        run["duration_seconds"] = round(elapsed, 3)
        run["throughput_eps"] = round(run.get("total_records", 0) / max(elapsed, 0.001), 1)
        bytes_proc = run.get("bytes_processed", 0)
        run["throughput_mb_s"] = round((bytes_proc / (1024 * 1024)) / max(elapsed, 0.001), 2)
        total_b = run.get("bytes_total", 0)
        if bytes_proc > 0 and total_b > bytes_proc:
            speed = bytes_proc / max(elapsed, 0.001)
            remaining_bytes = total_b - bytes_proc
            run["eta_seconds"] = round(remaining_bytes / max(speed, 1.0), 1)
        else:
            run["eta_seconds"] = 0.0
        run["skipped_records"] = run.get("invalid_records", 0) + run.get("duplicate_records", 0)

        now = time.monotonic()
        terminal = run.get("state") in {"complete", "failed", "paused", "cancelled"}
        if terminal or now - self._last_resource_sample >= 1.0:
            cpu_percent = self._resource_process.cpu_percent(interval=None)
            rss = self._resource_process.memory_info().rss
            for child in self._resource_process.children(recursive=True):
                try:
                    rss += child.memory_info().rss
                    cpu_percent += child.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self._last_cpu_percent = cpu_percent
            self._sampled_peak_memory = max(self._sampled_peak_memory, rss)
            self._last_resource_sample = now

        run["cpu_percent"] = round(self._last_cpu_percent, 1)
        run["memory_rss_bytes"] = int(self._resource_process.memory_info().rss)
        run["peak_memory_bytes"] = max(run.get("peak_memory_bytes", 0), self._sampled_peak_memory)
        run["duckdb_memory_bytes"] = self.storage.memory_usage_bytes()
        run["duckdb_size_bytes"] = self.storage.db_size_bytes()
        run["updated_at"] = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _record_error(run: dict, line_number: int, exc: Exception):
        if len(run.setdefault("errors", [])) < 10:
            message = f"Line {line_number}: {type(exc).__name__}: {exc}"
            run["errors"].append(message)
            logger.warning("Malformed source record", extra={"line_number": line_number, "parse_error": str(exc)})

    @staticmethod
    def _append_event(run: dict, batch: list, event):
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
            event.timestamp = timestamp
        elif timestamp.tzinfo != timezone.utc:
            timestamp = timestamp.astimezone(timezone.utc)
            event.timestamp = timestamp

        previous = run.get("_last_event_dt")
        if not isinstance(previous, datetime) and previous is not None:
            try:
                previous = datetime.fromisoformat(str(previous))
                run["_last_event_dt"] = previous
            except Exception:
                previous = None

        if previous is not None and timestamp < previous:
            run["timestamps_ordered"] = False
        run["_last_event_dt"] = timestamp
        batch.append(event)

    def _detect_accepted_batch(self, writer, events: list, run: dict, engine: DetectionEngine, started_at: float) -> tuple[float, float]:
        """Detect first-seen events inline while preserving sorted-pass semantics. Returns (detect_seconds, write_seconds)."""
        t_detect = 0.0
        t_write = 0.0
        if run.get("timestamps_ordered", True):
            t0 = time.perf_counter()
            detections = engine.detect_batch(events)
            t_detect = time.perf_counter() - t0
            if detections:
                t1 = time.perf_counter()
                writer.save_detections(detections)
                t_write = time.perf_counter() - t1
                run["detections"] = run.get("detections", 0) + len(detections)
            run["analysis_records"] = run.get("analysis_records", 0) + len(events)
            run["analysis_total"] = run["analysis_records"]
            run["detections_precomputed"] = True
            run["stream_detection_provisional"] = True
            run["detection_state"] = "provisional"
            run["message"] = "Parsing, deduplicating and detecting each complete batch during ingestion."
        else:
            if run.get("stream_detection_provisional"):
                writer.clear_detections()
                run["detections"] = 0
                run["analysis_records"] = 0
                run["analysis_total"] = 0
            run["detections_precomputed"] = False
            run["stream_detection_provisional"] = False
            run["detection_state"] = "deferred_until_timestamp_sort"
            run["message"] = "Source timestamps are out of order; exact detection will run in timestamp order."
        self._metrics(run, started_at)
        return t_detect, t_write

    def _run_job(self, path: Path, run: dict):
        started_at = time.perf_counter()
        run["prior_duration_seconds"] = run.get("duration_seconds", 0.0)
        run.setdefault("ingestion_duration_seconds", 0.0)
        run.setdefault("analysis_duration_seconds", 0.0)
        self._committed_stats = self._checkpoint_snapshot(run)
        try:
            current_signature = self._source_signature(path)
            if current_signature[3] != run["source_signature"]:
                raise RuntimeError("The source file changed after this job was queued; start a new job for the updated file.")

            if run.get("phase") != "analysis" and run.get("bytes_processed", 0) < current_signature[1]:
                ingestion_started = time.perf_counter()
                self._ingest_source(path, run, started_at)
                run["ingestion_duration_seconds"] += time.perf_counter() - ingestion_started

            if run.get("state") in {"paused", "cancelled"}:
                return

            if not run.get("cross_batch_duplicates_counted"):
                self.storage.finalize_staging_events(run)
            run["phase"] = "analysis"
            run["bytes_processed"] = run["bytes_total"]
            self._metrics(run, started_at)
            self._set_status(run)
            self.storage.save_run(run)
            analysis_started = time.perf_counter()
            self._analyze_staging(run, started_at)
            run["analysis_duration_seconds"] += time.perf_counter() - analysis_started

            final_signature = self._source_signature(path)
            if final_signature[3] != run["source_signature"]:
                raise RuntimeError("The source file changed during processing; results were not published.")
            run["state"] = "complete"
            run["phase"] = "complete"
            run["percent_complete"] = 100.0
            run["message"] = "Ingestion and analysis completed."
            if run.get("invalid_records", 0):
                logger.warning(
                    "Ingestion completed with malformed records",
                    extra={
                        "run_id": run.get("run_id"),
                        "invalid_records": run["invalid_records"],
                        "logged_examples": len(run.get("errors", [])),
                    },
                )
            self._metrics(run, started_at)
            self.storage.publish_staging(run)
            self._set_status(run)
        except Exception as exc:
            logger.exception("Ingestion job %s failed", run.get("run_id"))
            if run.get("phase") == "ingestion":
                run.update(self._committed_stats)
            run["state"] = "failed"
            run["message"] = f"{type(exc).__name__}: {exc}"
            self._metrics(run, started_at)
            try:
                self.storage.save_run(run)
            except Exception:
                logger.exception("Could not persist failed ingestion job status")
            self._set_status(run)
        finally:
            with self._lock:
                self._active = False

    def _ingest_source(self, path: Path, run: dict, started_at: float):
        run["phase"] = "ingestion"
        offset = int(run.get("bytes_processed", 0))
        line_number = int(run.get("line_number", 0))
        is_csv = path.suffix.lower() in {".csv", ".tsv"}
        is_jsonl = path.suffix.lower() in {".json", ".jsonl"}
        format_name = "csv" if is_csv else ("jsonl" if is_jsonl else "cef")
        self._apply_ingestion_profile(run, run["bytes_total"], file_format=format_name)

        batch_limit = max(1, min(int(run.get("batch_records", CHUNK_SIZE)), CHUNK_SIZE))
        optimizer = AdaptiveBatchOptimizer(
            min_batch=min(MIN_BATCH_RECORDS, batch_limit),
            max_batch=max(MAX_BATCH_RECORDS, batch_limit) if CHUNK_SIZE >= MAX_BATCH_RECORDS else batch_limit,
            initial_batch=batch_limit,
            memory_budget_bytes=MEMORY_BUDGET_BYTES,
            target_memory_ratio=TARGET_MEMORY_RATIO,
        )
        batch_limit = optimizer.current_batch
        worker_count = max(1, min(int(run.get("parser_workers", 1)), batch_limit))
        buffer_size = max(1, int(run.get("read_buffer_bytes", READ_BUFFER_BYTES)))
        executor = None
        if worker_count > 1:
            try:
                executor = ThreadPoolExecutor(max_workers=worker_count)
            except Exception:
                logger.exception("Could not start parser workers; using the main process")
                worker_count = 1
        run["parser_workers"] = worker_count
        detection_engine = (
            DetectionEngine()
            if run.get("deduplicated_during_ingestion") and not run.get("force_full_detection")
            else None
        )
        if detection_engine is not None and run.get("detection_engine_state"):
            detection_engine.import_state(run["detection_engine_state"])
        raw_batch = []
        event_batch = []
        latest_offset = offset
        latest_line = line_number
        last_state_export = 0.0

        def flush(writer, final_offset: int, final_line: int):
            nonlocal executor, batch_limit, last_state_export
            records_in_batch = len(raw_batch)
            bytes_in_batch = max(0, final_offset - run.get("bytes_processed", 0))

            t_parse_sec = 0.0
            if raw_batch:
                t0 = time.perf_counter()
                run["total_records"] = run.get("total_records", 0) + len(raw_batch)
                payloads = [(kind, payload) for _, _, kind, payload in raw_batch]
                parsed, executor = _parse_payload_batch(payloads, executor, worker_count)
                if executor is None and worker_count > 1:
                    run["parser_workers"] = 1
                for (number, _, _, _), (event, error) in zip(raw_batch, parsed):
                    if error:
                        run["invalid_records"] = run.get("invalid_records", 0) + 1
                        self._record_error(run, number, ValueError(error))
                        continue
                    self._append_event(run, event_batch, event)
                    run["valid_records"] = run.get("valid_records", 0) + 1
                raw_batch.clear()
                t_parse_sec = time.perf_counter() - t0

            if run.get("_last_event_dt"):
                run["last_event_timestamp"] = run["_last_event_dt"].isoformat()

            run["current_batch_number"] = run.get("current_batch_number", 0) + 1
            run["bytes_processed"] = final_offset
            run["line_number"] = final_line
            run["percent_complete"] = round(min(100.0, 100.0 * final_offset / max(1, run["bytes_total"])), 2)
            self._metrics(run, started_at)

            t0 = time.perf_counter()
            if run.get("deduplicated_during_ingestion"):
                accepted_events = writer.insert_stream_events(event_batch, checkpoint=run)
            else:
                writer.insert_events(event_batch, checkpoint=run)
                accepted_events = []
            event_batch.clear()
            t_write_sec = time.perf_counter() - t0

            t_detect_sec = 0.0
            if detection_engine is not None and accepted_events:
                t_det, t_det_w = self._detect_accepted_batch(writer, accepted_events, run, detection_engine, started_at)
                t_detect_sec = t_det
                t_write_sec += t_det_w
                now_mono = time.monotonic()
                if now_mono - last_state_export >= 2.0 or self._pause_requested.is_set():
                    run["detection_engine_state"] = detection_engine.export_state()
                    last_state_export = now_mono

            if ADAPTIVE_TUNING_ENABLED and records_in_batch > 0:
                current_rss = run.get("memory_rss_bytes", 0)
                available_ram = psutil.virtual_memory().available
                duckdb_mem = run.get("duckdb_memory_bytes", 0)
                new_batch, opt_status, bottleneck, profiling = optimizer.step(
                    records_count=records_in_batch,
                    bytes_count=bytes_in_batch,
                    parse_seconds=t_parse_sec,
                    write_seconds=t_write_sec,
                    detect_seconds=t_detect_sec,
                    process_rss=current_rss,
                    available_ram=available_ram,
                    duckdb_mem=duckdb_mem,
                )
                batch_limit = new_batch
                run["batch_records"] = new_batch
                run["optimization_status"] = opt_status
                run["bottleneck"] = bottleneck
                run["profiling"] = profiling

            self._committed_stats = self._checkpoint_snapshot(run)
            self._set_status(run)

        try:
            with self.storage.writer(staging=True) as writer:
                if is_csv:
                    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
                    records = stream_csv_records(
                        path,
                        start_offset=offset,
                        start_line=line_number,
                        delimiter=delimiter,
                        buffer_bytes=buffer_size,
                    )
                    for number, end_offset, record in records:
                        if self._pause_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "paused"
                            run["message"] = f"Ingestion paused by user at record {run.get('total_records', 0)}."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        if self._cancel_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "cancelled"
                            run["message"] = "Ingestion cancelled by user."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        latest_offset, latest_line = end_offset, number
                        if not record:
                            continue
                        raw_batch.append((number, end_offset, "invalid" if "__parse_error__" in record else "csv", record))
                        if len(raw_batch) >= batch_limit:
                            flush(writer, end_offset, number)
                elif is_jsonl:
                    for number, end_offset, line in stream_jsonl_records(
                        path,
                        start_offset=offset,
                        start_line=line_number,
                        buffer_bytes=buffer_size,
                    ):
                        if self._pause_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "paused"
                            run["message"] = f"Ingestion paused by user at record {run.get('total_records', 0)}."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        if self._cancel_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "cancelled"
                            run["message"] = "Ingestion cancelled by user."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        latest_offset, latest_line = end_offset, number
                        if not line.strip():
                            continue
                        raw_batch.append((number, end_offset, "line", line))
                        if len(raw_batch) >= batch_limit:
                            flush(writer, end_offset, number)
                else:
                    for number, end_offset, line in stream_records(
                        path,
                        start_offset=offset,
                        start_line=line_number,
                        buffer_bytes=buffer_size,
                    ):
                        if self._pause_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "paused"
                            run["message"] = f"Ingestion paused by user at record {run.get('total_records', 0)}."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        if self._cancel_requested.is_set():
                            flush(writer, latest_offset, latest_line)
                            run["state"] = "cancelled"
                            run["message"] = "Ingestion cancelled by user."
                            self._metrics(run, started_at)
                            writer.save_run(run)
                            self._set_status(run)
                            return
                        latest_offset, latest_line = end_offset, number
                        if not line.strip():
                            continue
                        raw_batch.append((number, end_offset, "line", line))
                        if len(raw_batch) >= batch_limit:
                            flush(writer, end_offset, number)

                flush(writer, run["bytes_total"], latest_line)
                if detection_engine is not None:
                    run["detection_engine_state"] = detection_engine.export_state()
                if ADAPTIVE_TUNING_ENABLED and optimizer.batch_count > 0:
                    hist_entry = {
                        "format": format_name,
                        "file_size_tier": classify_file_tier(run.get("bytes_total", 0)),
                        "file_size_bytes": run.get("bytes_total", 0),
                        **optimizer.summary(),
                    }
                    self.storage.record_ingestion_history(hist_entry)
                run["phase"] = "analysis"
                run["percent_complete"] = 100.0
                self._metrics(run, started_at)
                writer.save_run(run)
        finally:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
        self._set_status(run)

    @staticmethod
    def _checkpoint_snapshot(run: dict) -> dict:
        fields = (
            "bytes_processed", "line_number", "total_records", "valid_records",
            "invalid_records", "duplicate_records", "skipped_records", "percent_complete", "errors",
            "timestamps_ordered", "last_event_timestamp", "current_batch_number",
            "batch_records", "optimization_status", "bottleneck", "profiling",
            "throughput_mb_s", "throughput_eps", "eta_seconds", "detection_engine_state",
            "peak_memory_bytes", "duckdb_memory_bytes", "duckdb_size_bytes",
        )
        return {field: copy.deepcopy(run.get(field)) for field in fields}

    def _analyze_staging(self, run: dict, started_at: float):
        run["analysis_total"] = run.get("valid_records", 0) - run.get("duplicate_records", 0)
        run["correlation_records"] = 0
        run["incidents"] = 0
        if run.get("detections_precomputed") and run.get("timestamps_ordered", False):
            run["analysis_records"] = run["analysis_total"]
            run["detection_state"] = "complete"
            run["message"] = "Detection completed during upload; correlating evidence now."
            self._metrics(run, started_at)
            self.storage.save_run(run)
            self._set_status(run)
        else:
            self.storage.clear_staging_analysis()
            run["analysis_records"] = 0
            run["detections"] = 0
            run["detection_state"] = "running"
            self._detect_staging(run, started_at)
            run["detection_state"] = "complete"
        self._correlate_staging(run, started_at)

    def _detect_staging(self, run: dict, started_at: float):
        """Detect over bounded event batches and persist detections in bulk."""
        engine = DetectionEngine()
        run["phase"] = "detection"

        with self.storage.writer(staging=True) as writer:
            writer.save_run(run)
            last_persisted_at = time.monotonic()
            for event_batch in self.storage.iter_events(
                int(run.get("batch_records", CHUNK_SIZE)),
                table="events_staging",
                source_ordered=run.get("timestamps_ordered", False),
                for_detection=True,
            ):
                detections = engine.detect_batch(event_batch)
                if detections:
                    writer.save_detections(detections)
                    run["detections"] += len(detections)
                run["analysis_records"] += len(event_batch)
                self._metrics(run, started_at)
                now = time.monotonic()
                if now - last_persisted_at >= 1.0:
                    writer.save_run(run)
                    last_persisted_at = now
                self._set_status(run)
            writer.save_run(run)

    def _correlate_staging(self, run: dict, started_at: float):
        """Correlate only stored detections, streaming their evidence join once."""
        run["phase"] = "correlation"
        correlator = StreamingCorrelator(CORRELATION_WINDOW_MINUTES)

        with self.storage.writer(staging=True) as writer:
            writer.save_run(run)
            last_persisted_at = time.monotonic()
            for detection_batch in self.storage.iter_detection_events(
                int(run.get("batch_records", CHUNK_SIZE)),
                staging=True,
                source_ordered=run.get("timestamps_ordered", False),
            ):
                memberships = []
                for detection, event in detection_batch:
                    incident_id = correlator.add(detection, event)
                    memberships.append((incident_id, event.event_id))
                if memberships:
                    writer.add_incident_events(memberships)
                if correlator.merges:
                    writer.merge_incidents(correlator.merges)
                    correlator.merges.clear()
                run["correlation_records"] += len(detection_batch)
                run["active_incidents"] = len(correlator.states)
                finalized = correlator.drain_finalized()
                if finalized:
                    event_counts = writer.incident_event_counts([item.incident_id for item in finalized])
                    for incident in finalized:
                        incident.event_count = event_counts.get(incident.incident_id, 0)
                    writer.save_incidents(finalized)
                    run["incidents"] += len(finalized)
                self._metrics(run, started_at)
                now = time.monotonic()
                if now - last_persisted_at >= 1.0:
                    writer.save_run(run)
                    last_persisted_at = now
                self._set_status(run)
            incidents = correlator.finalize_all()
            event_counts = writer.incident_event_counts([item.incident_id for item in incidents])
            for incident in incidents:
                incident.event_count = event_counts.get(incident.incident_id, 0)
            writer.save_incidents(incidents)
            run["incidents"] += len(incidents)
            run["message"] = "Analysis complete; publishing the new dataset."
            self._metrics(run, started_at)
            writer.save_run(run)
            self._set_status(run)
