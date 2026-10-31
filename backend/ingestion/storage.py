from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Iterable, Sequence
from uuid import uuid4

import duckdb
import orjson
import pyarrow as pa

logger = logging.getLogger(__name__)

from backend.config import DB_PATH, DUCKDB_MEMORY_LIMIT, DUCKDB_TEMP_DIR, DUCKDB_THREADS

EVENT_COLUMNS = [
    "event_id", "timestamp", "event_kind", "category", "action", "severity", "host",
    "source_ip", "destination_ip", "user", "process_name", "process_id", "parent_process",
    "command_line", "file_path", "registry_path", "domain", "technique_id", "technique_name",
    "tactic", "raw_event",
]

_EVENT_ARROW_SCHEMA = pa.schema([
    ("event_id", pa.string()), ("timestamp", pa.timestamp("us", tz="UTC")), ("event_kind", pa.string()),
    ("category", pa.string()), ("action", pa.string()), ("severity", pa.string()),
    ("host", pa.string()), ("source_ip", pa.string()), ("destination_ip", pa.string()),
    ("user_name", pa.string()), ("process_name", pa.string()), ("process_id", pa.string()),
    ("parent_process", pa.string()), ("command_line", pa.string()), ("file_path", pa.string()),
    ("registry_path", pa.string()), ("domain", pa.string()), ("technique_id", pa.string()),
    ("technique_name", pa.string()), ("tactic", pa.string()), ("rule_context", pa.json_()),
    ("raw_event", pa.json_()),
])
_DETECTION_ARROW_SCHEMA = pa.schema([
    ("detection_id", pa.string()), ("event_id", pa.string()), ("rule_id", pa.string()),
    ("rule_name", pa.string()), ("severity", pa.string()), ("technique_id", pa.string()),
    ("technique_name", pa.string()), ("tactic", pa.string()), ("confidence", pa.float64()),
    ("evidence", pa.string()),
])
_MEMBERSHIP_ARROW_SCHEMA = pa.schema([
    ("incident_id", pa.string()), ("event_id", pa.string()),
])
_MERGE_ARROW_SCHEMA = pa.schema([
    ("source_id", pa.string()), ("target_id", pa.string()),
])
_INCIDENT_ARROW_SCHEMA = pa.schema([
    ("incident_id", pa.string()), ("payload", pa.string()),
])


def _json(value) -> str:
    return orjson.dumps(value, default=str).decode("utf-8")


def _events_to_arrow_table(unique_events: Sequence) -> pa.Table:
    if not unique_events:
        return pa.Table.from_batches([], schema=_EVENT_ARROW_SCHEMA)
    first = unique_events[0]
    if getattr(first, "timestamp_us", 0):
        raw_ts = pa.array([e.timestamp_us for e in unique_events], type=pa.int64())
        ts_array = pa.Array.from_buffers(pa.timestamp("us", tz="UTC"), len(unique_events), [None, raw_ts.buffers()[1]])
    else:
        timestamps = [
            e.timestamp if getattr(e.timestamp, "tzinfo", None) is not None
            else e.timestamp.replace(tzinfo=timezone.utc)
            for e in unique_events
        ]
        ts_array = pa.array(timestamps, type=pa.timestamp("us", tz="UTC"))
    empty_ctx_json = "{}"
    raw_events = [
        e.raw_event_json.decode("utf-8", errors="replace")
        if isinstance(getattr(e, "raw_event_json", None), bytes)
        else (getattr(e, "raw_event_json", None) or (empty_ctx_json if not e.raw_event else _json(e.raw_event)))
        for e in unique_events
    ]
    rule_contexts = [empty_ctx_json if not e.rule_context else _json(e.rule_context) for e in unique_events]
    return pa.Table.from_arrays(
        [
            pa.array([e.event_id for e in unique_events], type=pa.string()),
            ts_array,
            pa.array([e.event_kind for e in unique_events], type=pa.string()),
            pa.array([e.category for e in unique_events], type=pa.string()),
            pa.array([e.action for e in unique_events], type=pa.string()),
            pa.array([e.severity for e in unique_events], type=pa.string()),
            pa.array([e.host for e in unique_events], type=pa.string()),
            pa.array([e.source_ip for e in unique_events], type=pa.string()),
            pa.array([e.destination_ip for e in unique_events], type=pa.string()),
            pa.array([e.user for e in unique_events], type=pa.string()),
            pa.array([e.process_name for e in unique_events], type=pa.string()),
            pa.array([e.process_id for e in unique_events], type=pa.string()),
            pa.array([e.parent_process for e in unique_events], type=pa.string()),
            pa.array([e.command_line for e in unique_events], type=pa.string()),
            pa.array([e.file_path for e in unique_events], type=pa.string()),
            pa.array([e.registry_path for e in unique_events], type=pa.string()),
            pa.array([e.domain for e in unique_events], type=pa.string()),
            pa.array([e.technique_id for e in unique_events], type=pa.string()),
            pa.array([e.technique_name for e in unique_events], type=pa.string()),
            pa.array([e.tactic for e in unique_events], type=pa.string()),
            pa.array(rule_contexts, type=pa.json_() if hasattr(pa, "json_") else pa.string()),
            pa.array(raw_events, type=pa.json_() if hasattr(pa, "json_") else pa.string()),
        ],
        schema=_EVENT_ARROW_SCHEMA,
    )


def _detections_to_arrow_table(detections: Sequence) -> pa.Table:
    if not detections:
        return pa.Table.from_batches([], schema=_DETECTION_ARROW_SCHEMA)
    return pa.Table.from_arrays(
        [
            pa.array([d.detection_id for d in detections], type=pa.string()),
            pa.array([d.event_id for d in detections], type=pa.string()),
            pa.array([d.rule_id for d in detections], type=pa.string()),
            pa.array([d.rule_name for d in detections], type=pa.string()),
            pa.array([d.severity for d in detections], type=pa.string()),
            pa.array([d.technique_id for d in detections], type=pa.string()),
            pa.array([d.technique_name for d in detections], type=pa.string()),
            pa.array([d.tactic for d in detections], type=pa.string()),
            pa.array([float(d.confidence) for d in detections], type=pa.float64()),
            pa.array([_json(d.evidence) for d in detections], type=pa.string()),
        ],
        schema=_DETECTION_ARROW_SCHEMA,
    )


class BulkWriter:
    """A long-lived DuckDB writer using bounded Arrow batches."""

    def __init__(self, storage: "Storage", *, staging: bool = False):
        self.connection = storage.connect()
        self.staging = staging
        self.events_table = "events_staging" if staging else "events"
        self.detections_table = "detections_staging" if staging else "detections"
        self.incidents_table = "incidents_staging" if staging else "incidents"
        self.memberships_table = "incident_events_staging" if staging else "incident_events"
        self._seen_staging_hashes: set[int] = set()
        if staging:
            try:
                cur = self.connection.cursor()
                rows = cur.execute(f"SELECT event_id FROM {self.events_table}").fetchall()
                cur.close()
                self._seen_staging_hashes = {hash(r[0]) for r in rows}
            except Exception:
                self._seen_staging_hashes = set()
        self._closed = False

    def close(self):
        if not self._closed:
            self.connection.close()
            self._closed = True

    def __enter__(self) -> "BulkWriter":
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _execute_batch(
        self,
        name: str,
        table: pa.Table,
        query: str,
        checkpoint: dict | None = None,
        duplicate_candidates: int = 0,
        duplicate_increment: int | None = None,
        fetch_results: bool = True,
    ) -> list[tuple]:
        self.connection.register(name, table)
        try:
            self.connection.execute("BEGIN TRANSACTION")
            cursor = self.connection.execute(query)
            result = cursor.fetchall() if fetch_results else []
            if checkpoint is not None:
                duplicates = duplicate_increment if duplicate_increment is not None else duplicate_candidates - len(result)
                checkpoint["duplicate_records"] = checkpoint.get("duplicate_records", 0) + max(0, duplicates)
                checkpoint["skipped_records"] = checkpoint.get("invalid_records", 0) + checkpoint["duplicate_records"]
                self._write_run(checkpoint)
            self.connection.execute("COMMIT")
            return result
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        finally:
            self.connection.unregister(name)

    def _write_run(self, payload: dict):
        self.connection.execute(
            "INSERT OR REPLACE INTO ingestion_runs VALUES (?,TRY_CAST(? AS JSON))",
            [payload["run_id"], _json(payload)],
        )

    def save_run(self, payload: dict):
        self.connection.execute("BEGIN TRANSACTION")
        try:
            self._write_run(payload)
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def insert_events(self, events: Sequence, *, checkpoint: dict | None = None) -> int:
        if not events:
            if checkpoint is not None:
                self.save_run(checkpoint)
            return 0
        # Collapse repeated IDs within this bounded batch before bulk writing.
        unique_events = list({event.event_id: event for event in events}.values())
        table = _events_to_arrow_table(unique_events)
        columns = "event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,rule_context,raw_event"
        selected = "event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,rule_context,raw_event"
        if self.staging:
            self._execute_batch(
                "_event_batch", table,
                f"INSERT INTO {self.events_table} ({columns}) SELECT {selected} FROM _event_batch",
                checkpoint=checkpoint,
                duplicate_increment=len(events) - len(unique_events),
                fetch_results=False,
            )
            return len(unique_events)
        inserted = self._execute_batch(
            "_event_batch", table,
            f"INSERT OR IGNORE INTO {self.events_table} ({columns}) SELECT {selected} FROM _event_batch RETURNING 1",
            checkpoint=checkpoint,
            duplicate_candidates=len(events),
        )
        return len(inserted)

    def insert_stream_events(self, events: Sequence, *, checkpoint: dict | None = None) -> list:
        """Deduplicate a streaming batch at write time and return only first-seen rows."""
        if not self.staging:
            raise ValueError("Streaming event insertion requires a staging writer")
        if not events:
            if checkpoint is not None:
                self.save_run(checkpoint)
            return []

        accepted_events = []
        batch_seen = set()
        seen_hashes = self._seen_staging_hashes
        for event in events:
            h = hash(event.event_id)
            if h not in seen_hashes and h not in batch_seen:
                batch_seen.add(h)
                accepted_events.append(event)

        seen_hashes.update(batch_seen)
        duplicates = len(events) - len(accepted_events)

        if accepted_events:
            table = _events_to_arrow_table(accepted_events)
            columns = "event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,rule_context,raw_event"
            self._execute_batch(
                "_stream_event_batch", table,
                f"INSERT INTO {self.events_table} ({columns}) SELECT {columns} FROM _stream_event_batch",
                checkpoint=checkpoint,
                duplicate_increment=duplicates,
                fetch_results=False,
            )
        elif checkpoint is not None:
            checkpoint["duplicate_records"] = checkpoint.get("duplicate_records", 0) + duplicates
            checkpoint["skipped_records"] = checkpoint.get("invalid_records", 0) + checkpoint["duplicate_records"]
            self.save_run(checkpoint)

        return accepted_events

    def clear_detections(self):
        if not self.staging:
            raise ValueError("Only staged detections can be cleared")
        self.connection.execute("DELETE FROM detections_staging")

    def save_detections(self, detections: Sequence) -> int:
        if not detections:
            return 0
        table = _detections_to_arrow_table(detections)
        query = (
            f"INSERT INTO {self.detections_table} SELECT detection_id,event_id,rule_id,rule_name,severity,technique_id,technique_name,tactic,confidence,TRY_CAST(evidence AS JSON) FROM _detection_batch"
            if self.staging
            else f"""INSERT OR REPLACE INTO {self.detections_table} SELECT detection_id,event_id,rule_id,rule_name,severity,
                technique_id,technique_name,tactic,confidence,TRY_CAST(evidence AS JSON)
                FROM _detection_batch"""
        )
        self._execute_batch(
            "_detection_batch", table,
            query,
            fetch_results=False,
        )
        return len(detections)

    def add_incident_events(self, members: Iterable[tuple[str, str]]) -> int:
        """Insert unique ``(incident_id, event_id)`` memberships as one batch."""
        rows = list(dict.fromkeys((incident_id, event_id) for incident_id, event_id in members if incident_id and event_id))
        if not rows:
            return 0
        table = pa.Table.from_arrays(
            [
                pa.array([row[0] for row in rows], type=pa.string()),
                pa.array([row[1] for row in rows], type=pa.string()),
            ],
            schema=_MEMBERSHIP_ARROW_SCHEMA,
        )
        result = self._execute_batch(
            "_membership_batch", table,
            f"""INSERT OR IGNORE INTO {self.memberships_table} SELECT incident_id,event_id
                FROM _membership_batch RETURNING 1""",
        )
        return len(result)

    def merge_incidents(self, merges: Iterable[tuple[str, str]]) -> int:
        rows = list(dict.fromkeys((source, target) for source, target in merges if source and target and source != target))
        if not rows:
            return 0
        table = pa.Table.from_pylist(
            [{"source_id": source, "target_id": target} for source, target in rows],
            schema=_MERGE_ARROW_SCHEMA,
        )
        name = "_incident_merge_batch"
        self.connection.register(name, table)
        try:
            self.connection.execute("BEGIN TRANSACTION")
            self.connection.execute(
                f"""INSERT OR IGNORE INTO {self.memberships_table}
                    SELECT m.target_id, e.event_id FROM {self.memberships_table} e
                    JOIN {name} m ON e.incident_id=m.source_id"""
            )
            self.connection.execute(
                f"DELETE FROM {self.memberships_table} WHERE incident_id IN (SELECT source_id FROM {name})"
            )
            self.connection.execute("COMMIT")
            return len(rows)
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        finally:
            self.connection.unregister(name)

    def incident_event_counts(self, incident_ids: Sequence[str] | None = None) -> dict[str, int]:
        counts = {}
        if incident_ids is None:
            cur = self.connection.cursor()
            rows = cur.execute(
                f"SELECT incident_id,COUNT(*) FROM {self.memberships_table} GROUP BY incident_id"
            ).fetchall()
            cur.close()
            return {incident_id: count for incident_id, count in rows}
        ids = list(dict.fromkeys(incident_ids))
        if len(ids) > 100:
            cur = self.connection.cursor()
            rows = cur.execute(
                f"SELECT incident_id,COUNT(*) FROM {self.memberships_table} GROUP BY incident_id"
            ).fetchall()
            cur.close()
            id_set = set(ids)
            return {incident_id: count for incident_id, count in rows if incident_id in id_set}
        for start in range(0, len(ids), 500):
            batch = ids[start:start + 500]
            placeholders = ",".join("?" for _ in batch)
            cur = self.connection.cursor()
            rows = cur.execute(
                f"SELECT incident_id,COUNT(*) FROM {self.memberships_table} WHERE incident_id IN ({placeholders}) GROUP BY incident_id",
                batch,
            ).fetchall()
            cur.close()
            counts.update({incident_id: count for incident_id, count in rows})
        return counts

    def save_incidents(self, incidents: Sequence) -> int:
        if not incidents:
            return 0
        table = pa.Table.from_pylist([
            {"incident_id": item.incident_id, "payload": _json(item.model_dump(mode="json"))}
            for item in incidents
        ], schema=_INCIDENT_ARROW_SCHEMA)
        result = self._execute_batch(
            "_incident_batch", table,
            f"INSERT OR REPLACE INTO {self.incidents_table} SELECT incident_id,TRY_CAST(payload AS JSON) FROM _incident_batch RETURNING incident_id",
        )
        return len(result)


class Storage:
    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self, read_only: bool = False):
        db = duckdb.connect(str(self.path), read_only=read_only)
        temp_dir = DUCKDB_TEMP_DIR.as_posix().replace("'", "''")
        if not read_only:
            db.execute(f"SET memory_limit = '{DUCKDB_MEMORY_LIMIT}'")
            db.execute(f"SET threads = {DUCKDB_THREADS}")
            db.execute(f"SET temp_directory = '{temp_dir}'")
        db.execute("SET TimeZone = 'UTC'")
        return db

    def db_size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def memory_usage_bytes(self) -> int:
        try:
            with self.connect(read_only=True) as db:
                row = db.execute("SELECT sum(memory_usage_bytes) FROM duckdb_memory()").fetchone()
                return int(row[0] or 0)
        except Exception:
            return 0

    def writer(self, *, staging: bool = False) -> BulkWriter:
        return BulkWriter(self, staging=staging)

    def initialize(self):
        try:
            with self.connect() as db:
                db.execute("CREATE TABLE IF NOT EXISTS events (event_id VARCHAR PRIMARY KEY, timestamp TIMESTAMP, event_kind VARCHAR, category VARCHAR, action VARCHAR, severity VARCHAR, host VARCHAR, source_ip VARCHAR, destination_ip VARCHAR, user_name VARCHAR, process_name VARCHAR, process_id VARCHAR, parent_process VARCHAR, command_line VARCHAR, file_path VARCHAR, registry_path VARCHAR, domain VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, rule_context JSON, raw_event JSON)")
                db.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS rule_context JSON")
                db.execute("CREATE TABLE IF NOT EXISTS detections (detection_id VARCHAR PRIMARY KEY, event_id VARCHAR, rule_id VARCHAR, rule_name VARCHAR, severity VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, confidence DOUBLE, evidence JSON)")
                db.execute("CREATE TABLE IF NOT EXISTS incidents (incident_id VARCHAR PRIMARY KEY, payload JSON)")
                db.execute("CREATE TABLE IF NOT EXISTS incident_events (incident_id VARCHAR, event_id VARCHAR, PRIMARY KEY (incident_id, event_id))")
                db.execute("CREATE TABLE IF NOT EXISTS ingestion_runs (run_id VARCHAR PRIMARY KEY, payload JSON)")
                db.execute("CREATE TABLE IF NOT EXISTS ingestion_state (key VARCHAR PRIMARY KEY, value VARCHAR)")
                db.execute("CREATE TABLE IF NOT EXISTS ingestion_history (history_id VARCHAR PRIMARY KEY, format VARCHAR, file_size_tier VARCHAR, file_size_bytes BIGINT, record_count BIGINT, optimal_batch_size INTEGER, avg_throughput_eps DOUBLE, avg_throughput_mb_s DOUBLE, peak_memory_bytes BIGINT, parse_time_seconds DOUBLE, write_time_seconds DOUBLE, detect_time_seconds DOUBLE, bottleneck VARCHAR, created_at TIMESTAMP)")
        except duckdb.IOException as exc:
            if "used by another process" in str(exc).lower() or "cannot open file" in str(exc).lower():
                return
            raise

    def create_staging(self, run_id: str, *, resume: bool = False):
        """Prepare isolated tables so a failed job never replaces the last good dataset."""
        with self.connect() as db:
            if not resume:
                db.execute("DROP TABLE IF EXISTS events_staging")
                db.execute("DROP TABLE IF EXISTS detections_staging")
                db.execute("DROP TABLE IF EXISTS incidents_staging")
                db.execute("DROP TABLE IF EXISTS incident_events_staging")
            db.execute("CREATE TABLE IF NOT EXISTS events_staging (event_id VARCHAR, timestamp TIMESTAMP, event_kind VARCHAR, category VARCHAR, action VARCHAR, severity VARCHAR, host VARCHAR, source_ip VARCHAR, destination_ip VARCHAR, user_name VARCHAR, process_name VARCHAR, process_id VARCHAR, parent_process VARCHAR, command_line VARCHAR, file_path VARCHAR, registry_path VARCHAR, domain VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, rule_context JSON, raw_event JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS detections_staging (detection_id VARCHAR, event_id VARCHAR, rule_id VARCHAR, rule_name VARCHAR, severity VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, confidence DOUBLE, evidence JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS incidents_staging (incident_id VARCHAR PRIMARY KEY, payload JSON)")
            db.execute("CREATE TABLE IF NOT EXISTS incident_events_staging (incident_id VARCHAR, event_id VARCHAR, PRIMARY KEY (incident_id, event_id))")
            db.execute("INSERT OR REPLACE INTO ingestion_state VALUES ('staging_run_id',?)", [run_id])

    def create_streaming_staging(self, run_id: str):
        """Create fresh staging tables with exact event-ID deduplication on insert."""
        with self.connect() as db:
            for table in ("events_staging", "detections_staging", "incidents_staging", "incident_events_staging"):
                db.execute(f"DROP TABLE IF EXISTS {table}")
            db.execute("CREATE TABLE events_staging (event_id VARCHAR, timestamp TIMESTAMP, event_kind VARCHAR, category VARCHAR, action VARCHAR, severity VARCHAR, host VARCHAR, source_ip VARCHAR, destination_ip VARCHAR, user_name VARCHAR, process_name VARCHAR, process_id VARCHAR, parent_process VARCHAR, command_line VARCHAR, file_path VARCHAR, registry_path VARCHAR, domain VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, rule_context JSON, raw_event JSON)")
            db.execute("CREATE TABLE detections_staging (detection_id VARCHAR, event_id VARCHAR, rule_id VARCHAR, rule_name VARCHAR, severity VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, confidence DOUBLE, evidence JSON)")
            db.execute("CREATE TABLE incidents_staging (incident_id VARCHAR PRIMARY KEY, payload JSON)")
            db.execute("CREATE TABLE incident_events_staging (incident_id VARCHAR, event_id VARCHAR, PRIMARY KEY (incident_id, event_id))")
            db.execute("INSERT OR REPLACE INTO ingestion_state VALUES ('staging_run_id',?)", [run_id])

    def has_staging(self, run_id: str | None = None) -> bool:
        expected = {"events_staging", "detections_staging", "incidents_staging", "incident_events_staging"}
        with self.connect() as db:
            names = {row[0] for row in db.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='main'").fetchall()}
            row = db.execute("SELECT value FROM ingestion_state WHERE key='staging_run_id'").fetchone()
        return expected.issubset(names) and row is not None and (run_id is None or row[0] == run_id)

    def clear_staging_analysis(self):
        with self.connect() as db:
            db.execute("DELETE FROM detections_staging")
            db.execute("DELETE FROM incidents_staging")
            db.execute("DELETE FROM incident_events_staging")

    def finalize_staging_events(self, run: dict) -> int:
        """Count cross-batch duplicates once and rewrite only when duplicates exist."""
        with self.connect() as db:
            db.execute("BEGIN TRANSACTION")
            try:
                if run.get("cross_batch_duplicates_counted"):
                    db.execute("COMMIT")
                    return 0
                if run.get("deduplicated_during_ingestion"):
                    run["cross_batch_duplicates_counted"] = True
                    run["analysis_total"] = max(0, run.get("valid_records", 0) - run.get("duplicate_records", 0))
                    run["updated_at"] = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        "INSERT OR REPLACE INTO ingestion_runs VALUES (?,TRY_CAST(? AS JSON))",
                        [run["run_id"], _json(run)],
                    )
                    db.execute("COMMIT")
                    return 0
                total, unique = db.execute(
                    "SELECT COUNT(*),COUNT(DISTINCT event_id) FROM events_staging"
                ).fetchone()
                duplicates = total - unique
                if duplicates:
                    db.execute("DROP TABLE IF EXISTS events_staging_dedup")
                    db.execute("""
                        CREATE TABLE events_staging_dedup AS
                        SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,
                            user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,
                            domain,technique_id,technique_name,tactic,rule_context,raw_event
                        FROM (
                            SELECT ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY rowid) AS duplicate_rank, *
                            FROM events_staging
                        ) WHERE duplicate_rank=1
                    """)
                    db.execute("DROP TABLE events_staging")
                    db.execute("ALTER TABLE events_staging_dedup RENAME TO events_staging")
                if duplicates:
                    run["duplicate_records"] = run.get("duplicate_records", 0) + duplicates
                run["skipped_records"] = run.get("invalid_records", 0) + run["duplicate_records"]
                run["cross_batch_duplicates_counted"] = True
                run["analysis_total"] = max(0, run.get("valid_records", 0) - run["duplicate_records"])
                run["updated_at"] = datetime.now(timezone.utc).isoformat()
                db.execute(
                    "INSERT OR REPLACE INTO ingestion_runs VALUES (?,TRY_CAST(? AS JSON))",
                    [run["run_id"], _json(run)],
                )
                db.execute("COMMIT")
                return duplicates
            except Exception:
                db.execute("ROLLBACK")
                raise

    @staticmethod
    def _decode_json(value):
        return orjson.loads(value) if isinstance(value, str) else value

    def get_run(self, run_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM ingestion_runs WHERE run_id=?", [run_id]).fetchone()
        return self._decode_json(row[0]) if row else None

    def latest_run(self) -> dict | None:
        try:
            with self.connect() as db:
                rows = db.execute("SELECT payload FROM ingestion_runs").fetchall()
            runs = [self._decode_json(row[0]) for row in rows]
            runs = [run for run in runs if run]
            return max(runs, key=lambda run: run.get("updated_at", ""), default=None)
        except duckdb.IOException as exc:
            if "used by another process" in str(exc).lower() or "cannot open file" in str(exc).lower():
                return None
            raise

    def find_resumable_run(self, source_signature: str) -> dict | None:
        resumable = {"processing", "interrupted", "failed"}
        try:
            with self.connect() as db:
                rows = db.execute("SELECT payload FROM ingestion_runs").fetchall()
            for (payload,) in rows:
                run = self._decode_json(payload)
                if run and run.get("source_signature") == source_signature and run.get("state") in resumable:
                    return run
            return None
        except duckdb.IOException as exc:
            if "used by another process" in str(exc).lower() or "cannot open file" in str(exc).lower():
                return None
            raise

    def save_run(self, payload: dict):
        with self.writer() as writer:
            writer.save_run(payload)

    def record_ingestion_history(self, history_entry: dict):
        """Record completed ingestion profile metrics to inform subsequent runs."""
        history_id = history_entry.get("history_id") or str(uuid4())
        created_at = datetime.now(timezone.utc)
        try:
            with self.connect() as db:
                db.execute(
                    """INSERT OR REPLACE INTO ingestion_history (
                        history_id, format, file_size_tier, file_size_bytes, record_count,
                        optimal_batch_size, avg_throughput_eps, avg_throughput_mb_s,
                        peak_memory_bytes, parse_time_seconds, write_time_seconds,
                        detect_time_seconds, bottleneck, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [
                        history_id,
                        history_entry.get("format", "jsonl"),
                        history_entry.get("file_size_tier", "small"),
                        int(history_entry.get("file_size_bytes", 0)),
                        int(history_entry.get("record_count", 0)),
                        int(history_entry.get("optimal_batch_size", 10000)),
                        float(history_entry.get("avg_throughput_eps", 0.0)),
                        float(history_entry.get("avg_throughput_mb_s", 0.0)),
                        int(history_entry.get("peak_memory_bytes", 0)),
                        float(history_entry.get("parse_time_seconds", 0.0)),
                        float(history_entry.get("write_time_seconds", 0.0)),
                        float(history_entry.get("detect_time_seconds", 0.0)),
                        history_entry.get("bottleneck", "Balanced"),
                        created_at,
                    ]
                )
        except Exception:
            logger.exception("Could not record ingestion history")

    def lookup_historical_optimal(self, file_format: str, file_size_tier: str) -> dict | None:
        """Find the median optimal batch size and performance from past runs for similar input."""
        try:
            with self.connect(read_only=True) as db:
                rows = db.execute(
                    """SELECT optimal_batch_size, avg_throughput_eps, avg_throughput_mb_s, bottleneck
                       FROM ingestion_history
                       WHERE format = ? AND file_size_tier = ?
                       ORDER BY created_at DESC LIMIT 5""",
                    [file_format.lower(), file_size_tier.lower()]
                ).fetchall()
                if not rows:
                    return None
                batches = sorted(row[0] for row in rows)
                median_batch = batches[len(batches) // 2]
                avg_eps = sum(row[1] for row in rows) / len(rows)
                avg_mb_s = sum(row[2] for row in rows) / len(rows)
                last_bottleneck = rows[0][3]
                return {
                    "optimal_batch_size": median_batch,
                    "avg_throughput_eps": round(avg_eps, 1),
                    "avg_throughput_mb_s": round(avg_mb_s, 2),
                    "bottleneck": last_bottleneck,
                }
        except Exception:
            return None

    def get_ingestion_history(self, limit: int = 20) -> list[dict]:
        try:
            with self.connect(read_only=True) as db:
                rows = db.execute(
                    """SELECT history_id, format, file_size_tier, file_size_bytes, record_count,
                              optimal_batch_size, avg_throughput_eps, avg_throughput_mb_s,
                              peak_memory_bytes, parse_time_seconds, write_time_seconds,
                              detect_time_seconds, bottleneck, created_at
                       FROM ingestion_history
                       ORDER BY created_at DESC LIMIT ?""",
                    [limit]
                ).fetchall()
                cols = [
                    "history_id", "format", "file_size_tier", "file_size_bytes", "record_count",
                    "optimal_batch_size", "avg_throughput_eps", "avg_throughput_mb_s",
                    "peak_memory_bytes", "parse_time_seconds", "write_time_seconds",
                    "detect_time_seconds", "bottleneck", "created_at"
                ]
                return [dict(zip(cols, row)) for row in rows]
        except Exception:
            return []

    def mark_interrupted_runs(self):
        try:
            with self.connect() as db:
                rows = db.execute("SELECT run_id,payload FROM ingestion_runs").fetchall()
                for run_id, raw in rows:
                    payload = self._decode_json(raw)
                    if payload and payload.get("state") in {"processing", "queued"}:
                        payload["state"] = "interrupted"
                        payload["message"] = "Backend restarted; submit the same source again to resume from the last checkpoint."
                        db.execute("UPDATE ingestion_runs SET payload=TRY_CAST(? AS JSON) WHERE run_id=?", [_json(payload), run_id])
        except duckdb.IOException as exc:
            if "used by another process" in str(exc).lower() or "cannot open file" in str(exc).lower():
                return
            raise

    def publish_staging(self, payload: dict):
        """Atomically publish the completed dataset and its analysis tables."""
        tables = [
            ("events", "events_staging"),
            ("detections", "detections_staging"),
            ("incidents", "incidents_staging"),
            ("incident_events", "incident_events_staging"),
        ]
        with self.connect() as db:
            db.execute("BEGIN TRANSACTION")
            try:
                for target, staged in tables:
                    previous = f"{target}_previous"
                    db.execute(f"DROP TABLE IF EXISTS {previous}")
                    db.execute(f"ALTER TABLE {target} RENAME TO {previous}")
                    db.execute(f"ALTER TABLE {staged} RENAME TO {target}")
                    db.execute(f"DROP TABLE {previous}")
                db.execute(
                    "INSERT OR REPLACE INTO ingestion_runs VALUES (?,TRY_CAST(? AS JSON))",
                    [payload["run_id"], _json(payload)],
                )
                db.execute("DELETE FROM ingestion_state WHERE key='staging_run_id'")
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def reset_analysis(self):
        with self.connect() as db:
            db.execute("DELETE FROM detections")
            db.execute("DELETE FROM incidents")
            db.execute("DELETE FROM incident_events")

    def clear_all(self):
        """Clear investigation data and saved progress so a fresh run starts idle."""
        with self.connect() as db:
            db.execute("BEGIN TRANSACTION")
            try:
                for table in (
                    "incident_events",
                    "incidents",
                    "detections",
                    "events",
                    "ingestion_runs",
                    "ingestion_state",
                    "incident_events_staging",
                    "incidents_staging",
                    "detections_staging",
                    "events_staging_dedup",
                    "events_staging",
                ):
                    db.execute(f"DROP TABLE IF EXISTS {table}")
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        self.initialize()

    def insert_events(self, events):
        with self.writer() as writer:
            return writer.insert_events(events)

    @staticmethod
    def _event_from_row(row):
        from backend.models import NormalizedEvent
        values = list(row[:9]) + [row[9]] + list(row[10:20]) + [orjson.loads(row[20]) if isinstance(row[20], str) else row[20]]
        return NormalizedEvent(**dict(zip(EVENT_COLUMNS, values)))

    @staticmethod
    def _detection_event_from_row(row):
        from backend.models import NormalizedEventRecord
        values = list(row[:9]) + [row[9]] + list(row[10:20])
        data = dict(zip(EVENT_COLUMNS[:20], values))
        data["raw_event"] = {}
        data["rule_context"] = Storage._decode_json(row[20]) or {}
        return NormalizedEventRecord(**data)

    def iter_events(self, batch_size=10_000, where="", args=(), *, table="events", source_ordered=False, for_detection=False):
        if table not in {"events", "events_staging"}:
            raise ValueError("Unsupported event table")
        order_clause = " ORDER BY rowid" if source_ordered else " ORDER BY timestamp,event_id"
        raw_column = "rule_context" if for_detection else "raw_event"
        with self.connect() as db:
            cursor = db.execute(
                "SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic," + raw_column + " FROM " + table + " "
                + where + order_clause,
                args,
            )
            while rows := cursor.fetchmany(batch_size):
                converter = self._detection_event_from_row if for_detection else self._event_from_row
                yield [converter(row) for row in rows]

    def events(self, where="", args=(), limit: int | None = 10_000):
        """Materialize events only for explicitly small callers; production APIs page."""
        values = []
        for batch in self.iter_events(where=where, args=args):
            values.extend(batch)
            if limit is not None and len(values) >= limit:
                return values[:limit]
        return values

    def event_page(self, limit=200, offset=0, severity=None):
        clause = " WHERE severity = ?" if severity else ""
        args = [severity] if severity else []
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM events" + clause, args).fetchone()[0]
            rows = db.execute(
                "SELECT event_id,timestamp,event_kind,category,action,severity,host,source_ip,destination_ip,user_name,process_name,process_id,parent_process,command_line,file_path,registry_path,domain,technique_id,technique_name,tactic,raw_event FROM events"
                + clause + " ORDER BY timestamp,event_id LIMIT ? OFFSET ?",
                args + [limit, offset],
            ).fetchall()
        return total, [self._event_from_row(row) for row in rows]

    def save_detections(self, detections):
        with self.writer() as writer:
            return writer.save_detections(detections)

    def detections(self):
        from backend.models import Detection
        with self.connect() as db:
            rows = db.execute("SELECT * FROM detections").fetchall()
        return [Detection(detection_id=r[0], event_id=r[1], rule_id=r[2], rule_name=r[3], severity=r[4], technique_id=r[5], technique_name=r[6], tactic=r[7], confidence=r[8], evidence=orjson.loads(r[9]) if isinstance(r[9], str) else r[9]) for r in rows]

    def iter_detection_events(self, batch_size=10_000, *, staging=False, source_ordered=False):
        from backend.models import Detection
        detection_table, event_table = ("detections_staging", "events_staging") if staging else ("detections", "events")
        order_clause = "e.rowid,d.detection_id" if source_ordered else "e.timestamp,e.event_id,d.detection_id"
        query = f"SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,d.evidence,e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.rule_context FROM {detection_table} d JOIN {event_table} e ON e.event_id=d.event_id ORDER BY {order_clause}"
        with self.connect() as db:
            cursor = db.execute(query)
            while rows := cursor.fetchmany(batch_size):
                batch = []
                for row in rows:
                    detection = Detection(detection_id=row[0], event_id=row[1], rule_id=row[2], rule_name=row[3], severity=row[4], technique_id=row[5], technique_name=row[6], tactic=row[7], confidence=row[8], evidence=orjson.loads(row[9]) if isinstance(row[9], str) else row[9])
                    batch.append((detection, self._detection_event_from_row(row[10:])))
                yield batch

    def add_incident_events(self, members: Iterable[tuple[str, str]]) -> int:
        """Batch-insert incident evidence using a bounded DuckDB writer transaction."""
        with self.writer() as writer:
            return writer.add_incident_events(members)

    def add_incident_event(self, incident_id: str, event_id: str) -> int:
        """Insert one incident/evidence relationship idempotently."""
        return self.add_incident_events([(incident_id, event_id)])

    def merge_incidents(self, source_id, target_id):
        with self.connect() as db:
            db.execute("UPDATE incident_events SET incident_id=? WHERE incident_id=?", [target_id, source_id])

    def save_incidents(self, incidents):
        with self.writer() as writer:
            return writer.save_incidents(incidents)

    @staticmethod
    def _hydrate_incident(data: dict):
        from backend.models import Incident
        from backend.risk.scoring import classify_attack_behavior
        inc = Incident(**data)
        if (not inc.attack_type or inc.attack_type == "Suspicious Security Anomaly") and inc.techniques:
            inc.attack_type, inc.behavior_summary = classify_attack_behavior(inc.techniques, reasons=inc.correlation_reasons)
        return inc

    def incidents(self):
        with self.connect() as db:
            rows = db.execute("SELECT payload FROM incidents").fetchall()
        return [self._hydrate_incident(orjson.loads(r[0]) if isinstance(r[0], str) else r[0]) for r in rows]

    def incident(self, incident_id: str):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM incidents WHERE incident_id=?", [incident_id]).fetchone()
        return self._hydrate_incident(self._decode_json(row[0])) if row else None

    def incident_overview(self, recent_limit: int = 8):
        with self.connect() as db:
            total, critical = db.execute(
                "SELECT COUNT(*),COUNT(*) FILTER (WHERE json_extract_string(payload,'$.risk_label')='Critical') FROM incidents"
            ).fetchone()
            rows = db.execute(
                "SELECT payload FROM incidents ORDER BY TRY_CAST(json_extract_string(payload,'$.last_observed') AS TIMESTAMP) DESC LIMIT ?",
                [recent_limit],
            ).fetchall()
        recent = [self._hydrate_incident(self._decode_json(row[0])) for row in rows]
        return {"total": total, "critical": critical, "recent": recent}

    def events_for_incident(self, incident_id, limit=1_000):
        query = "SELECT e.event_id,e.timestamp,e.event_kind,e.category,e.action,e.severity,e.host,e.source_ip,e.destination_ip,e.user_name,e.process_name,e.process_id,e.parent_process,e.command_line,e.file_path,e.registry_path,e.domain,e.technique_id,e.technique_name,e.tactic,e.raw_event FROM events e JOIN incident_events ie ON ie.event_id=e.event_id WHERE ie.incident_id=? ORDER BY e.timestamp,e.event_id LIMIT ?"
        with self.connect() as db:
            rows = db.execute(query, [incident_id, limit]).fetchall()
        return [self._event_from_row(row) for row in rows]

    def detections_for_incident(self, incident_id, limit=2_000):
        from backend.models import Detection
        query = "SELECT d.detection_id,d.event_id,d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,d.confidence,d.evidence FROM detections d JOIN incident_events ie ON ie.event_id=d.event_id WHERE ie.incident_id=? ORDER BY d.detection_id LIMIT ?"
        with self.connect() as db:
            rows = db.execute(query, [incident_id, limit]).fetchall()
        return [Detection(detection_id=row[0], event_id=row[1], rule_id=row[2], rule_name=row[3], severity=row[4], technique_id=row[5], technique_name=row[6], tactic=row[7], confidence=row[8], evidence=orjson.loads(row[9]) if isinstance(row[9], str) else row[9]) for row in rows]

    def detection_summary_for_incident(self, incident_id: str) -> list[dict]:
        """Return exact detection counts grouped by rule and ATT&CK mapping."""
        query = """
            SELECT d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic,COUNT(*) AS count
            FROM detections d
            JOIN incident_events ie ON ie.event_id=d.event_id
            WHERE ie.incident_id=?
            GROUP BY d.rule_id,d.rule_name,d.severity,d.technique_id,d.technique_name,d.tactic
            ORDER BY CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
                     count DESC,d.rule_id
        """
        with self.connect() as db:
            rows = db.execute(query, [incident_id]).fetchall()
        return [{
            "rule_id": row[0],
            "rule_name": row[1],
            "severity": row[2],
            "technique_id": row[3],
            "technique_name": row[4],
            "tactic": row[5],
            "count": row[6],
        } for row in rows]

    def dashboard_counts(self):
        with self.connect() as db:
            events = db.execute("SELECT COUNT(*),COUNT(DISTINCT host) FROM events").fetchone()
            suspicious = db.execute("SELECT COUNT(DISTINCT event_id) FROM detections").fetchone()[0]
            detections = db.execute("SELECT severity,COUNT(*) FROM detections GROUP BY severity").fetchall()
        return {
            "total_events": events[0],
            "hosts_involved": events[1],
            "suspicious_events": suspicious,
            "severity_counts": {row[0]: row[1] for row in detections},
        }

    def mitre_summary(self):
        query = "SELECT technique_id,technique_name,tactic,COUNT(*) FROM detections GROUP BY technique_id,technique_name,tactic ORDER BY technique_id"
        with self.connect() as db:
            rows = db.execute(query).fetchall()
            evidence_rows = db.execute(
                "SELECT technique_id,evidence FROM detections QUALIFY ROW_NUMBER() OVER (PARTITION BY technique_id ORDER BY detection_id)<=3"
            ).fetchall()
            incident_rows = db.execute(
                "SELECT d.technique_id,COUNT(DISTINCT ie.incident_id) FROM detections d JOIN incident_events ie ON ie.event_id=d.event_id GROUP BY d.technique_id"
            ).fetchall()
        evidence_by_technique = {}
        for technique_id, evidence in evidence_rows:
            evidence_by_technique.setdefault(technique_id, []).append(self._decode_json(evidence))
        incident_counts = dict(incident_rows)
        result = [{
            "technique_id": technique_id,
            "technique_name": name,
            "tactic": tactic,
            "frequency": frequency,
            "incident_count": incident_counts.get(technique_id, 0),
            "evidence": evidence_by_technique.get(technique_id, []),
        } for technique_id, name, tactic, frequency in rows]
        return result
