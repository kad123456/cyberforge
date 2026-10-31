# ChainSight AI architecture

ChainSight is a local-first modular monolith. FastAPI accepts file paths or uploaded files, `IngestionService` coordinates parsing and analysis, DuckDB is the disk-backed storage adapter, and the React/Vite dashboard reads the existing API. The backend does not connect to a broker, external log service, or the organizer IP.

## Large-file ingestion

The file reader uses a bounded binary buffer and decodes one physical record at a time. CSV/TSV use Python's streaming CSV reader, which can handle quoted fields spanning lines. The current formats are JSONL, CEF, FortiGate key/value, CSV and TSV. CSV maps common security field names and preserves every source column; organizer-specific aliases need a verified parser mapping.

Parsing builds lightweight internal records in bounded batches. DuckDB settings cap its memory use and direct spill files to the configured temporary directory. Normalized events are written to isolated staging tables with Arrow batches. The previous published dataset remains available during the job. At completion, the event, detection, incident and membership tables are swapped in one database transaction.

Each committed ingestion batch stores its byte offset, physical line number and counters in `ingestion_runs` in the same transaction as its events. On restart, the same path, file size and modification timestamp can resume from the last checkpoint. If analysis was interrupted, it is rerun from staged events. A changed source gets a new run. Duplicate IDs within batches are removed before writing; cross-batch duplicate IDs are counted and removed using a DuckDB disk-backed query before detection.

The service detects whether timestamps are ordered while reading. Ordered inputs use DuckDB's insertion-order scan and avoid a full-table sort. Unordered inputs are sorted by event time in DuckDB; the configured memory limit and spill directory constrain that work. Detection reads a compact rule context instead of reparsing every full raw event. Original raw JSON remains stored for evidence and API responses.

Long jobs run in a single bounded worker and expose progress at `POST /api/ingest/jobs` and `GET /api/ingest/jobs/{job_id}`. The existing synchronous `/api/ingest/process` endpoint remains for the dashboard. Only one job can run at once, avoiding concurrent dataset replacement and unbounded background queues.

## Detection and correlation

`DetectionEngine` validates JSON-configured rules on startup and compiles them by event category. Authentication state holds at most five recent failure IDs per host/account and expires inactive keys through a time-ordered queue. A successful login following five failures in a 15-minute window produces a separate detection.

`StreamingCorrelator` links detections only when they share evidence-bearing entities inside the configured time window. Incident entity state expires as the time window advances; finalized summaries are persisted incrementally. When a new event connects two active incidents, their state and stored event membership are merged. Incident-specific timeline and graph routes load bounded event pages rather than building a graph for every raw record.

NetworkX creates an entity relationship only when both values appear in the same evidence event. Reachability follows observed host/source-IP and source/destination-IP links as defensive leads. It does not scan, probe, or assert compromise.

## Extension points

The parser, storage and job coordinator are separated so alternate adapters can be added without changing the React dashboard. Spark, Kafka, Flink, object storage, Iceberg, ClickHouse and Neo4j remain future adapters; they are not implemented or required for the single-machine backend.

When the organizer sample arrives, run `inspect_data.py`, verify the format and fields, add tests for its schema, and benchmark against its ground truth. Do not infer an organizer schema from synthetic data.
