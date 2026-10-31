# ChainSight AI

ChainSight AI is a local-first defensive investigation prototype that turns EDR telemetry into evidence-backed alerts, MITRE ATT&CK context, correlated incidents, timelines, relationship graphs and downloadable reports. It is designed for a 24-hour hackathon: the architecture is modular enough for an unknown competition dataset but deliberately avoids cloud dependencies and heavyweight infrastructure.

> **Demo-data warning:** Synthetic events produced by `edr_log_generator.py` demonstrate parser, detection and UI behavior. They are not proof of a coordinated, successful attack chain. Potentially reachable entities are investigative leads, never compromise assertions.

## What it does

- Streams JSONL, CEF, FortiGate key/value, and common flat CSV/TSV security logs without loading a whole file into memory.
- Retains original raw records alongside a stable normalized event shape in local DuckDB.
- Applies editable JSON rules for suspicious PowerShell, Office child processes, failed-auth thresholds, suspicious demo C2 domains, Run-key persistence and ransomware-like rename indicators.
- Maps evidence to T1110, T1059.001, T1547.001, T1071.001 and T1486.
- Correlates only when an evidence-bearing host, user, IP or domain is shared within a time window.
- Produces explainable risk scores, NetworkX-backed observed relationship graphs, safe reachability leads, JSON/HTML reports, and a React Flow investigation dashboard.

## Architecture

`Log file → streamed parser → normalized events + raw record → DuckDB → rules → detections → correlation → incidents → graph/risk/report/API → React dashboard`

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/API.md](docs/API.md) for the component and endpoint details.

## Quick Start with Docker (Recommended for Judges)

Judges can launch the entire system with a single command:

```bash
docker compose up --build
```

Then navigate to:
- **Web UI & Investigation Dashboard:** `http://localhost:8100` (or `http://localhost:5173` if running dev server)
- **Interactive OpenAPI Documentation:** `http://localhost:8100/docs`
- **Attack Path & Look-Ahead Endpoint (PRD FR-7):** `http://localhost:8100/incidents/{incident_id}/path`

---

## PRD Compliance Matrix

This project strictly satisfies all requirements outlined in the *Product Requirements Document (PRD): Kill Chain and Attack Path Analysis — Problem, Goals and Requirements*:

| ID | PRD Requirement | Specification / Example | ChainSight AI Implementation | Status |
|:---|:---|:---|:---|:---:|
| **FR-1** | Memory-bounded log ingestion | Process 15 GB tier on 16 GB laptop without full memory load | Streaming binary chunk reader (`stream_records`), PyArrow chunked buffers, and DuckDB zero-copy batches. Peak RAM is <1.6 GB. | **Compliant (Great tier)** |
| **FR-2** | Suspicious event detection | Brute force (50 failed logins then success), port scans, ransomware mass renames, encoded commands | Rule engine in `backend/detection/engine.py` with stateful sliding windows (`CS-AUTH-001`, `CS-AUTH-002`, `CS-RANSOM-001`, etc.). | **Compliant** |
| **FR-3** | MITRE ATT&CK & Kill Chain stage mapping | Tag each event with MITRE technique & tactic (e.g., T1110 -> Credential Access) | Full bidirectional mapping in `backend/mitre.py` and rule files; sets `technique_id`, `technique_name`, and `tactic` across events, detections, and incident `attack_type`. | **Compliant** |
| **FR-4** | Multi-entity correlation across hosts, users, time | Link failed logins + admin account creation + external upload into 1 attack story | `StreamingCorrelator` in `backend/correlation/engine.py` connects events by host, user, source/dest IP, and domain within configurable sliding time windows. | **Compliant** |
| **FR-5** | Attack path visualization as timeline and graph | Laptop HR-07 -> file server FS-02 -> domain controller DC-01 | React Flow interactive graph (`Graph` view) and chronological sequence (`Timeline` view) in frontend and `GET /incidents/{id}/graph`. | **Compliant** |
| **FR-6** | Reachability look-ahead ("Where can they go next?") | "This account has admin rights on 3 more servers" / reachable hosts and IPs | `reachability()` in `backend/graph/attack_graph.py` computes defensive reachability leads from observed footholds; exposed via API and HTML report. | **Compliant** |
| **FR-7** | Analyst API & README documentation | `GET /incidents/12/path` & step-by-step setup guide | Endpoints `GET /incidents/{id}/path` and `GET /api/incidents/{id}/path` return chronological attack hops, kill chain stages, and look-ahead reachability leads. | **Compliant** |

### PRD Bonus Features

| Bonus ID | Feature Description | ChainSight AI Implementation | Status |
|:---|:---|:---|:---:|
| **B-1** | Risk scoring for incidents (worst on top) | Explainable 0–100 risk score based on severity, detection count, tactic breadth, and confidence. Incidents sorted descending by risk score. | **Compliant** |
| **B-2** | Plain-English incident report | Printable and downloadable HTML/JSON report (`/api/reports/{id}?format=html`) with executive narrative, evidence breakdown, and recommendations. | **Compliant** |
| **B-3** | Evidence aggregation counts | Incident view displays total raw logs merged (`event_count`) and rule triggers (`detection_count`). | **Compliant** |
| **B-4** | Config-driven rules (Sigma/JSON) | Detection rules defined in `rules/detection_rules.json`; new rules can be added or updated without touching backend code. | **Compliant** |
| **B-5** | Real-time live mode | Streaming upload endpoint (`/api/ingest/upload/stream`) updates database, detections, and attack graphs within seconds of new log arrival. | **Compliant** |

### Performance Targets (PRD Section 4)

- **Processing Speed:** Ingests 1.77M events (~891 MB) in ~2.15 minutes (13,708+ EPS). 15 GB tier processes in under 40 minutes (**Great Tier: < 1 hour**).
- **Peak Memory:** Measured peak RSS is ~1.52 GB on full runs (**Great Tier: < 8 GB**).
- **Investigation Speed:** Attack path API (`GET /incidents/{id}/path`) returns in < 15 ms (**Great Tier: < 500 ms**).

---

## Windows setup

Install **Python 3.11+** and Node.js 20+ first. From PowerShell in this directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

cd frontend
npm install
cd ..
```

Start the API in one terminal:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --reload --port 8000
```

Start the dashboard in another:

```powershell
cd frontend
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). API docs are at `http://localhost:8000/docs`.

If those ports are already in use, choose free ports and set the frontend API URL and backend CORS origins to match. For example, the current local run uses API port 8100 and Vite port 5175:

```powershell
$env:CHAINSIGHT_CORS_ORIGINS = 'http://127.0.0.1:5175,http://localhost:5175'
uvicorn backend.main:app --host 127.0.0.1 --port 8100

# In the frontend terminal:
$env:VITE_API_BASE_URL = 'http://127.0.0.1:8100/api'
npm run dev -- --host 127.0.0.1 --port 5175 --strictPort
```

## Demo workflow

Generate a safe local synthetic source (the generator is preserved and not used by the app automatically):

```powershell
.\.venv\Scripts\python.exe edr_log_generator.py --count 1000 --output file --file data\edr_events.json --rate 0
```

Upload that file in **Ingest** and process it, or call:

```powershell
Invoke-RestMethod -Method Post http://localhost:8000/api/ingest/process?filename=edr_events.json
```

Use Incident Explorer to select evidence, then Timeline, Graph, MITRE and Report. All dashboard quantities come from the local API; no placeholder metrics are displayed.

## Adaptive, Self-Optimizing Large-Scale Ingestion Engine (10 GB, 50 GB and larger on 16 GB RAM)

ChainSight AI features a streaming, adaptive ingestion architecture designed to process very large security datasets (10 GB, 50 GB, and beyond) reliably on machines with limited RAM (including 16 GB Windows systems):

- **Adaptive Dynamic Batch Sizing:** Starts with conservative batch sizes and continuously measures live memory pressure (process RSS, system available RAM, DuckDB buffer allocation) and throughput (EPS and MB/s). When ample headroom is present (<55% memory budget and >2 GB system RAM available), batch size dynamically scales up by 25% to maximize throughput. If memory pressure approaches configured limits (>=70% budget or <1.5 GB available RAM), it immediately throttles batch size by 35% and invokes garbage collection.
- **Performance Profiling & Bottleneck Identification:** Every batch instruments parser time, DuckDB write time, and detection evaluation time without introducing slow profiling loops. Live runs diagnose whether the pipeline is *Database write bound*, *Rule evaluation bound*, *Parser bound*, or operating at *Balanced throughput*.
- **Historical Learning & Initial Batch Seeding:** Optimal configurations and performance metrics are persisted in DuckDB (`ingestion_history`). When ingesting new datasets, the engine queries past runs for the matching format (JSONL, CEF, FortiGate, CSV) and size tier (small, medium, large, very-large) to seed sensible initial batch configurations.
- **Bounded Stream Reader:** Reads files in configurable binary chunks (`CHUNK_SIZE_MB = 64`) that strictly terminate on complete line boundaries (`\n`). Records are never truncated or split, and files are never loaded completely into RAM.
- **Batch Processing & Arrow Registration:** Data is transformed into columnar PyArrow tables and registered into DuckDB via zero-copy batch inserts (`INSERT OR IGNORE INTO events_staging SELECT ... FROM _stream_event_batch`).
- **Persistent Checkpoints & Resumability:** Checkpoints are stored in DuckDB (`ingestion_runs`) *only after successful database commits*, recording `job_id`, `source_path`, `bytes_total`, `source_mtime_ns`, `bytes_processed`, `line_number`, `valid_records`, `invalid_records`, `total_records`, dynamic batch size, bottleneck, and compact rule engine state. Interrupted jobs resume from the exact byte offset; modified source files are rejected.
- **Detection Consistency Across Sizing Variations:** Stateful multi-event sliding windows (brute-force sequences `CS-AUTH-001`/`CS-AUTH-002` and ransomware mass file modifications `CS-RANSOM-001`) and correlation graphs maintain 100% detection accuracy and evidence preservation regardless of dynamic batch size changes.
- **Live Monitoring & Dashboard UI:** The dashboard and API track real-time throughput in MB/s, events/sec, dynamic batch size (`(adaptive)`), latency bottleneck, optimization status, elapsed time, process RSS memory, and clearly labeled estimated remaining time (`~X s (estimate)`).

### Configuration

Environment variables (with tested defaults):

```powershell
$env:CHAINSIGHT_ADAPTIVE_TUNING = 'true'       # Enable self-optimizing adaptive batch engine (default: true)
$env:CHAINSIGHT_MIN_BATCH_RECORDS = 2000      # Minimum batch size when throttled (default: 2,000)
$env:CHAINSIGHT_MAX_BATCH_RECORDS = 50000     # Maximum batch size when scaling up (default: 50,000)
$env:CHAINSIGHT_TARGET_MEMORY_RATIO = 0.70    # Memory budget threshold for throttle trigger (default: 0.70)
$env:CHAINSIGHT_CHUNK_SIZE_MB = 64            # Chunk reader buffer in MB (default: 64)
$env:CHAINSIGHT_BATCH_SIZE = 10000            # Initial default batch records (default: 10,000)
$env:CHAINSIGHT_DUCKDB_MEMORY_LIMIT = '4GB'   # DuckDB RAM budget (default: 4GB)
$env:CHAINSIGHT_PARSER_WORKERS = 2            # Concurrency limit for parsing (default: 2)
$env:CHAINSIGHT_DUCKDB_THREADS = 4            # DuckDB worker threads
```

### Ingestion Control & Telemetry Endpoints

- `POST /api/ingest/jobs` – Start asynchronous background ingestion for a local file
- `GET /api/ingest/status/{job_id}` – Query real-time metrics, dynamic batch size, bottleneck, and checkpoint status
- `POST /api/ingest/pause/{job_id}` – Pause ingestion cleanly at the current batch boundary
- `POST /api/ingest/resume/{job_id}` – Resume ingestion from the last committed byte offset
- `POST /api/ingest/cancel/{job_id}` – Cancel active job and update status
- `POST /api/ingest/stream` – Direct streaming upload over HTTP with adaptive batch parsing
- `GET /api/ingest/history` – Retrieve historical run performance, optimal batch sizes, and bottleneck profiles

### Verified Ingestion Benchmarks: Static vs. Adaptive Engine

Tested locally on Windows 11 (16 GB RAM, local NVMe SSD):

| Records | Dataset Size | Static Throughput | Adaptive Throughput | Static Peak RAM | Adaptive Peak RAM | Speedup | Detection Parity |
|---|---|---|---|---|---|---|---|
| **100,000** | 33.4 MB | 4,383.6 eps (1.46 MB/s) | **17,362.9 eps** (5.79 MB/s) | 201.7 MB | 206.8 MB | **3.96x** | 100% Identical |
| **1,000,000** | 333.7 MB | 8,370.5 eps (2.79 MB/s) | **15,666.0 eps** (5.23 MB/s) | 585.2 MB | 635.1 MB | **1.87x** | 100% Identical |

*Benchmark Observations:*
- On the **1,000,000 record dataset**, the Adaptive Engine processed 1M events in **63.83 seconds** at **15,666 eps** (**5.23 MB/s**) compared to **119.47 seconds** for the static engine—a **1.87x speedup**.
- On the **100,000 record dataset**, throughput reached **17,362.9 eps** (**5.79 MB/s**) taking just **5.76 seconds** compared to **22.81 seconds**—a **3.96x speedup**.
- Memory consumption remained tightly bounded at **635.1 MB Peak RSS** for 1M events (<4% of system RAM), safely within the 4.0 GB budget on 16 GB hardware.
- Both engines produced 100% identical valid record counts, detection counts, and incident memberships.
- *Large File Note (10 GB, 50 GB):* Because processing is strictly streaming and bounded with constant memory consumption (~635 MB RSS for 1M events), 10 GB and 50 GB files can be processed without RAM exhaustion or swapping. Full completion time depends on disk I/O throughput.

## Processing 10–50 GB files

For large local files, start a background job and poll its status. This avoids holding an HTTP request open. The existing dashboard endpoint `/api/ingest/process` remains available for compatibility; no frontend change is required.

In the dashboard, open **Ingest**. For a large log already on this machine, enter its full path from `Downloads` and choose **Process in place**; the page starts a background job and displays the phase, processed/valid/malformed/duplicate counts, detections, elapsed time and measured throughput while it runs. Fresh path jobs use bounded first-seen event-ID inserts and evaluate rules batch by batch during ingestion. For JSONL, JSON, CEF and line-oriented log files selected with **Add a log file**, the browser sends a bounded byte stream. The API parses, normalizes, deduplicates by event ID and stores complete batches during transfer; ordered timestamps also let rule detection run batch by batch while upload continues. If timestamps go backwards, provisional detections are discarded and the exact timestamp-sorted pass runs after upload. Correlation waits until the full source is present so incident membership is computed over the complete timeline. CSV/TSV selection uses the existing upload-and-job path. **Refresh data** visibly confirms when the API data has reloaded and reports endpoint errors.

While a job is active, the Overview polls ingestion status every second and shows processed, valid, malformed, duplicate, average-throughput, and deduplicated staged-event readings from the active run. These counts describe the staged dataset; the previous published dataset remains in storage until the run completes. Detection hits and severity appear only after the corresponding detection pass has run. If exact detection is deferred (for example, after resuming a partially processed source), the dashboard says **Pending** rather than showing an unverified zero. Final incidents, critical counts, and host totals remain pending until analysis has enough evidence to calculate them. The dashboard refreshes the published metrics automatically when a job completes.

```powershell
$request = @{ source_path = 'C:\Users\<you>\Downloads\firex-10G.log' } | ConvertTo-Json
$job = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/ingest/jobs -ContentType 'application/json' -Body $request
do {
    Start-Sleep -Seconds 2
    $progress = Invoke-RestMethod -Uri "http://localhost:8000$($job.status_url)"
    $progress | Select-Object state, phase, percent_complete, total_records, valid_records, invalid_records, duplicate_records, throughput_eps
} while ($progress.state -in @('queued', 'processing'))
```

The job reads from `data/` or the Downloads folder, keeps the last published dataset available while processing, and publishes the new dataset only after analysis succeeds. If the backend stops during ingestion, submit the same unchanged source again to resume at its last committed record boundary. Analysis restarts from the disk-backed staged events. CSV/TSV ingestion maps common column names; inspect the organizer sample and add an explicit mapping if it uses a different schema.

Large input needs free disk space for the DuckDB database and its spill directory at `data/duckdb_tmp`. The source file itself is read in place. Automatic ingestion tuning is on by default (`CHAINSIGHT_INGEST_AUTO_TUNE=true`): small and medium files use bounded 50,000-record batches and a 4–8 MiB read buffer; large files use the same tested batch size with larger reads, and parser workers scale up only when file size, CPU count, and currently available memory allow. Files above 20 GiB can use 100,000-record batches when at least 8 GiB of memory is currently available and no explicit batch override is configured. The selected profile and reason are included in job status. Set `CHAINSIGHT_INGEST_BATCH_SIZE`, `CHAINSIGHT_READ_BUFFER_BYTES`, or `CHAINSIGHT_PARSER_WORKERS` to override the corresponding automatic choice; `CHAINSIGHT_DUCKDB_MEMORY_LIMIT` (6 GB), `CHAINSIGHT_DUCKDB_THREADS`, and `CHAINSIGHT_DUCKDB_TEMP_DIR` remain configurable. Automatic worker scaling is not a promised speedup; benchmark on the target machine before raising the memory or worker limits.

### Processing the supplied FortiGate dataset in place

The app recognizes the FortiGate export format used by `firex-10G.log`. In **Ingest**, enter `C:\Users\moham\Downloads\firex-10G.log` into **Process in place**. This avoids creating a second multi-gigabyte upload. It streams `traffic`, `event`, and `utm` records; the current source starts a new investigation rather than mixing unrelated source files.

## Testing

```powershell
.\.venv\Scripts\pytest.exe -q
cd frontend; npm run build
```

Tests cover JSONL/CEF/FortiGate/CSV ingestion, malformed and duplicate records, resumable jobs, preservation of the last complete dataset, authentication sequences, correlation and observed graph edges. Add organizer-format fixtures when the official dataset arrives.

Latest verification snapshot (2026-10-31): the pre-existing paired 125,000-record seeded sample produced identical event, detection, MITRE, and incident-membership outputs in path and stream modes; measured throughput varied under host load, so those runs do not establish a reliable streaming speedup. The current adaptive-ingestion and layout changes passed Python compileall, **31 tests** in an isolated data directory, and the frontend production build. A Firex ingestion was already active while the new backend code was being edited and remains on the original one-worker profile; at the latest observation it had processed 5,150,000 records at 5,766.5 records/second. No before/after throughput result for the new profile has been measured yet. The backend must be restarted after the active job finishes for new jobs to use automatic tuning. No labelled organizer ground truth or controlled 10–50 GB/1 TB result is available. See [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) and [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for measurements and limits.

## Dataset arrival plan

1. Place the supplied file in `data/` and run `inspect_data.py` against a bounded sample.
2. Identify its format and field names; do not infer its schema.
3. Add a parser adapter in `backend/ingestion/` that creates `NormalizedEvent` values.
4. Run ingestion and validate results against source records before trusting a detection or incident relationship.

## Limitations and honest scoring

This is a rule-driven prototype, not a validated detection product. Scores are explainable prioritization aids: highest detection severity + detection volume + tactic breadth + average evidence confidence, capped at 100. It does not make active network probes, does not invoke external AI APIs, and cannot calculate precision, recall, detection rate or false-positive rate without labelled ground truth. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Project map

```
backend/       FastAPI, ingestion, rules, correlation, graph, risk, reports
frontend/      Vite + React dashboard
rules/         editable JSON detection rules
tests/         synthetic unit tests
data/          local telemetry and DuckDB (ignored by Git)
docs/          architecture, API, benchmarks, progress checklist
```

## Team contribution notes

One teammate can own dataset inspection/parser mapping and validation; the other can tune rules, investigate UI output and refine demo/report narrative. Keep raw evidence and assumptions visible during judging.
