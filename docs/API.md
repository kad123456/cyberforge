# API

FastAPI publishes OpenAPI/Swagger at `/docs`.

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Health and offline mode |
| `POST /api/ingest/upload` | Stream an uploaded file to local storage |
| `POST /api/ingest/process?filename=` | Synchronous compatibility path used by the current dashboard |
| `POST /api/ingest/jobs` | Start a long-running local file job |
| `GET /api/ingest/jobs/{job_id}` | Poll progress and final counters |
| `GET /api/ingest/status` | Latest job status for the dashboard |
| `GET /api/dashboard/summary` | Dashboard metrics from persisted data |
| `GET /api/events` | Normalized events (`limit`, `offset`, `severity`) |
| `GET /api/incidents` | Correlated incidents |
| `GET /api/incidents/{id}/timeline` | Ordered evidence |
| `GET /api/incidents/{id}/graph` | Evidence-backed entity graph |
| `GET /api/incidents/{id}/reachability` | Potential relationships, not compromise claims |
| `GET /api/mitre/techniques` | Mapped detection evidence |
| `GET /api/reports/{id}?format=html` | JSON or printable HTML report |

`/api/ingestion/jobs` and `/api/ingestion/jobs/{job_id}` are aliases for the `/api/ingest/jobs` routes.

Start a job with a file already in `data/`:

```json
POST /api/ingest/jobs
Content-Type: application/json

{"filename":"edr_events.jsonl"}
```

Or pass a local `source_path` inside the project `data/` directory or the user's Downloads folder. The response includes `job_id`, `state`, `phase`, `resuming` and `status_url`. Poll `status_url` until `state` is `complete` or `failed`.

Job status includes source bytes, byte progress, processed/valid/invalid/duplicate/skipped counts, phase, events per second, detections, incidents, CPU sample, peak process RSS and bounded parse errors. A failed job leaves the last completed dataset published; submitting the unchanged source again resumes from its last committed checkpoint where possible.
