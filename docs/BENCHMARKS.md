# Benchmarking

Run a reproducible local measurement against a source file:

```powershell
python scripts/benchmark_ingestion.py "C:\path\to\events.jsonl" --database data\benchmark.duckdb --output data\benchmark.json
```

The report records source/database/temp bytes, processed/valid/invalid/duplicate counts, detections, incidents, duration, events per second, sampled CPU, peak process RSS and latency for representative dashboard/event queries. Detection accuracy, MITRE-label accuracy, path accuracy and false-positive rate stay `null` until organizer ground truth is supplied.

## Available smoke measurement

The organizer's 100 MB development sample was not present in the workspace. A generated 100 MiB JSONL workload was used to check bounded processing and the benchmark harness. On the available Windows/Python 3.12.5 environment, it contained 174,657 benign process events and completed in 13.854 seconds (12,607 events/second), with a measured peak process RSS of 379,293,696 bytes. The DuckDB file grew by 33,816,576 bytes. Measured query latencies were 57.53 ms for dashboard counts, 108.48 ms for the first 200-event page, and 49.49 ms for incident overview. The generated records produced zero detections and incidents.

This synthetic result checks the pipeline mechanics only. It is not organizer-data accuracy evidence, not a 10/30/50 GB test, and not a claim that official processing targets are met. The 50 GB tier must be measured on the target machine with its actual data format and ground truth. Unordered timestamps also trigger a disk-backed DuckDB sort and can take longer than the ordered synthetic workload.

## Accuracy and scale

Detection rate, precision, recall, MITRE-label accuracy and false-positive rate are unavailable without reliable ground truth. The PRD's performance numbers are evaluation targets, not achieved results. Run the benchmark separately for each supplied tier and keep its JSON output with the tested source, machine configuration and code revision.

A five-second limit for files of arbitrary size is not physically achievable: the data must at least be read or transferred. The existing 6.543 GB source alone requires about 1.31 GB/s sustained input to finish in five seconds, before parsing, deduplication, detection, correlation or storage. A 50 GB file would require 10 GB/s just for input. The stream-upload path overlaps bounded parsing/normalization/storage with transfer to reduce serial work; it does not remove the input-byte lower bound or promise a fixed completion time.

DuckDB defaults to a 6 GB memory limit and spills to `data/duckdb_tmp`. This bounds DuckDB-managed memory; total process RSS also includes Python, Arrow and any configured parser workers. Leave disk space for the database and spill files. `CHAINSIGHT_PARSER_WORKERS` defaults to 1; four workers were slower on the available 100 MiB synthetic workload, so enable them only after measuring on the actual target machine and dataset.

## Seeded EDR generator smoke run (2026-10-31)

The repository's generator was run with `--count 5000 --output file --rate 0 --seed 42`, followed by the benchmark harness against an isolated temporary DuckDB database. It emitted 5,000 records (4,181,238 source bytes; 250 generator-tagged alerts). Processing took 3.584 seconds at 1,395.1 records/second, with 5,000 valid, 0 invalid, 0 duplicates, 267 detections, 1 incident, and 191,762,432 bytes peak process RSS. Query timings were 56.96 ms for dashboard counts, 70.96 ms for the first event page, and 61.22 ms for incident overview. Accuracy remains `null`: synthetic alert tags do not establish ground truth.

## Before/after throughput comparison (2026-10-31)

### Main bottlenecks found in code inspection

1. The JSONL hot path decoded every line to text and serialized parsed raw JSON again before storage. The reader now yields bounded source bytes; JSONL parsing accepts bytes directly, and the original bytes are passed through as evidence.
2. Each batch built Python row dictionaries before Arrow registration, and the default 10,000-record batch caused more write/registration cycles. Bulk Arrow inserts remain in place, with a measured 50,000-record default and an environment override. The larger batch improves throughput on this fixture but raises peak RSS; use 10,000 or smaller under memory pressure.
3. Progress updates sampled process CPU/RSS on every batch, and detection/correlation work ran as a separate full pass after ingestion. Resource sampling is throttled to once per second; fresh ordered jobs now detect each accepted batch during ingestion, with a sorted fallback for out-of-order input. Correlation consumes one bounded streaming join of persisted detections to their evidence events instead of materializing the full event set.

Fresh path jobs and browser stream uploads use a staging primary key to deduplicate as each batch is inserted, avoiding a full-table deduplication scan and rewrite. For ordered timestamps, rule detection also runs over accepted batches during ingestion/transfer; if ordering breaks, provisional detections are cleared and the canonical sorted pass runs after input completes. Correlation runs after ingestion and consumes persisted detections in timestamp order. Legacy interrupted runs retain the disk-backed deduplication pass. The pipeline does not use DuckDB's native JSON reader: it uses bounded parsing followed by Arrow bulk inserts to preserve normalization and raw-evidence behavior.

Fresh path-based jobs use the same first-seen primary-key insert and inline rule evaluation. A partial resume disables inline detection and rebuilds detection from all staged rows, so stateful rules keep their full window state. Out-of-order input is also detected in a sorted pass. These choices preserve the same normalized evidence and detection results as the canonical sorted pipeline while showing counts during ingestion.

The same deterministic input and Windows/Python 3.12.5 machine were used for both runs. The file was generated with `edr_log_generator.py --count 125000 --output file --rate 0 --alert-ratio 0.05 --seed 42` and measured 104,652,691 bytes. Baseline code used 10,000-record batches; optimized code uses 50,000-record batches, one parser worker, and 15 DuckDB threads.

| Measurement | Baseline | Optimized |
|---|---:|---:|
| Duration | 17.160 s | 14.592 s |
| Throughput | 7,284.4 records/s | 8,566.4 records/s |
| Peak process RSS | 519,675,904 bytes | 811,360,256 bytes |
| Valid / invalid / duplicates | 125,000 / 0 / 0 | 125,000 / 0 / 0 |
| Detections / incidents | 7,818 / 1 | 7,818 / 1 |
| Incident-event memberships | 6,570 | 6,570 |

The measured throughput increased 17.6% and elapsed time fell 15.0%. Peak RSS increased by about 279 MiB; lower the batch size with `CHAINSIGHT_INGEST_BATCH_SIZE=10000` on memory-constrained machines. Query timings in the optimized run were 49.49 ms for dashboard counts, 138.13 ms for the first event page, and 40.62 ms for incident overview.

Canonical fingerprints matched for normalized event evidence, detection semantics, incident membership groups, and MITRE mapping counts. The generator's 6,214 tagged alerts are not ground truth, so precision, recall, and detection accuracy remain `null`. The old code created random UUIDv4 detection IDs; the optimized pipeline now creates stable UUIDv5 IDs from the event ID and rule ID. Exact legacy UUID bytes differ by design, but the semantic detection set is unchanged and the new IDs repeat exactly across optimized runs.

## Inline detection and upload benchmark (2026-10-31)

The final paired run used the same 104,652,691-byte seeded 125,000-record file, Windows/Python 3.12.5 host, 50,000-record batches and 15 DuckDB threads. The path run was followed by a bounded 4 MiB chunk upload through `/api/ingest/stream` using FastAPI's in-process test client.

| Mode | Duration | Throughput | Peak process RSS | Valid / invalid / duplicates | Detections / incidents |
|---|---:|---:|---:|---:|---:|
| Process in place | 13.888 s | 9,000.3 records/s | 841,281,536 bytes | 125,000 / 0 / 0 | 7,818 / 1 |
| Stream upload | 13.696 s | 9,126.7 records/s | 1,063,346,176 bytes | 125,000 / 0 / 0 | 7,818 / 1 |

The paired stream result was 1.4% faster, but repeat timings during other host activity ranged from 13.1 to 28.7 seconds. Treat that small difference as timing noise, not as a reliable speedup. The stream method provides per-batch detection visibility and can overlap parsing/storage/rules with transfer; for a local file, **Process in place** avoids the extra byte transfer and is the better default. A 100,000-record batch used about 1.21 GB peak RSS and did not consistently beat 50,000; an 8-thread trial took 17.417 seconds, so the defaults remain 50,000 and 15 threads.

Exact DuckDB comparisons between the path and stream sample found zero difference rows for normalized event evidence, stable detection IDs/evidence, incident-membership groups, and MITRE technique/tactic counts. The synthetic sample produced no ground-truth accuracy measure.

Reproduce the upload-mode measurement with:

```powershell
python scripts/benchmark_stream_upload.py C:\path\to\seeded-125k.json --database $env:TEMP\stream-bench\stream.duckdb --output $env:TEMP\stream-bench\report.json
```
