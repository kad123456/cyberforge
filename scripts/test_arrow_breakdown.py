import sys, time, orjson
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pyarrow as pa
from scripts.compare_static_vs_adaptive import generate_benchmark_dataset
from backend.ingestion.parser import parse_line, normalize

f = Path("test_sample.jsonl")
generate_benchmark_dataset(f, 100_000)
lines = f.read_bytes().splitlines()
raw = [parse_line(l, source_format="jsonl") for l in lines]
events = [normalize(d) for d in raw]

# Benchmark parts of _events_to_arrow_table
t0 = time.perf_counter()
timestamps = [
    e.timestamp if getattr(e.timestamp, "tzinfo", None) is not None
    else e.timestamp.replace(tzinfo=timezone.utc)
    for e in events
]
print("Timestamps:", time.perf_counter() - t0)

t0 = time.perf_counter()
raw_events = [
    e.raw_event_json.decode("utf-8", errors="replace")
    if isinstance(getattr(e, "raw_event_json", None), bytes)
    else (getattr(e, "raw_event_json", None) or orjson.dumps(e.raw_event, default=str).decode("utf-8"))
    for e in events
]
print("Raw events JSON serialization:", time.perf_counter() - t0)

t0 = time.perf_counter()
rule_contexts = [orjson.dumps(e.rule_context, default=str).decode("utf-8") for e in events]
print("Rule contexts JSON serialization:", time.perf_counter() - t0)

t0 = time.perf_counter()
pa_timestamp = pa.array(timestamps, type=pa.timestamp("us", tz="UTC"))
print("pa.array timestamp:", time.perf_counter() - t0)

t0 = time.perf_counter()
pa_strings = [pa.array([getattr(e, attr) for e in events], type=pa.string()) for attr in ["event_id", "host", "user", "action"]]
print("pa.array 4 string columns:", time.perf_counter() - t0)

f.unlink(missing_ok=True)
