import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import time
import orjson
import pyarrow as pa
from datetime import datetime, timezone
from backend.models import NormalizedEventRecord

count = 100_000
dt = datetime.now(timezone.utc)
events = [
    NormalizedEventRecord(
        event_id=f"evt-{i}",
        timestamp=dt,
        event_kind="event",
        category="authentication",
        action="failure",
        severity="low",
        host="WS-01",
        raw_event={"foo": "bar", "num": i},
        rule_context={},
        raw_event_json=b'{"foo":"bar"}'
    )
    for i in range(count)
]

# Method 1: Current approach with 22 separate list comprehensions
t0 = time.perf_counter()
raw_events = [
    e.raw_event_json.decode("utf-8", errors="replace")
    if isinstance(getattr(e, "raw_event_json", None), bytes)
    else (getattr(e, "raw_event_json", None) or orjson.dumps(e.raw_event).decode())
    for e in events
]
rule_contexts = [orjson.dumps(e.rule_context).decode() for e in events]
t1 = [e.event_id for e in events]
t2 = [e.timestamp for e in events]
t3 = [e.event_kind for e in events]
t4 = [e.category for e in events]
t5 = [e.action for e in events]
t6 = [e.severity for e in events]
t7 = [e.host for e in events]
t8 = [e.source_ip for e in events]
t9 = [e.destination_ip for e in events]
t10 = [e.user for e in events]
t11 = [e.process_name for e in events]
t12 = [e.process_id for e in events]
t13 = [e.parent_process for e in events]
t14 = [e.command_line for e in events]
t15 = [e.file_path for e in events]
t16 = [e.registry_path for e in events]
t17 = [e.domain for e in events]
t18 = [e.technique_id for e in events]
t19 = [e.technique_name for e in events]
t20 = [e.tactic for e in events]
time_curr = time.perf_counter() - t0
print(f"Current 22 comprehensions: {time_curr:.3f} s")

# Method 2: Single-pass unpacking
t0 = time.perf_counter()
c_id = [None] * count
c_time = [None] * count
c_kind = [None] * count
c_cat = [None] * count
c_act = [None] * count
c_sev = [None] * count
c_host = [None] * count
c_src = [None] * count
c_dst = [None] * count
c_user = [None] * count
c_proc = [None] * count
c_pid = [None] * count
c_parent = [None] * count
c_cmd = [None] * count
c_file = [None] * count
c_reg = [None] * count
c_dom = [None] * count
c_tid = [None] * count
c_tname = [None] * count
c_tac = [None] * count
c_ctx = [None] * count
c_raw = [None] * count

empty_ctx_json = "{}"
for i, e in enumerate(events):
    c_id[i] = e.event_id
    c_time[i] = e.timestamp
    c_kind[i] = e.event_kind
    c_cat[i] = e.category
    c_act[i] = e.action
    c_sev[i] = e.severity
    c_host[i] = e.host
    c_src[i] = e.source_ip
    c_dst[i] = e.destination_ip
    c_user[i] = e.user
    c_proc[i] = e.process_name
    c_pid[i] = e.process_id
    c_parent[i] = e.parent_process
    c_cmd[i] = e.command_line
    c_file[i] = e.file_path
    c_reg[i] = e.registry_path
    c_dom[i] = e.domain
    c_tid[i] = e.technique_id
    c_tname[i] = e.technique_name
    c_tac[i] = e.tactic
    c_ctx[i] = empty_ctx_json if not e.rule_context else orjson.dumps(e.rule_context).decode()
    if isinstance(e.raw_event_json, str):
        c_raw[i] = e.raw_event_json
    elif isinstance(e.raw_event_json, bytes):
        c_raw[i] = e.raw_event_json.decode("utf-8", errors="replace")
    else:
        c_raw[i] = orjson.dumps(e.raw_event).decode()

time_single = time.perf_counter() - t0
print(f"Single-pass pre-allocated: {time_single:.3f} s ({time_curr/time_single:.2f}x faster)")
