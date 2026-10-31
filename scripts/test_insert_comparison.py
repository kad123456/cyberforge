import time
import duckdb
import pyarrow as pa
from pathlib import Path

count = 100_000
batch_size = 10_000

# Generate 100k test records
all_ids = [f"evt-{i:07d}" for i in range(count)]
all_timestamps = [1700000000 + i for i in range(count)]
all_hosts = [f"host-{i%50}" for i in range(count)]

# Method 1: Disk DuckDB with PRIMARY KEY + INSERT OR IGNORE + RETURNING
p1 = Path("bench_m1.duckdb")
p1.unlink(missing_ok=True)
db1 = duckdb.connect(str(p1))
db1.execute("CREATE TABLE events (event_id VARCHAR PRIMARY KEY, timestamp BIGINT, host VARCHAR)")

t0 = time.perf_counter()
for b_start in range(0, count, batch_size):
    b_end = b_start + batch_size
    sub_table = pa.Table.from_arrays([
        pa.array(all_ids[b_start:b_end]),
        pa.array(all_timestamps[b_start:b_end]),
        pa.array(all_hosts[b_start:b_end])
    ], names=["event_id", "timestamp", "host"])
    db1.register("batch", sub_table)
    db1.execute("BEGIN TRANSACTION")
    res = db1.execute("INSERT OR IGNORE INTO events SELECT * FROM batch RETURNING event_id").fetchall()
    db1.execute("COMMIT")
    db1.unregister("batch")
    inserted_ids = {r[0] for r in res}
t_m1 = time.perf_counter() - t0
print(f"Method 1 (Disk PK + INSERT OR IGNORE + RETURNING): {t_m1:.3f} s ({count/t_m1:,.0f} eps)")
db1.close()
p1.unlink(missing_ok=True)

# Method 2: In-memory seen_ids set + Disk DuckDB plain INSERT INTO (no PK)
p2 = Path("bench_m2.duckdb")
p2.unlink(missing_ok=True)
db2 = duckdb.connect(str(p2))
db2.execute("CREATE TABLE events (event_id VARCHAR, timestamp BIGINT, host VARCHAR)")

t0 = time.perf_counter()
seen_ids = set()
for b_start in range(0, count, batch_size):
    b_end = b_start + batch_size
    batch_ids = all_ids[b_start:b_end]
    # Filter duplicates in O(1) Python set
    first_seen_indices = [idx for idx, eid in enumerate(batch_ids) if eid not in seen_ids]
    seen_ids.update(batch_ids[idx] for idx in first_seen_indices)
    
    sub_table = pa.Table.from_arrays([
        pa.array([batch_ids[idx] for idx in first_seen_indices]),
        pa.array([all_timestamps[b_start + idx] for idx in first_seen_indices]),
        pa.array([all_hosts[b_start + idx] for idx in first_seen_indices])
    ], names=["event_id", "timestamp", "host"])
    db2.register("batch", sub_table)
    db2.execute("BEGIN TRANSACTION")
    db2.execute("INSERT INTO events SELECT * FROM batch")
    db2.execute("COMMIT")
    db2.unregister("batch")
t_m2 = time.perf_counter() - t0
print(f"Method 2 (Set tracking + Disk plain INSERT INTO):  {t_m2:.3f} s ({count/t_m2:,.0f} eps)")
db2.close()
p2.unlink(missing_ok=True)
print(f"Speedup: {t_m1 / t_m2:.2f}x faster!")
