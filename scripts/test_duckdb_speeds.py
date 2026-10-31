import time
import duckdb
import pyarrow as pa
from uuid import uuid4

# Setup test arrow table with 100k rows
count = 100_000
ids = [f"evt-{i:07d}" for i in range(count)]
timestamps = [1700000000 + i for i in range(count)]
hosts = [f"host-{i%50}" for i in range(count)]

table = pa.Table.from_arrays([
    pa.array(ids, type=pa.string()),
    pa.array(timestamps, type=pa.int64()),
    pa.array(hosts, type=pa.string())
], names=["event_id", "timestamp", "host"])

from pathlib import Path
tmp = Path("test_db_speeds.duckdb")
tmp.unlink(missing_ok=True)

# Test 1: File-backed with PK + INSERT OR IGNORE + RETURNING
db1 = duckdb.connect(str(tmp))
db1.execute("CREATE TABLE t1 (event_id VARCHAR PRIMARY KEY, timestamp BIGINT, host VARCHAR)")
t0 = time.perf_counter()
db1.register("b1", table)
db1.execute("BEGIN TRANSACTION")
res1 = db1.execute("INSERT OR IGNORE INTO t1 SELECT * FROM b1 RETURNING event_id").fetchall()
db1.execute("COMMIT")
t1 = time.perf_counter() - t0
print(f"Test 1 (Disk PK + INSERT OR IGNORE + RETURNING): {t1:.3f} s ({count/t1:,.0f} eps)")
db1.close()
tmp.unlink(missing_ok=True)

# Test 2: File-backed with NO PK, plain INSERT INTO
db2 = duckdb.connect(str(tmp))
db2.execute("CREATE TABLE t2 (event_id VARCHAR, timestamp BIGINT, host VARCHAR)")
t0 = time.perf_counter()
db2.register("b2", table)
db2.execute("BEGIN TRANSACTION")
db2.execute("INSERT INTO t2 SELECT * FROM b2")
db2.execute("COMMIT")
t2 = time.perf_counter() - t0
print(f"Test 2 (Disk NO PK, plain INSERT INTO):          {t2:.3f} s ({count/t2:,.0f} eps)")
db2.close()
tmp.unlink(missing_ok=True)
