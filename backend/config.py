from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("CHAINSIGHT_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("CHAINSIGHT_DB_PATH", str(DATA_DIR / "chainsight.duckdb"))).expanduser().resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
DUCKDB_TEMP_DIR = Path(os.getenv("CHAINSIGHT_DUCKDB_TEMP_DIR", str(DATA_DIR / "duckdb_tmp"))).expanduser().resolve()
DUCKDB_TEMP_DIR.mkdir(parents=True, exist_ok=True)
RULES_PATH = Path(os.getenv("CHAINSIGHT_RULES_PATH", str(ROOT / "rules" / "detection_rules.json"))).expanduser().resolve()


def _positive_int(name: str, default: int, maximum: int | None = None) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    if value < 1:
        return default
    return min(value, maximum) if maximum else value


import psutil

# Chunk-based streaming & Adaptive Ingestion Configuration
CHUNK_SIZE_MB = _positive_int("CHAINSIGHT_CHUNK_SIZE_MB", 64, 512)
CHUNK_SIZE_BYTES = CHUNK_SIZE_MB * 1024 * 1024

MIN_BATCH_RECORDS = _positive_int("CHAINSIGHT_MIN_BATCH_RECORDS", 10_000, 50_000)
MAX_BATCH_RECORDS = _positive_int("CHAINSIGHT_MAX_BATCH_RECORDS", 100_000, 200_000)
BATCH_SIZE = _positive_int("CHAINSIGHT_BATCH_SIZE", 50_000, MAX_BATCH_RECORDS)
ADAPTIVE_TUNING_ENABLED = os.getenv("CHAINSIGHT_ADAPTIVE_TUNING", "true").strip().lower() in {"1", "true", "yes", "on"}
TARGET_MEMORY_RATIO = float(os.getenv("CHAINSIGHT_TARGET_MEMORY_RATIO", "0.80"))

MAX_WORKERS = _positive_int("CHAINSIGHT_PARSER_WORKERS", max(2, min(4, (os.cpu_count() or 2) // 2)), 8)
PARSER_WORKERS_OVERRIDE = _positive_int("CHAINSIGHT_PARSER_WORKERS", MAX_WORKERS, 16) if os.getenv("CHAINSIGHT_PARSER_WORKERS") else MAX_WORKERS
PARSER_WORKERS = MAX_WORKERS

CHUNK_SIZE_OVERRIDE = _positive_int("CHAINSIGHT_INGEST_BATCH_SIZE", BATCH_SIZE, 100_000) if os.getenv("CHAINSIGHT_INGEST_BATCH_SIZE") else None
CHUNK_SIZE = CHUNK_SIZE_OVERRIDE or MAX_BATCH_RECORDS

READ_BUFFER_BYTES_OVERRIDE = _positive_int("CHAINSIGHT_READ_BUFFER_BYTES", 4 * 1024 * 1024, 64 * 1024 * 1024) if os.getenv("CHAINSIGHT_READ_BUFFER_BYTES") else None
READ_BUFFER_BYTES = READ_BUFFER_BYTES_OVERRIDE or min(CHUNK_SIZE_BYTES, 8 * 1024 * 1024)

DUCKDB_THREADS = _positive_int("CHAINSIGHT_DUCKDB_THREADS", max(1, min(4, (os.cpu_count() or 2) - 1)), 64)
AUTO_INGEST_TUNING = os.getenv("CHAINSIGHT_INGEST_AUTO_TUNE", "true").strip().lower() in {"1", "true", "yes", "on"}

_sys_total_ram = psutil.virtual_memory().total
_default_mem_limit_gb = max(4, min(8, int(_sys_total_ram / (1024**3) * 0.50)))
_raw_memory_limit = os.getenv("CHAINSIGHT_DUCKDB_MEMORY_LIMIT", f"{_default_mem_limit_gb}GB").strip().upper()
MAX_MEMORY_LIMIT = _raw_memory_limit if re.fullmatch(r"\d+(?:B|KB|MB|GB|TB|%)", _raw_memory_limit) else f"{_default_mem_limit_gb}GB"
DUCKDB_MEMORY_LIMIT = MAX_MEMORY_LIMIT

def _parse_bytes(size_str: str, default_bytes: int = 4 * 1024 * 1024 * 1024) -> int:
    m = re.match(r"^(\d+)\s*([A-Za-z]+)?$", size_str.strip())
    if not m:
        return default_bytes
    num = int(m.group(1))
    unit = (m.group(2) or "B").upper()
    multipliers = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3,
        "TB": 1024 ** 4,
    }
    return num * multipliers.get(unit, 1)

MEMORY_BUDGET_BYTES = _parse_bytes(MAX_MEMORY_LIMIT, _default_mem_limit_gb * 1024 * 1024 * 1024)

CORRELATION_WINDOW_MINUTES = _positive_int("CHAINSIGHT_CORRELATION_WINDOW_MINUTES", 60, 10_080)
