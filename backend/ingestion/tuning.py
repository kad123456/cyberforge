from __future__ import annotations

import gc
import time
from dataclasses import asdict, dataclass

from backend.config import (
    BATCH_SIZE,
    MAX_BATCH_RECORDS,
    MEMORY_BUDGET_BYTES,
    MIN_BATCH_RECORDS,
    TARGET_MEMORY_RATIO,
)

MIB = 1024 * 1024
GIB = 1024 * MIB


def classify_file_tier(file_size_bytes: int) -> str:
    """Classify dataset file size into tiers for historical performance profiling."""
    size = max(0, int(file_size_bytes))
    if size < 256 * MIB:
        return "small"
    if size < 2 * GIB:
        return "medium"
    if size < 20 * GIB:
        return "large"
    return "very-large"


class AdaptiveBatchOptimizer:
    """Self-optimizing adaptive batch engine that tunes batch size from live telemetry.

    Monitors memory pressure, throughput (EPS and MB/s), CPU utilization, and latency
    bottlenecks (parser, DuckDB write, rule evaluation). Dynamically expands batch size
    when ample headroom exists to maximize throughput, and throttles immediately when
    memory pressure approaches configured budget limits.
    """

    def __init__(
        self,
        min_batch: int = MIN_BATCH_RECORDS,
        max_batch: int = MAX_BATCH_RECORDS,
        initial_batch: int = BATCH_SIZE,
        memory_budget_bytes: int = MEMORY_BUDGET_BYTES,
        target_memory_ratio: float = TARGET_MEMORY_RATIO,
    ):
        self.min_batch = max(1, int(min_batch))
        self.max_batch = max(self.min_batch, int(max_batch))
        self.current_batch = min(self.max_batch, max(self.min_batch, int(initial_batch)))
        self.memory_budget_bytes = max(100 * MIB, int(memory_budget_bytes))
        self.target_memory_ratio = max(0.40, min(0.90, float(target_memory_ratio)))

        self.batch_count = 0
        self.total_records = 0
        self.total_bytes = 0
        self.total_parse_sec = 0.0
        self.total_write_sec = 0.0
        self.total_detect_sec = 0.0
        self.peak_rss_bytes = 0
        self.recent_eps: list[float] = []
        self.last_status = "Adaptive dynamic tuning initialized"
        self.last_bottleneck = "Balanced throughput"
        self._last_gc_time = 0.0

    def step(
        self,
        records_count: int,
        bytes_count: int,
        parse_seconds: float,
        write_seconds: float,
        detect_seconds: float,
        process_rss: int,
        available_ram: int,
        duckdb_mem: int = 0,
    ) -> tuple[int, str, str, dict]:
        """Record batch performance and compute the optimal batch size for the next batch."""
        self.batch_count += 1
        self.total_records += records_count
        self.total_bytes += bytes_count
        self.total_parse_sec += parse_seconds
        self.total_write_sec += write_seconds
        self.total_detect_sec += detect_seconds

        used_mem = max(process_rss, duckdb_mem)
        self.peak_rss_bytes = max(self.peak_rss_bytes, used_mem)

        batch_time = max(0.0001, parse_seconds + write_seconds + detect_seconds)
        batch_eps = records_count / batch_time
        batch_mb_s = (bytes_count / MIB) / batch_time
        self.recent_eps.append(batch_eps)
        if len(self.recent_eps) > 10:
            self.recent_eps.pop(0)

        # Bottleneck classification
        if write_seconds / batch_time > 0.45:
            bottleneck = "Database write bound"
        elif detect_seconds / batch_time > 0.40:
            bottleneck = "Rule evaluation bound"
        elif parse_seconds / batch_time > 0.45:
            bottleneck = "Parser bound"
        else:
            bottleneck = "Balanced throughput"
        self.last_bottleneck = bottleneck

        # Memory pressure calculation
        mem_ratio = used_mem / self.memory_budget_bytes
        headroom_pct = max(0, int((1.0 - mem_ratio) * 100))

        # Adaptation heuristics:
        # 1. High memory pressure: process RSS + DuckDB buffer >= target ratio OR system available RAM critically low (< 500 MB)
        if mem_ratio >= self.target_memory_ratio or available_ram < 500 * MIB:
            new_batch = max(self.min_batch, int(self.current_batch * 0.65))
            status = f"Throttled: Reduced batch to {new_batch:,} (memory pressure: {int(used_mem / MIB)} MB used, {headroom_pct}% headroom)"
            now_mono = time.monotonic()
            if now_mono - self._last_gc_time >= 30.0:
                gc.collect()
                self._last_gc_time = now_mono
        # 2. Ample headroom (< 55% budget & available system RAM >= 1 GB)
        elif mem_ratio < 0.55 and available_ram >= 1000 * MIB:
            if self.current_batch < self.max_batch:
                # Scale up by 25%
                new_batch = min(self.max_batch, int(self.current_batch * 1.25))
                status = f"Optimizing: Scaled batch to {new_batch:,} ({int(batch_eps):,} eps, {headroom_pct}% RAM headroom)"
            else:
                new_batch = self.current_batch
                status = f"Stable: Maximum batch {new_batch:,} reached ({bottleneck})"
        # 3. Balanced / Optimal operating band (55% - 70%)
        else:
            new_batch = self.current_batch
            status = f"Stable: Optimal batch {new_batch:,} ({bottleneck})"

        self.current_batch = new_batch
        self.last_status = status

        profiling = {
            "batch_eps": round(batch_eps, 1),
            "batch_mb_s": round(batch_mb_s, 2),
            "parse_pct": round(100.0 * parse_seconds / batch_time, 1),
            "write_pct": round(100.0 * write_seconds / batch_time, 1),
            "detect_pct": round(100.0 * detect_seconds / batch_time, 1),
            "memory_ratio": round(mem_ratio, 2),
            "bottleneck": bottleneck,
        }
        return new_batch, status, bottleneck, profiling

    def summary(self) -> dict:
        total_time = max(0.001, self.total_parse_sec + self.total_write_sec + self.total_detect_sec)
        avg_eps = self.total_records / total_time
        avg_mb_s = (self.total_bytes / MIB) / total_time
        return {
            "record_count": self.total_records,
            "optimal_batch_size": self.current_batch,
            "avg_throughput_eps": round(avg_eps, 1),
            "avg_throughput_mb_s": round(avg_mb_s, 2),
            "peak_memory_bytes": self.peak_rss_bytes,
            "parse_time_seconds": round(self.total_parse_sec, 3),
            "write_time_seconds": round(self.total_write_sec, 3),
            "detect_time_seconds": round(self.total_detect_sec, 3),
            "bottleneck": self.last_bottleneck,
        }


@dataclass(frozen=True, slots=True)
class IngestionProfile:
    name: str
    batch_records: int
    parser_workers: int
    read_buffer_bytes: int
    reason: str

    def as_dict(self) -> dict[str, str | int]:
        return asdict(self)


def select_ingestion_profile(
    file_size_bytes: int,
    *,
    cpu_count: int,
    available_memory_bytes: int,
    max_batch_records: int = 100_000,
    max_parser_workers: int = 4,
    batch_override: int | None = None,
    worker_override: int | None = None,
    buffer_override: int | None = None,
    enabled: bool = True,
) -> IngestionProfile:
    """Choose bounded ingestion settings from file size and current headroom.

    The worker budget is intentionally conservative: every extra parser process
    needs memory for a deserialized batch, while DuckDB and the OS also need
    headroom. The limits affect throughput only; they never skip source rows.
    """
    file_size = max(0, int(file_size_bytes))
    available_memory = max(0, int(available_memory_bytes))
    cpu_count = max(1, int(cpu_count))
    max_batch_records = max(1, int(max_batch_records))
    max_parser_workers = max(1, int(max_parser_workers))

    if not enabled:
        batch_records = batch_override or min(50_000, max_batch_records)
        parser_workers = worker_override or 1
        read_buffer_bytes = buffer_override or 4 * MIB
        name = "fixed"
        reason = "Automatic tuning is disabled by configuration."
    else:
        if file_size < 256 * MIB:
            size_band = "small"
            recommended_batch = 50_000
            recommended_buffer = 4 * MIB
            size_worker_budget = 2
        elif file_size < 2 * GIB:
            size_band = "medium"
            recommended_batch = 50_000
            recommended_buffer = 8 * MIB
            size_worker_budget = 2
        elif file_size < 20 * GIB:
            size_band = "large"
            recommended_batch = 50_000
            recommended_buffer = 8 * MIB
            size_worker_budget = 2
        else:
            size_band = "very-large"
            recommended_batch = 100_000 if available_memory >= 8 * GIB else 50_000
            recommended_buffer = 16 * MIB
            size_worker_budget = 4

        batch_records = batch_override or min(recommended_batch, max_batch_records)
        read_buffer_bytes = buffer_override or recommended_buffer
        memory_worker_budget = max(1, 1 + (available_memory - 4 * GIB) // (4 * GIB))
        cpu_worker_budget = max(1, cpu_count // 4)
        worker_limit = min(size_worker_budget, memory_worker_budget, cpu_worker_budget, max_parser_workers)
        parser_workers = worker_override or worker_limit
        name = f"{size_band}-file"
        reason = (
            f"{size_band} source profile; {cpu_count} logical CPUs and "
            f"{available_memory / GIB:.1f} GiB currently available; "
            f"worker count capped for memory headroom."
        )

    return IngestionProfile(
        name=name,
        batch_records=min(max(1, int(batch_records)), max_batch_records),
        parser_workers=min(max(1, int(parser_workers)), max_parser_workers, cpu_count),
        read_buffer_bytes=max(1 * MIB, int(read_buffer_bytes)),
        reason=reason,
    )
