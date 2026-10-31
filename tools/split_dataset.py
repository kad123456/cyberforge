#!/usr/bin/env python3
"""Dataset Partitioner Tool for ChainSight AI.

Splits large security datasets (JSONL, CEF, FortiGate) into exact line-boundary
partitions without corrupting records, and supports:
1. Extracting a specific partition (e.g. Part 1 of 7) to disk.
2. Ingesting any partition directly into ChainSight AI without duplicating file storage.
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ingestion.storage import Storage
from backend.ingestion.service import IngestionService


def compute_line_partitions(path: Path, num_partitions: int = 7) -> list[tuple[int, int]]:
    """Compute exact byte offset ranges aligned to newline boundaries."""
    total_size = path.stat().st_size
    step = total_size // num_partitions
    offsets = [0]
    with path.open("rb") as f:
        for i in range(1, num_partitions):
            target = i * step
            f.seek(target)
            _ = f.readline()  # advance to next newline boundary
            offsets.append(f.tell())
    offsets.append(total_size)
    return [(offsets[i], offsets[i + 1]) for i in range(num_partitions)]


def extract_part(path: Path, part_idx: int, num_partitions: int, output_path: Path):
    """Extract a single partition to a standalone file."""
    partitions = compute_line_partitions(path, num_partitions)
    if part_idx < 1 or part_idx > num_partitions:
        raise ValueError(f"Part must be between 1 and {num_partitions}")

    start_offset, end_offset = partitions[part_idx - 1]
    bytes_to_read = end_offset - start_offset
    mb = bytes_to_read / (1024 * 1024)

    print(f"Extracting Part {part_idx}/{num_partitions} ({mb:.1f} MB)...")
    print(f"Offsets: {start_offset:,} to {end_offset:,}")

    t0 = time.perf_counter()
    with path.open("rb") as src, output_path.open("wb") as dst:
        src.seek(start_offset)
        remaining = bytes_to_read
        buf_size = 4 * 1024 * 1024
        while remaining > 0:
            chunk = src.read(min(remaining, buf_size))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
    t1 = time.perf_counter()
    print(f"Extracted to: {output_path} in {t1 - t0:.2f}s")


def main():
    parser = argparse.ArgumentParser(description="ChainSight AI Dataset Partitioner")
    parser.add_argument("file", type=Path, help="Path to large log file")
    parser.add_argument("--parts", type=int, default=7, help="Number of partitions (default: 7)")
    parser.add_argument("--extract-part", type=int, default=None, help="Extract part number (1-based)")
    parser.add_argument("--output", type=Path, default=None, help="Output path for extracted part")
    parser.add_argument("--info-only", action="store_true", help="Print partition boundaries without extracting")

    args = parser.parse_args()
    if not args.file.exists():
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    partitions = compute_line_partitions(args.file, args.parts)
    print(f"\n--- {args.file.name} Partition Plan ({args.parts} Parts) ---")
    for idx, (start, end) in enumerate(partitions):
        mb = (end - start) / (1024 * 1024)
        print(f"  Part {idx + 1:2d}: {start:12,d} -> {end:12,d} ({mb:6.1f} MB)")

    if args.info_only:
        return

    if args.extract_part is not None:
        out = args.output or args.file.with_name(f"{args.file.stem}_part{args.extract_part}{args.file.suffix}")
        extract_part(args.file, args.extract_part, args.parts, out)


if __name__ == "__main__":
    main()
