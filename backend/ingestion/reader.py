from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Iterator

from backend.config import BATCH_SIZE, CHUNK_SIZE_BYTES, READ_BUFFER_BYTES


def stream_jsonl_records(
    path: str | Path,
    *,
    start_offset: int = 0,
    start_line: int = 0,
    end_offset: int | None = None,
    buffer_bytes: int = READ_BUFFER_BYTES,
) -> Iterator[tuple[int, int, bytes]]:
    """Yield raw JSONL bytes one record at a time with exact line number and byte offset.

    Uses a buffered binary stream with bounded C-level buffer so the entire file
    is NEVER loaded into memory. Byte offsets are exact and stable across restarts.
    Handles large individual records safely and ends strictly on complete line boundaries.
    """
    file_path = Path(path)
    buffer_size = max(1024 * 1024, buffer_bytes)
    with file_path.open("rb", buffering=buffer_size) as source:
        if start_offset > 0:
            source.seek(start_offset)
        byte_offset = start_offset
        line_number = start_line

        while True:
            if end_offset is not None and byte_offset >= end_offset:
                break
            line = source.readline()
            if not line:
                break
            byte_offset += len(line)
            line_number += 1
            yield line_number, byte_offset, line


def stream_records(
    path: str | Path,
    *,
    start_offset: int = 0,
    start_line: int = 0,
    end_offset: int | None = None,
    buffer_bytes: int = READ_BUFFER_BYTES,
) -> Iterator[tuple[int, int, str]]:
    """Yield decoded text lines with their 1-based line number and end byte offset."""
    for line_number, byte_offset, raw in stream_jsonl_records(
        path,
        start_offset=start_offset,
        start_line=start_line,
        end_offset=end_offset,
        buffer_bytes=buffer_bytes,
    ):
        yield line_number, byte_offset, raw.decode("utf-8", errors="replace")


def stream_lines(path: str | Path) -> Iterator[tuple[int, str]]:
    """Backward-compatible line iterator that skips blank records."""
    for line_number, _, line in stream_records(path):
        if line.strip():
            yield line_number, line


class _DecodedLines:
    """Track byte offsets while csv.reader consumes possibly multiline rows."""

    def __init__(self, source: io.BufferedReader, initial_offset: int = 0, initial_line: int = 0):
        self.source = source
        self.byte_offset = initial_offset
        self.line_number = initial_line

    def __iter__(self):
        return self

    def __next__(self) -> str:
        raw = self.source.readline()
        if not raw:
            raise StopIteration
        self.byte_offset += len(raw)
        self.line_number += 1
        return raw.decode("utf-8-sig" if self.line_number == 1 else "utf-8", errors="replace")


def stream_csv_records(
    path: str | Path,
    *,
    start_offset: int = 0,
    start_line: int = 0,
    delimiter: str = ",",
    buffer_bytes: int = READ_BUFFER_BYTES,
) -> Iterator[tuple[int, int, dict[str, str]]]:
    """Stream CSV rows, retaining the header and supporting resume at row edges.

    CSV quoted fields may span physical lines. Checkpoints therefore use the
    byte position after a complete logical row. The header is reread on resume.
    """
    buffer_size = max(1024 * 1024, buffer_bytes)
    with Path(path).open("rb", buffering=buffer_size) as source:
        lines = _DecodedLines(source)
        reader = csv.reader(lines, delimiter=delimiter, strict=True)
        try:
            header = next(reader)
        except StopIteration:
            return
        header = [name.strip() for name in header]
        if not any(header):
            raise ValueError("CSV input has an empty header row")
        if start_offset > 0:
            source.seek(start_offset)
            lines.line_number = start_line
            lines.byte_offset = start_offset
        reader = csv.reader(lines, delimiter=delimiter, strict=True)
        while True:
            try:
                values = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                line_number = lines.line_number
                yield line_number, lines.byte_offset, {"__parse_error__": str(exc)}
                reader = csv.reader(lines, delimiter=delimiter, strict=True)
                continue
            line_number = lines.line_number
            if not values or not any(value.strip() for value in values):
                yield line_number, lines.byte_offset, {}
                continue
            if len(values) != len(header):
                yield line_number, lines.byte_offset, {"__parse_error__": f"expected {len(header)} fields, got {len(values)}"}
                continue
            yield line_number, lines.byte_offset, dict(zip(header, values))


def stream_bounded_batches(
    path: str | Path,
    *,
    batch_size: int = BATCH_SIZE,
    chunk_size_bytes: int = CHUNK_SIZE_BYTES,
    start_offset: int = 0,
    start_line: int = 0,
) -> Iterator[tuple[list[tuple[int, int, bytes]], int, int]]:
    """Yield bounded batches of raw records that strictly end on complete line boundaries.

    Each yielded item is (batch_records, end_byte_offset, end_line_number).
    A batch is emitted when either batch_size records are collected or chunk_size_bytes
    of raw data have been accumulated, ensuring bounded RAM usage.
    """
    batch: list[tuple[int, int, bytes]] = []
    accumulated_bytes = 0
    latest_offset = start_offset
    latest_line = start_line

    for line_number, byte_offset, raw in stream_jsonl_records(
        path,
        start_offset=start_offset,
        start_line=start_line,
        buffer_bytes=min(chunk_size_bytes, 8 * 1024 * 1024),
    ):
        latest_offset = byte_offset
        latest_line = line_number
        if raw.strip():
            batch.append((line_number, byte_offset, raw))
            accumulated_bytes += len(raw)

        if len(batch) >= batch_size or accumulated_bytes >= chunk_size_bytes:
            yield batch, latest_offset, latest_line
            batch = []
            accumulated_bytes = 0

    if batch:
        yield batch, latest_offset, latest_line
