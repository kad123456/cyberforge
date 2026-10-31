import json
from pathlib import Path
import pytest

from backend.ingestion.reader import (
    stream_bounded_batches,
    stream_jsonl_records,
    stream_records,
)


def test_streaming_reader_preserves_records_and_offsets(tmp_path: Path):
    test_file = tmp_path / "test.jsonl"
    records = [
        {"@timestamp": "2026-01-01T00:00:00Z", "event": {"id": f"evt-{i}", "category": "test"}, "data": "x" * (i * 100)}
        for i in range(50)
    ]
    lines = [json.dumps(r) + "\n" for r in records]
    test_file.write_text("".join(lines), encoding="utf-8")

    read_records = []
    offsets = []
    for line_num, byte_offset, raw in stream_jsonl_records(test_file):
        read_records.append(json.loads(raw))
        offsets.append((line_num, byte_offset))

    assert len(read_records) == 50
    assert read_records[0]["event"]["id"] == "evt-0"
    assert read_records[-1]["event"]["id"] == "evt-49"
    assert offsets[-1][1] == test_file.stat().st_size
    assert offsets[-1][0] == 50


def test_streaming_reader_resumes_from_exact_offset(tmp_path: Path):
    test_file = tmp_path / "test_resume.jsonl"
    records = [{"event": {"id": f"evt-{i}"}} for i in range(20)]
    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    all_items = list(stream_jsonl_records(test_file))
    midpoint_line, midpoint_offset, _ = all_items[9]  # After 10 items (index 9)

    # Resume from midpoint
    resumed_items = list(stream_jsonl_records(test_file, start_offset=midpoint_offset, start_line=midpoint_line))
    assert len(resumed_items) == 10
    assert json.loads(resumed_items[0][2])["event"]["id"] == "evt-10"
    assert json.loads(resumed_items[-1][2])["event"]["id"] == "evt-19"
    assert resumed_items[-1][1] == test_file.stat().st_size


def test_streaming_reader_handles_large_individual_record(tmp_path: Path):
    test_file = tmp_path / "large_record.jsonl"
    large_payload = "A" * (2 * 1024 * 1024)  # 2 MB in one single JSON record
    records = [
        {"event": {"id": "small-1"}},
        {"event": {"id": "large-2"}, "payload": large_payload},
        {"event": {"id": "small-3"}},
    ]
    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    items = list(stream_jsonl_records(test_file))
    assert len(items) == 3
    loaded_large = json.loads(items[1][2])
    assert loaded_large["event"]["id"] == "large-2"
    assert len(loaded_large["payload"]) == 2 * 1024 * 1024


def test_stream_bounded_batches(tmp_path: Path):
    test_file = tmp_path / "batches.jsonl"
    records = [{"event": {"id": f"batch-{i}"}} for i in range(25)]
    test_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    batches = list(stream_bounded_batches(test_file, batch_size=10))
    # 25 records with batch_size 10 -> batches of 10, 10, 5
    assert len(batches) == 3
    assert len(batches[0][0]) == 10
    assert len(batches[1][0]) == 10
    assert len(batches[2][0]) == 5
    assert batches[2][1] == test_file.stat().st_size
