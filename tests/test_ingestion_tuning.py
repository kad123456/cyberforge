from backend.ingestion.reader import stream_jsonl_records
from backend.ingestion.tuning import GIB, MIB, select_ingestion_profile


def test_reader_keeps_offsets_across_buffer_boundaries(tmp_path):
    source = tmp_path / "boundary.jsonl"
    content = b'{"a":1}\n\n{"b":2}\r\nlast'
    source.write_bytes(content)

    records = list(stream_jsonl_records(source, buffer_bytes=5))

    assert records == [
        (1, 8, b'{"a":1}\n'),
        (2, 9, b"\n"),
        (3, 18, b'{"b":2}\r\n'),
        (4, 22, b"last"),
    ]


def test_profile_scales_workers_with_large_files_and_memory():
    constrained = select_ingestion_profile(
        8 * GIB,
        cpu_count=16,
        available_memory_bytes=2 * GIB,
    )
    available = select_ingestion_profile(
        8 * GIB,
        cpu_count=16,
        available_memory_bytes=12 * GIB,
    )
    very_large = select_ingestion_profile(
        24 * GIB,
        cpu_count=16,
        available_memory_bytes=20 * GIB,
    )

    assert constrained.parser_workers == 1
    assert available.parser_workers == 2
    assert available.batch_records == 50_000
    assert very_large.parser_workers == 4
    assert very_large.batch_records == 100_000
    assert very_large.read_buffer_bytes == 16 * MIB


def test_explicit_profile_overrides_are_respected():
    profile = select_ingestion_profile(
        24 * GIB,
        cpu_count=16,
        available_memory_bytes=24 * GIB,
        max_batch_records=100_000,
        max_parser_workers=8,
        batch_override=25_000,
        worker_override=2,
        buffer_override=8 * MIB,
    )

    assert profile.batch_records == 25_000
    assert profile.parser_workers == 2
    assert profile.read_buffer_bytes == 8 * MIB


def test_disabling_auto_tuning_uses_safe_fixed_defaults():
    profile = select_ingestion_profile(
        24 * GIB,
        cpu_count=16,
        available_memory_bytes=24 * GIB,
        enabled=False,
    )

    assert profile.batch_records == 50_000
    assert profile.parser_workers == 1
    assert profile.read_buffer_bytes == 4 * MIB
