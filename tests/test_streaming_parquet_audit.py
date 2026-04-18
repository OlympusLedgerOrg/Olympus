"""
Tests for streaming canonicalization, deterministic Parquet writer,
and audit metadata tracking.

Covers:
- Streaming JSONL external merge sort canonicalization
- Streaming CSV canonicalization
- Content-Defined Chunking (CDC) with Buzhash
- Deterministic Parquet writer (fixed row-group, sort, compression)
- Audit metadata log with chain verification
- Data catalog entry generation
"""

import io
import json
import os
import tempfile
from pathlib import Path

import pytest

from protocol.streaming import (
    CDCChunk,
    CDCResult,
    StreamingCsvResult,
    StreamingJsonlResult,
    canonicalize_csv_streaming,
    canonicalize_jsonl_streaming,
    cdc_from_file,
    content_defined_chunking,
)

# ---------------------------------------------------------------------------
# Streaming JSONL canonicalizer
# ---------------------------------------------------------------------------


class TestStreamingJsonl:
    """Tests for canonicalize_jsonl_streaming()."""

    def test_basic_sort_and_canonicalize(self, tmp_path: Path) -> None:
        """Records are canonicalized and sorted lexicographically."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"

        # Write unsorted records
        inp.write_text(
            '{"z": 1, "a": 2}\n'
            '{"b": 10, "a": 5}\n'
            '{"a": 1, "b": 3}\n',
            encoding="utf-8",
        )

        result = canonicalize_jsonl_streaming(inp, out)

        assert isinstance(result, StreamingJsonlResult)
        assert result.record_count == 3
        assert len(result.blake3_hex) == 64  # 32-byte hex digest

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3

        # Each line should be canonical JSON (sorted keys, compact)
        for line in lines:
            obj = json.loads(line)
            assert list(obj.keys()) == sorted(obj.keys())

        # Lines should be in sorted order
        assert lines == sorted(lines)

    def test_sort_by_key(self, tmp_path: Path) -> None:
        """Records are sorted by a specified top-level field."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"

        inp.write_text(
            '{"id": "charlie", "val": 3}\n'
            '{"id": "alice", "val": 1}\n'
            '{"id": "bob", "val": 2}\n',
            encoding="utf-8",
        )

        result = canonicalize_jsonl_streaming(inp, out, sort_key="id")

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        ids = [json.loads(line)["id"] for line in lines]
        assert ids == ["alice", "bob", "charlie"]

    def test_whitespace_normalization(self, tmp_path: Path) -> None:
        """String values have whitespace normalized."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"

        inp.write_text(
            '{"name": "  Hello   World  "}\n',
            encoding="utf-8",
        )

        canonicalize_jsonl_streaming(inp, out)

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        obj = json.loads(lines[0])
        assert obj["name"] == "Hello World"

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        """Blank lines in input are silently skipped."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"

        inp.write_text(
            '{"a": 1}\n\n\n{"b": 2}\n\n',
            encoding="utf-8",
        )

        result = canonicalize_jsonl_streaming(inp, out)
        assert result.record_count == 2

    def test_deterministic_hash(self, tmp_path: Path) -> None:
        """Same input produces same hash across runs."""
        inp = tmp_path / "input.jsonl"
        out1 = tmp_path / "out1.jsonl"
        out2 = tmp_path / "out2.jsonl"

        inp.write_text(
            '{"x": 1}\n{"y": 2}\n',
            encoding="utf-8",
        )

        r1 = canonicalize_jsonl_streaming(inp, out1)
        r2 = canonicalize_jsonl_streaming(inp, out2)

        assert r1.blake3_hex == r2.blake3_hex
        assert out1.read_text() == out2.read_text()

    def test_external_sort_spill(self, tmp_path: Path) -> None:
        """When chunk_mem is small, records spill to disk and are merged."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"

        # Write enough records to force multiple spills with tiny chunk_mem
        records = [json.dumps({"id": f"{i:04d}"}) for i in range(100, 0, -1)]
        inp.write_text("\n".join(records) + "\n", encoding="utf-8")

        result = canonicalize_jsonl_streaming(
            inp, out, chunk_mem=200  # tiny buffer → many spills
        )

        assert result.record_count == 100
        lines = out.read_text(encoding="utf-8").strip().split("\n")
        ids = [json.loads(line)["id"] for line in lines]
        # Should be sorted (lexicographic matches numeric for zero-padded)
        assert ids == sorted(ids)

    def test_empty_input(self, tmp_path: Path) -> None:
        """Empty file produces zero records."""
        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"
        inp.write_text("", encoding="utf-8")

        result = canonicalize_jsonl_streaming(inp, out)
        assert result.record_count == 0

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON raises CanonicalizationError."""
        from protocol.canonicalizer import CanonicalizationError

        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"
        inp.write_text("not valid json\n", encoding="utf-8")

        with pytest.raises(CanonicalizationError, match="Invalid JSON"):
            canonicalize_jsonl_streaming(inp, out)

    def test_non_dict_raises(self, tmp_path: Path) -> None:
        """Non-object JSON records raise CanonicalizationError."""
        from protocol.canonicalizer import CanonicalizationError

        inp = tmp_path / "input.jsonl"
        out = tmp_path / "output.jsonl"
        inp.write_text("[1, 2, 3]\n", encoding="utf-8")

        with pytest.raises(CanonicalizationError, match="must be JSON objects"):
            canonicalize_jsonl_streaming(inp, out)


# ---------------------------------------------------------------------------
# Streaming CSV canonicalizer
# ---------------------------------------------------------------------------


class TestStreamingCsv:
    """Tests for canonicalize_csv_streaming()."""

    def test_basic_sort(self, tmp_path: Path) -> None:
        """Data rows are sorted; header preserved."""
        inp = tmp_path / "input.csv"
        out = tmp_path / "output.csv"

        inp.write_text("name,age\nBob,30\nAlice,25\n", encoding="utf-8")

        result = canonicalize_csv_streaming(inp, out)

        assert isinstance(result, StreamingCsvResult)
        assert result.record_count == 2

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert lines[0] == "name,age"
        assert lines[1] == "Alice,25"
        assert lines[2] == "Bob,30"

    def test_bom_stripped(self, tmp_path: Path) -> None:
        """BOM is stripped from the input."""
        inp = tmp_path / "input.csv"
        out = tmp_path / "output.csv"

        inp.write_text("\ufeffname,age\nAlice,25\n", encoding="utf-8")

        canonicalize_csv_streaming(inp, out)

        content = out.read_text(encoding="utf-8")
        assert not content.startswith("\ufeff")

    def test_crlf_normalized(self, tmp_path: Path) -> None:
        """CRLF line endings are normalized."""
        inp = tmp_path / "input.csv"
        out = tmp_path / "output.csv"

        inp.write_text("name,age\r\nAlice,25\r\nBob,30\r\n", encoding="utf-8")

        canonicalize_csv_streaming(inp, out)

        content = out.read_text(encoding="utf-8")
        assert "\r" not in content

    def test_no_sort(self, tmp_path: Path) -> None:
        """sort_rows=False preserves original order."""
        inp = tmp_path / "input.csv"
        out = tmp_path / "output.csv"

        inp.write_text("name,age\nZoe,20\nAlice,25\n", encoding="utf-8")

        canonicalize_csv_streaming(inp, out, sort_rows=False)

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert lines[1] == "Zoe,20"

    def test_tsv_input(self, tmp_path: Path) -> None:
        """TSV input is normalized to comma-delimited output."""
        inp = tmp_path / "input.tsv"
        out = tmp_path / "output.csv"

        inp.write_text("name\tage\nAlice\t25\n", encoding="utf-8")

        canonicalize_csv_streaming(inp, out, delimiter="\t")

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert lines[0] == "name,age"

    def test_deterministic(self, tmp_path: Path) -> None:
        """Same input produces same hash."""
        inp = tmp_path / "input.csv"
        out1 = tmp_path / "out1.csv"
        out2 = tmp_path / "out2.csv"

        inp.write_text("name,age\nBob,30\nAlice,25\n", encoding="utf-8")

        r1 = canonicalize_csv_streaming(inp, out1)
        r2 = canonicalize_csv_streaming(inp, out2)

        assert r1.blake3_hex == r2.blake3_hex

    def test_empty_raises(self, tmp_path: Path) -> None:
        """Empty CSV raises CanonicalizationError."""
        from protocol.canonicalizer import CanonicalizationError

        inp = tmp_path / "input.csv"
        out = tmp_path / "output.csv"
        inp.write_text("", encoding="utf-8")

        with pytest.raises(CanonicalizationError, match="empty"):
            canonicalize_csv_streaming(inp, out)


# ---------------------------------------------------------------------------
# Content-Defined Chunking (CDC)
# ---------------------------------------------------------------------------


class TestCDC:
    """Tests for content_defined_chunking() and cdc_from_file()."""

    def test_basic_chunking(self) -> None:
        """A non-empty stream produces at least one chunk."""
        data = os.urandom(100_000)
        stream = io.BytesIO(data)

        result = content_defined_chunking(
            stream, min_chunk=1024, avg_chunk=4096, max_chunk=16384
        )

        assert isinstance(result, CDCResult)
        assert result.total_bytes == len(data)
        assert len(result.chunks) >= 1
        assert len(result.combined_blake3_hex) == 64

        # Chunks should cover entire input
        total = sum(c.length for c in result.chunks)
        assert total == len(data)

        # Offsets should be contiguous
        expected_offset = 0
        for chunk in result.chunks:
            assert chunk.offset == expected_offset
            expected_offset += chunk.length

    def test_max_chunk_enforced(self) -> None:
        """No chunk exceeds max_chunk."""
        data = os.urandom(200_000)
        max_chunk = 8192
        result = content_defined_chunking(
            io.BytesIO(data), min_chunk=256, avg_chunk=2048, max_chunk=max_chunk
        )

        for chunk in result.chunks:
            assert chunk.length <= max_chunk

    def test_min_chunk_enforced(self) -> None:
        """No chunk (except possibly the last) is smaller than min_chunk."""
        data = os.urandom(200_000)
        min_chunk = 1024
        result = content_defined_chunking(
            io.BytesIO(data), min_chunk=min_chunk, avg_chunk=4096, max_chunk=16384
        )

        for chunk in result.chunks[:-1]:  # last chunk may be shorter
            assert chunk.length >= min_chunk

    def test_deterministic(self) -> None:
        """Same data produces same chunks."""
        data = os.urandom(50_000)

        r1 = content_defined_chunking(
            io.BytesIO(data), min_chunk=512, avg_chunk=2048, max_chunk=8192
        )
        r2 = content_defined_chunking(
            io.BytesIO(data), min_chunk=512, avg_chunk=2048, max_chunk=8192
        )

        assert r1.combined_blake3_hex == r2.combined_blake3_hex
        assert len(r1.chunks) == len(r2.chunks)
        for c1, c2 in zip(r1.chunks, r2.chunks):
            assert c1.offset == c2.offset
            assert c1.length == c2.length
            assert c1.blake3_hex == c2.blake3_hex

    def test_insertion_locality(self) -> None:
        """Inserting data in the middle only changes nearby chunk hashes."""
        base = b"A" * 10_000 + b"B" * 10_000 + b"C" * 10_000
        modified = b"A" * 10_000 + b"X" * 100 + b"B" * 10_000 + b"C" * 10_000

        r1 = content_defined_chunking(
            io.BytesIO(base), min_chunk=256, avg_chunk=1024, max_chunk=4096
        )
        r2 = content_defined_chunking(
            io.BytesIO(modified), min_chunk=256, avg_chunk=1024, max_chunk=4096
        )

        # At least some chunks should be different, but not all
        hashes1 = {c.blake3_hex for c in r1.chunks}
        hashes2 = {c.blake3_hex for c in r2.chunks}
        # The tail chunks (over "C" * 10_000) should overlap
        common = hashes1 & hashes2
        assert len(common) > 0, "CDC should preserve some chunk hashes after local edit"

    def test_empty_stream(self) -> None:
        """Empty stream produces no chunks."""
        result = content_defined_chunking(io.BytesIO(b""))
        assert result.total_bytes == 0
        assert len(result.chunks) == 0

    def test_cdc_from_file(self, tmp_path: Path) -> None:
        """cdc_from_file convenience wrapper works."""
        f = tmp_path / "testfile.bin"
        data = os.urandom(50_000)
        f.write_bytes(data)

        result = cdc_from_file(
            f, min_chunk=512, avg_chunk=2048, max_chunk=8192
        )

        assert result.total_bytes == len(data)
        assert len(result.chunks) >= 1

    def test_invalid_params(self) -> None:
        """Invalid chunk size parameters raise ValueError."""
        with pytest.raises(ValueError, match="min_chunk"):
            content_defined_chunking(io.BytesIO(b"x"), min_chunk=0)

        with pytest.raises(ValueError, match="avg_chunk"):
            content_defined_chunking(
                io.BytesIO(b"x"), min_chunk=100, avg_chunk=50
            )

        with pytest.raises(ValueError, match="max_chunk"):
            content_defined_chunking(
                io.BytesIO(b"x"), min_chunk=100, avg_chunk=200, max_chunk=100
            )


# ---------------------------------------------------------------------------
# Deterministic Parquet writer
# ---------------------------------------------------------------------------


class TestDeterministicParquet:
    """Tests for write_deterministic_parquet() and verify_parquet_determinism()."""

    @pytest.fixture(autouse=True)
    def _check_pyarrow(self) -> None:
        pytest.importorskip("pyarrow")

    def test_basic_write(self, tmp_path: Path) -> None:
        """Write and read back a simple Parquet file."""
        import pyarrow.parquet as pq

        from protocol.parquet_writer import ParquetWriteResult, write_deterministic_parquet

        data = [
            {"id": 3, "name": "charlie"},
            {"id": 1, "name": "alice"},
            {"id": 2, "name": "bob"},
        ]
        out = tmp_path / "test.parquet"

        result = write_deterministic_parquet(
            data, out, sort_columns=["id"], row_group_size=2
        )

        assert isinstance(result, ParquetWriteResult)
        assert result.row_count == 3
        assert result.row_group_count == 2  # 2 + 1 rows
        assert result.file_size_bytes > 0
        assert len(result.blake3_hex) == 64

        # Read back and verify sort order
        table = pq.read_table(str(out))
        ids = table.column("id").to_pylist()
        assert ids == [1, 2, 3]

    def test_deterministic_output(self, tmp_path: Path) -> None:
        """Same data + settings produce identical files."""
        from protocol.parquet_writer import (
            verify_parquet_determinism,
            write_deterministic_parquet,
        )

        data = [
            {"id": i, "value": f"val_{i}"}
            for i in range(50)
        ]

        out1 = tmp_path / "out1.parquet"
        out2 = tmp_path / "out2.parquet"

        r1 = write_deterministic_parquet(data, out1, sort_columns=["id"])
        r2 = write_deterministic_parquet(data, out2, sort_columns=["id"])

        assert r1.blake3_hex == r2.blake3_hex
        assert verify_parquet_determinism(out1, out2)

    def test_column_order_deterministic(self, tmp_path: Path) -> None:
        """Columns are always written in alphabetical order."""
        import pyarrow.parquet as pq

        from protocol.parquet_writer import write_deterministic_parquet

        data = [{"z_col": 1, "a_col": 2, "m_col": 3}]
        out = tmp_path / "test.parquet"

        write_deterministic_parquet(data, out)

        table = pq.read_table(str(out))
        assert table.column_names == ["a_col", "m_col", "z_col"]

    def test_empty_data_raises(self, tmp_path: Path) -> None:
        """Empty input raises ValueError."""
        from protocol.parquet_writer import write_deterministic_parquet

        with pytest.raises(ValueError, match="empty"):
            write_deterministic_parquet([], tmp_path / "test.parquet")

    def test_invalid_sort_column_raises(self, tmp_path: Path) -> None:
        """Non-existent sort column raises ValueError."""
        from protocol.parquet_writer import write_deterministic_parquet

        data = [{"id": 1}]
        with pytest.raises(ValueError, match="Sort column"):
            write_deterministic_parquet(
                data, tmp_path / "test.parquet", sort_columns=["nonexistent"]
            )

    def test_pyarrow_table_input(self, tmp_path: Path) -> None:
        """pyarrow Table input works."""
        import pyarrow as pa

        from protocol.parquet_writer import write_deterministic_parquet

        table = pa.table({"id": [3, 1, 2], "name": ["c", "a", "b"]})
        out = tmp_path / "test.parquet"

        result = write_deterministic_parquet(
            table, out, sort_columns=["id"]
        )

        assert result.row_count == 3


# ---------------------------------------------------------------------------
# Audit metadata tracking
# ---------------------------------------------------------------------------


class TestAuditMetadata:
    """Tests for AuditLog and catalog entry creation."""

    def test_record_and_verify(self, tmp_path: Path) -> None:
        """Record entries and verify chain integrity."""
        from protocol.audit_metadata import AuditEntry, AuditLog

        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path, operator="test-operator")

        e1 = log.record(
            format_name="application/json",
            input_hash="a" * 64,
            output_hash="b" * 64,
        )
        assert isinstance(e1, AuditEntry)
        assert e1.operator == "test-operator"
        assert e1.previous_hash == ""
        assert len(e1.entry_hash) == 64

        e2 = log.record(
            format_name="text/html",
            input_hash="c" * 64,
            output_hash="d" * 64,
        )
        assert e2.previous_hash == e1.entry_hash

        # Verify chain
        valid, count, msg = log.verify_chain()
        assert valid is True
        assert count == 2
        assert "valid" in msg.lower()

    def test_chain_persists_across_instances(self, tmp_path: Path) -> None:
        """Chain linkage survives log file re-open."""
        from protocol.audit_metadata import AuditLog

        log_path = tmp_path / "audit.jsonl"

        log1 = AuditLog(log_path, operator="op1")
        e1 = log1.record(
            format_name="jcs", input_hash="a" * 64, output_hash="b" * 64
        )

        # Re-open
        log2 = AuditLog(log_path, operator="op2")
        e2 = log2.record(
            format_name="html", input_hash="c" * 64, output_hash="d" * 64
        )

        assert e2.previous_hash == e1.entry_hash

        valid, count, _ = log2.verify_chain()
        assert valid is True
        assert count == 2

    def test_tampered_chain_detected(self, tmp_path: Path) -> None:
        """Tampering with an entry breaks chain verification."""
        from protocol.audit_metadata import AuditLog

        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path, operator="test")

        log.record(
            format_name="jcs", input_hash="a" * 64, output_hash="b" * 64
        )
        log.record(
            format_name="html", input_hash="c" * 64, output_hash="d" * 64
        )

        # Tamper with the first entry by changing the input_hash value
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["input_hash"] = "f" * 64  # change a data field
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, count, msg = AuditLog(log_path).verify_chain()
        assert valid is False
        assert "mismatch" in msg.lower() or "break" in msg.lower()

    def test_empty_log_valid(self, tmp_path: Path) -> None:
        """An empty or non-existent log is considered valid."""
        from protocol.audit_metadata import AuditLog

        log = AuditLog(tmp_path / "nonexistent.jsonl")
        valid, count, _ = log.verify_chain()
        assert valid is True
        assert count == 0

    def test_metadata_in_entry(self, tmp_path: Path) -> None:
        """Extra metadata is stored in the entry."""
        from protocol.audit_metadata import AuditLog

        log = AuditLog(tmp_path / "audit.jsonl", operator="test")
        entry = log.record(
            format_name="csv",
            input_hash="a" * 64,
            output_hash="b" * 64,
            metadata={"dataset": "budget_2025", "source": "foia"},
        )

        assert entry.metadata["dataset"] == "budget_2025"

    def test_catalog_entry(self) -> None:
        """create_catalog_entry produces a well-formed catalog record."""
        from protocol.audit_metadata import create_catalog_entry

        entry = create_catalog_entry(
            dataset_name="test_dataset",
            format_name="application/json",
            input_hash="a" * 64,
            output_hash="b" * 64,
            operator="tester",
            tags={"department": "treasury"},
        )

        assert entry["dataset_name"] == "test_dataset"
        assert entry["format"] == "application/json"
        assert entry["input_hash"] == "a" * 64
        assert entry["output_hash"] == "b" * 64
        assert entry["operator"] == "tester"
        assert entry["tags"]["department"] == "treasury"
        assert "version_manifest" in entry
        assert "timestamp" in entry

    def test_version_resolution(self) -> None:
        """_resolve_version maps MIME types to canonicalizer versions."""
        from protocol.audit_metadata import _resolve_version

        assert _resolve_version("application/json") != "unknown"
        assert _resolve_version("text/html") != "unknown"
        assert _resolve_version("text/plain") != "unknown"
        assert _resolve_version("text/csv") != "unknown"
        assert _resolve_version("jcs") != "unknown"
        assert _resolve_version("totally-unknown-format") == "unknown"
