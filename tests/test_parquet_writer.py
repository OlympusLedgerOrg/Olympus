"""Tests for protocol.parquet_writer — deterministic Parquet output.

All tests are skipped automatically when pyarrow is not installed.
Install it with: pip install pyarrow
"""

from __future__ import annotations

from pathlib import Path

import pytest


try:
    import pyarrow as pa
    import pyarrow.parquet as pq

    _PYARROW_AVAILABLE = True
except ImportError:
    _PYARROW_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _PYARROW_AVAILABLE,
    reason="pyarrow not installed",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_records(n: int = 5) -> list[dict]:
    return [
        {
            "id": i,
            "name": f"record-{i}",
            "value": float(i) * 1.5,
        }
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# write_deterministic_parquet — basic functionality
# ---------------------------------------------------------------------------


class TestWriteDeterministicParquet:
    def test_write_from_list_of_dicts(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = _make_records(10)
        result = write_deterministic_parquet(records, tmp_path / "out.parquet")

        assert result.row_count == 10
        assert result.row_group_count == 1
        assert result.file_size_bytes > 0
        assert len(result.blake3_hex) == 64
        assert result.compression == "zstd"

    def test_write_from_pyarrow_table(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        table = pa.table({"x": [1, 2, 3], "y": ["a", "b", "c"]})
        result = write_deterministic_parquet(table, tmp_path / "out.parquet")

        assert result.row_count == 3
        assert result.row_group_count == 1
        assert result.file_size_bytes > 0

    def test_sort_columns_applied(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = [{"id": 3, "val": "c"}, {"id": 1, "val": "a"}, {"id": 2, "val": "b"}]
        result = write_deterministic_parquet(
            records, tmp_path / "out.parquet", sort_columns=["id"]
        )
        assert result.sort_columns == ["id"]

        # Read back and verify sort order
        out = pq.read_table(str(tmp_path / "out.parquet"))
        assert out.column("id").to_pylist() == [1, 2, 3]

    def test_column_order_is_alphabetical(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = [{"z": 1, "a": 2, "m": 3}]
        write_deterministic_parquet(records, tmp_path / "out.parquet")

        out = pq.read_table(str(tmp_path / "out.parquet"))
        assert out.column_names == ["a", "m", "z"]

    def test_row_groups_split_correctly(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = _make_records(25)
        result = write_deterministic_parquet(
            records, tmp_path / "out.parquet", row_group_size=10
        )
        assert result.row_count == 25
        assert result.row_group_count == 3  # ceil(25/10)

    def test_custom_compression(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = _make_records(5)
        result = write_deterministic_parquet(
            records, tmp_path / "out.parquet", compression="snappy"
        )
        assert result.compression == "snappy"

    def test_created_by_metadata_is_fixed(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import WRITER_CREATED_BY, write_deterministic_parquet

        records = _make_records(3)
        write_deterministic_parquet(records, tmp_path / "out.parquet")

        pf = pq.ParquetFile(str(tmp_path / "out.parquet"))
        schema_meta = pf.schema_arrow.metadata or {}
        assert schema_meta.get(b"created_by") == WRITER_CREATED_BY.encode("utf-8")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_identical_hash_on_repeated_write(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = _make_records(20)
        r1 = write_deterministic_parquet(records, tmp_path / "a.parquet", sort_columns=["id"])
        r2 = write_deterministic_parquet(records, tmp_path / "b.parquet", sort_columns=["id"])

        assert r1.blake3_hex == r2.blake3_hex

    def test_different_row_order_same_hash_when_sorted(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records_fwd = list(range(10))
        records_rev = list(reversed(range(10)))

        dicts_fwd = [{"id": i} for i in records_fwd]
        dicts_rev = [{"id": i} for i in records_rev]

        r1 = write_deterministic_parquet(dicts_fwd, tmp_path / "fwd.parquet", sort_columns=["id"])
        r2 = write_deterministic_parquet(dicts_rev, tmp_path / "rev.parquet", sort_columns=["id"])

        assert r1.blake3_hex == r2.blake3_hex

    def test_different_input_different_hash(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        r1 = write_deterministic_parquet(
            _make_records(5), tmp_path / "a.parquet", sort_columns=["id"]
        )
        r2 = write_deterministic_parquet(
            _make_records(6), tmp_path / "b.parquet", sort_columns=["id"]
        )

        assert r1.blake3_hex != r2.blake3_hex


# ---------------------------------------------------------------------------
# verify_parquet_determinism
# ---------------------------------------------------------------------------


class TestVerifyParquetDeterminism:
    def test_identical_files_return_true(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import verify_parquet_determinism, write_deterministic_parquet

        records = _make_records(5)
        write_deterministic_parquet(records, tmp_path / "a.parquet", sort_columns=["id"])
        write_deterministic_parquet(records, tmp_path / "b.parquet", sort_columns=["id"])

        assert verify_parquet_determinism(tmp_path / "a.parquet", tmp_path / "b.parquet")

    def test_different_files_return_false(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import verify_parquet_determinism, write_deterministic_parquet

        write_deterministic_parquet(_make_records(5), tmp_path / "a.parquet")
        write_deterministic_parquet(_make_records(6), tmp_path / "b.parquet")

        assert not verify_parquet_determinism(tmp_path / "a.parquet", tmp_path / "b.parquet")


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestErrorCases:
    def test_empty_list_raises_value_error(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        with pytest.raises(ValueError, match="empty"):
            write_deterministic_parquet([], tmp_path / "out.parquet")

    def test_empty_table_raises_value_error(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        empty = pa.table({"x": pa.array([], type=pa.int32())})
        with pytest.raises(ValueError, match="empty"):
            write_deterministic_parquet(empty, tmp_path / "out.parquet")

    def test_invalid_sort_column_raises_value_error(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        records = _make_records(3)
        with pytest.raises(ValueError, match="nonexistent"):
            write_deterministic_parquet(
                records, tmp_path / "out.parquet", sort_columns=["nonexistent"]
            )

    def test_unsupported_type_raises_type_error(self, tmp_path: Path) -> None:
        from protocol.parquet_writer import write_deterministic_parquet

        with pytest.raises(TypeError):
            write_deterministic_parquet("not-a-table", tmp_path / "out.parquet")  # type: ignore[arg-type]

    def test_pyarrow_not_available_raises_import_error(self) -> None:
        from protocol import parquet_writer as pw_module

        orig = pw_module._PYARROW_AVAILABLE
        pw_module._PYARROW_AVAILABLE = False
        try:
            with pytest.raises(ImportError, match="pyarrow"):
                pw_module._ensure_pyarrow()
        finally:
            pw_module._PYARROW_AVAILABLE = orig
