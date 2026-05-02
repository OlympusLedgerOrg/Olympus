"""
Deterministic Parquet writer for Olympus.

Produces byte-identical Parquet files across runs and machines by enforcing:

1. **Fixed row-group size** — every row group contains exactly
   ``row_group_size`` rows (the final group may be smaller).
2. **Primary-key sort** — data is sorted by a caller-specified column (or
   set of columns) before writing, guaranteeing deterministic row order.
3. **Standardized compression** — uses a fixed codec (Zstd level 3 by
   default) so that the compressed output is identical on every machine.
4. **Deterministic metadata** — ``created_by`` and other file-level
   metadata are fixed strings, not environment-dependent.

The writer accepts either an Arrow :class:`pyarrow.Table` or a list of
Python dicts and produces a ``.parquet`` file whose BLAKE3 hash is
reproducible.

.. note::

   This module requires ``pyarrow``.  If pyarrow is not installed, importing
   the module will raise :class:`ImportError`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import blake3 as _blake3


try:
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq

    _PYARROW_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYARROW_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_ROW_GROUP_SIZE: int = 1_000_000
"""Default number of rows per row group."""

DEFAULT_COMPRESSION: str = "zstd"
"""Default compression codec."""

DEFAULT_COMPRESSION_LEVEL: int = 3
"""Default Zstd compression level (deterministic across platforms)."""

# Codecs that accept a compression_level parameter.
# Snappy, lz4, and uncompressed reject the level parameter in PyArrow.
_LEVEL_AWARE_CODECS: frozenset[str] = frozenset({"zstd", "gzip", "brotli"})

# Valid compression_level ranges per level-aware codec.
# Passing a level outside these bounds raises ArrowInvalid in PyArrow.
# brotli quality is 0-11 (NOT 0-22 like zstd); guard against callers
# passing zstd-style levels to brotli by accident.
_CODEC_LEVEL_RANGES: dict[str, tuple[int, int]] = {
    "zstd": (1, 22),
    "gzip": (1, 9),
    "brotli": (0, 11),
}

WRITER_CREATED_BY: str = "olympus-deterministic-parquet-writer/1.0"
"""Fixed ``created_by`` metadata for reproducibility."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ParquetWriteResult:
    """Metadata returned after writing a deterministic Parquet file."""

    row_count: int
    """Total number of rows written."""

    row_group_count: int
    """Number of row groups in the file."""

    file_size_bytes: int
    """Size of the output file in bytes."""

    blake3_hex: str
    """BLAKE3 hash of the output file."""

    sort_columns: list[str] = field(default_factory=list)
    """Columns used for sorting."""

    compression: str = DEFAULT_COMPRESSION
    """Compression codec used."""

    compression_level: int | None = DEFAULT_COMPRESSION_LEVEL
    """Compression level used, or ``None`` for codecs that do not support levels."""


def _ensure_pyarrow() -> None:
    """Raise if pyarrow is not available."""
    if not _PYARROW_AVAILABLE:
        raise ImportError(
            "pyarrow is required for deterministic Parquet writing.  "
            "Install it with: pip install pyarrow"
        )


def _dicts_to_table(records: Sequence[dict[str, Any]]) -> pa.Table:
    """Convert a list of flat dicts to a pyarrow Table.

    All values are inferred by pyarrow; the caller should ensure
    consistent typing across records.

    Args:
        records: List of dictionaries with identical key sets.

    Returns:
        pyarrow Table.

    Raises:
        ValueError: If *records* is empty.
    """
    if not records:
        raise ValueError("Cannot create Parquet from empty record list")

    # Use sorted column order for determinism
    columns = sorted(records[0].keys())
    arrays = {}
    for col in columns:
        arrays[col] = [rec.get(col) for rec in records]

    return pa.table(arrays)


def write_deterministic_parquet(
    data: Any,
    output_path: str | Path,
    *,
    sort_columns: Sequence[str] | None = None,
    row_group_size: int = DEFAULT_ROW_GROUP_SIZE,
    compression: str = DEFAULT_COMPRESSION,
    compression_level: int = DEFAULT_COMPRESSION_LEVEL,
) -> ParquetWriteResult:
    """Write data to a deterministic Parquet file.

    The output is byte-identical across runs when given the same input,
    sort columns, row-group size, and compression settings.

    Args:
        data: Either a ``pyarrow.Table`` or a ``list[dict]``.
        output_path: Destination file path.
        sort_columns: Column name(s) used to sort rows before writing.
            If ``None``, rows are written in their existing order (the
            caller is responsible for pre-sorting).
        row_group_size: Number of rows per row group.
        compression: Compression codec name (e.g. ``"zstd"``, ``"snappy"``).
        compression_level: Compression level (codec-dependent).

    Returns:
        :class:`ParquetWriteResult` with file metadata and hash.

    Raises:
        ImportError: If pyarrow is not installed.
        ValueError: If *data* is empty, *sort_columns* reference non-existent
            columns, or *compression_level* is out of range for the codec.
    """
    _ensure_pyarrow()

    output_path = Path(output_path)

    # Coerce input to pyarrow Table
    if isinstance(data, list):
        table = _dicts_to_table(data)
    elif _PYARROW_AVAILABLE and isinstance(data, pa.Table):
        table = data
    else:
        raise ValueError(
            f"data must be a pyarrow.Table or list[dict], got {type(data).__name__}"
        )

    if table.num_rows == 0:
        raise ValueError("Cannot write an empty table to Parquet")

    # Validate sort columns
    sort_cols: list[str] = list(sort_columns) if sort_columns else []
    for col in sort_cols:
        if col not in table.column_names:
            raise ValueError(
                f"Sort column '{col}' not found in table columns: {table.column_names}"
            )

    # Sort table
    if sort_cols:
        sort_keys = [(col, "ascending") for col in sort_cols]
        indices = pc.sort_indices(table, sort_keys=sort_keys)
        table = table.take(indices)

    # Ensure deterministic column order (alphabetical)
    ordered_names = sorted(table.column_names)
    if list(table.column_names) != ordered_names:
        table = table.select(ordered_names)

    # Write Parquet with fixed settings
    # Set deterministic file-level metadata via the schema
    file_metadata = {
        b"created_by": WRITER_CREATED_BY.encode("utf-8"),
    }
    schema_with_meta = table.schema.with_metadata(file_metadata)

    writer_kwargs: dict = {
        "compression": compression,
        "version": "2.6",
        "write_statistics": True,
    }
    # Only pass compression_level for codecs that support it.
    # Snappy, lz4, and uncompressed ignore/reject the level parameter in PyArrow.
    effective_level: int | None = (
        compression_level if compression.lower() in _LEVEL_AWARE_CODECS else None
    )
    if effective_level is not None:
        # Validate the level is within the codec's accepted range before
        # passing it to PyArrow — catches e.g. a zstd-style level=15 being
        # passed to brotli (max 11) which would raise ArrowInvalid at runtime.
        codec_key = compression.lower()
        if codec_key in _CODEC_LEVEL_RANGES:
            lo, hi = _CODEC_LEVEL_RANGES[codec_key]
            if not (lo <= effective_level <= hi):
                raise ValueError(
                    f"compression_level {effective_level} is out of range "
                    f"[{lo}, {hi}] for codec '{compression}'"
                )
        writer_kwargs["compression_level"] = effective_level

    writer = pq.ParquetWriter(str(output_path), schema_with_meta, **writer_kwargs)

    try:
        # Write in fixed-size row groups
        total_rows = table.num_rows
        row_groups = 0
        offset = 0
        while offset < total_rows:
            end = min(offset + row_group_size, total_rows)
            group = table.slice(offset, end - offset)
            writer.write_table(group)
            row_groups += 1
            offset = end
    finally:
        writer.close()

    # Compute file hash
    hasher = _blake3.blake3()
    with output_path.open("rb") as fh:
        while True:
            block = fh.read(1 << 20)  # 1 MiB
            if not block:
                break
            hasher.update(block)

    return ParquetWriteResult(
        row_count=total_rows,
        row_group_count=row_groups,
        file_size_bytes=output_path.stat().st_size,
        blake3_hex=hasher.hexdigest(),
        sort_columns=sort_cols,
        compression=compression,
        compression_level=effective_level,
    )


def verify_parquet_determinism(
    path_a: str | Path,
    path_b: str | Path,
) -> bool:
    """Verify that two Parquet files are byte-identical.

    Args:
        path_a: First file.
        path_b: Second file.

    Returns:
        ``True`` if both files have the same BLAKE3 hash.
    """ 

    def _hash_file(path: str | Path) -> str:
        hasher = _blake3.blake3()
        with open(path, "rb") as fh:
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                hasher.update(block)
        return hasher.hexdigest()

    return _hash_file(path_a) == _hash_file(path_b)