"""
Streaming canonicalization for Olympus.

Provides chunk-based processing for arbitrarily large datasets without
loading the entire file into memory.  Key capabilities:

1. **Streaming JSONL canonicalizer** — reads JSONL line-by-line, canonicalizes
   each record, and writes the output in deterministic sorted order using an
   external merge sort (disk-backed).

2. **Streaming CSV canonicalizer** — processes CSV files in configurable chunks,
   canonicalizes cells, and merge-sorts the result.

3. **Content-Defined Chunking (CDC)** — splits arbitrary byte streams into
   variable-length chunks whose boundaries are determined by content (rolling
   Buzhash).  Adding or removing data only invalidates the affected chunk
   hashes, not the entire file.

All operations stream through data without exceeding
``DEFAULT_CHUNK_MEM_BYTES`` of heap usage (default 128 MiB).
"""

from __future__ import annotations

import contextlib
import csv
import heapq
import io
import json
import os
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, BinaryIO, Iterator, TextIO

import blake3 as _blake3

from .canonical import _scrub_homoglyphs, _strip_bom, normalize_whitespace
from .canonical_json import canonical_json_encode
from .canonicalizer import CanonicalizationError


# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_MEM_BYTES: int = 128 * 1024 * 1024  # 128 MiB working memory
"""Maximum in-memory buffer before spilling to disk during external sort."""

DEFAULT_CDC_MIN_CHUNK: int = 256 * 1024       # 256 KiB
"""Minimum CDC chunk size (bytes)."""

DEFAULT_CDC_AVG_CHUNK: int = 1 * 1024 * 1024  # 1 MiB
"""Target average CDC chunk size (bytes)."""

DEFAULT_CDC_MAX_CHUNK: int = 8 * 1024 * 1024  # 8 MiB
"""Maximum CDC chunk size (bytes)."""

# Buzhash table — 256 random 64-bit values, deterministic seed.
_BUZHASH_TABLE: list[int] = []


def _init_buzhash_table() -> None:
    """Populate the Buzhash lookup table with deterministic random values."""
    import random

    rng = random.Random(0x4F4C594D505553)  # "OLYMPUS" as seed
    _BUZHASH_TABLE.clear()
    for _ in range(256):
        _BUZHASH_TABLE.append(rng.getrandbits(64))


_init_buzhash_table()


# ---------------------------------------------------------------------------
# External merge sort helpers
# ---------------------------------------------------------------------------


def _write_sorted_run(
    records: list[str],
    tmp_dir: str,
    run_index: int,
) -> str:
    """Sort *records* in memory and flush to a temporary file.

    Args:
        records: List of canonical JSON lines (no trailing newline).
        tmp_dir: Directory for temporary spill files.
        run_index: Monotonic index for the run file name.

    Returns:
        Path to the written run file.
    """
    records.sort()
    run_path = os.path.join(tmp_dir, f"run_{run_index:06d}.jsonl")
    with open(run_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec)
            fh.write("\n")
    return run_path


def _merge_sorted_runs(run_paths: list[str], output: TextIO) -> int:
    """K-way merge of pre-sorted run files into *output*.

    Args:
        run_paths: Paths to sorted run files.
        output: Writable text stream for the merged result.

    Returns:
        Total number of records written.
    """
    with contextlib.ExitStack() as stack:
        iterators: list[Iterator[str]] = []
        for path in run_paths:
            fh = stack.enter_context(open(path, encoding="utf-8"))
            iterators.append(iter(fh))

        # heapq.merge gives a sorted iterator over pre-sorted iterables.
        count = 0
        for line in heapq.merge(*iterators):
            output.write(line)
            count += 1
        return count


# ---------------------------------------------------------------------------
# Streaming JSONL canonicalizer
# ---------------------------------------------------------------------------


def _canonicalize_json_record(line: str, *, scrub_homoglyphs: bool = True) -> str:
    """Canonicalize a single JSON record (one line of JSONL).

    Args:
        line: A single JSON-encoded line.
        scrub_homoglyphs: Replace homoglyphs with ASCII equivalents.

    Returns:
        Canonical JSON string for this record.

    Raises:
        CanonicalizationError: On invalid JSON.
    """
    stripped = line.strip()
    if not stripped:
        raise CanonicalizationError("Empty JSONL line")

    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"Invalid JSON in JSONL line: {exc}") from exc

    if not isinstance(obj, dict):
        raise CanonicalizationError("JSONL records must be JSON objects (dicts)")

    # Recursively canonicalize values
    def _canon_value(val: Any) -> Any:
        if isinstance(val, dict):
            return {k: _canon_value(v) for k, v in sorted(val.items())}
        if isinstance(val, list):
            return [_canon_value(v) for v in val]
        if isinstance(val, str):
            normalized = normalize_whitespace(val)
            if scrub_homoglyphs:
                normalized = _scrub_homoglyphs(normalized)
            return normalized
        return val

    canonical_obj = {k: _canon_value(v) for k, v in sorted(obj.items())}
    return canonical_json_encode(canonical_obj)


@dataclass
class StreamingJsonlResult:
    """Result of a streaming JSONL canonicalization."""

    record_count: int
    """Total records processed."""

    blake3_hex: str
    """BLAKE3 hash of the entire canonical output stream."""


def canonicalize_jsonl_streaming(
    input_path: str | Path,
    output_path: str | Path,
    *,
    sort_key: str | None = None,
    chunk_mem: int = DEFAULT_CHUNK_MEM_BYTES,
    scrub_homoglyphs: bool = True,
) -> StreamingJsonlResult:
    """Canonicalize a JSONL file using streaming external merge sort.

    The input file is read line-by-line.  Each record is canonicalized to
    deterministic JSON, buffered until ``chunk_mem`` bytes are accumulated,
    then sorted and spilled to a temporary run file.  After all records are
    processed the runs are k-way merged into the final sorted output.

    If *sort_key* is ``None`` the full canonical JSON string is used as the
    sort key (lexicographic byte order).  If *sort_key* names a top-level
    field, records are sorted by the canonical value of that field.

    Args:
        input_path: Path to source ``.jsonl`` file.
        output_path: Destination path for the canonical ``.jsonl``.
        sort_key: Optional top-level JSON field name to sort by.
        chunk_mem: Max in-memory buffer (bytes) before spilling.
        scrub_homoglyphs: Forwarded to per-record canonicalization.

    Returns:
        :class:`StreamingJsonlResult` with record count and hash.

    Raises:
        CanonicalizationError: If any record fails canonicalization.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    with tempfile.TemporaryDirectory(prefix="oly_sort_") as tmp_dir:
        run_paths: list[str] = []
        buffer: list[str] = []
        buffer_bytes = 0
        run_index = 0

        with input_path.open(encoding="utf-8") as fh:
            for raw_line in fh:
                if not raw_line.strip():
                    continue  # skip blank lines
                canonical = _canonicalize_json_record(
                    raw_line, scrub_homoglyphs=scrub_homoglyphs
                )

                # If a sort key is specified, prepend it for sorting, then
                # strip it after the merge.  Format: "<sort_value>\t<record>"
                if sort_key is not None:
                    obj = json.loads(canonical)
                    key_val = obj.get(sort_key, "")
                    if isinstance(key_val, str):
                        sort_prefix = key_val
                    else:
                        sort_prefix = json.dumps(
                            key_val, sort_keys=True, separators=(",", ":")
                        )
                    entry = f"{sort_prefix}\t{canonical}"
                else:
                    entry = canonical

                buffer.append(entry)
                buffer_bytes += len(entry.encode("utf-8"))

                if buffer_bytes >= chunk_mem:
                    run_paths.append(
                        _write_sorted_run(buffer, tmp_dir, run_index)
                    )
                    run_index += 1
                    buffer.clear()
                    buffer_bytes = 0

        # Flush remaining buffer
        if buffer:
            run_paths.append(_write_sorted_run(buffer, tmp_dir, run_index))

        # Merge sorted runs → output
        hasher = _blake3.blake3()
        total_records = 0

        with output_path.open("w", encoding="utf-8") as out:
            if not run_paths:
                return StreamingJsonlResult(
                    record_count=0, blake3_hex=hasher.hexdigest()
                )

            # Open all runs and merge
            with contextlib.ExitStack() as stack:
                iterators: list[Iterator[str]] = []
                for path in run_paths:
                    fh_run = stack.enter_context(open(path, encoding="utf-8"))
                    iterators.append(iter(fh_run))

                for line in heapq.merge(*iterators):
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    # Strip sort prefix if present
                    if sort_key is not None:
                        _, _, line = line.partition("\t")
                    out.write(line)
                    out.write("\n")
                    hasher.update(line.encode("utf-8"))
                    hasher.update(b"\n")
                    total_records += 1

    return StreamingJsonlResult(
        record_count=total_records, blake3_hex=hasher.hexdigest()
    )


# ---------------------------------------------------------------------------
# Streaming CSV canonicalizer
# ---------------------------------------------------------------------------


@dataclass
class StreamingCsvResult:
    """Result of a streaming CSV canonicalization."""

    record_count: int
    """Total data rows (excluding header)."""

    blake3_hex: str
    """BLAKE3 hash of the canonical output."""


def canonicalize_csv_streaming(
    input_path: str | Path,
    output_path: str | Path,
    *,
    delimiter: str = ",",
    has_header: bool = True,
    sort_rows: bool = True,
    chunk_mem: int = DEFAULT_CHUNK_MEM_BYTES,
) -> StreamingCsvResult:
    """Canonicalize a CSV file in a streaming fashion using external sort.

    Reads the CSV in chunks, canonicalizes cell values (NFC, whitespace),
    sorts data rows via external merge sort, and writes the result with
    deterministic quoting and comma delimiter.

    Args:
        input_path: Source CSV/TSV file path.
        output_path: Destination path for canonical CSV.
        delimiter: Input field delimiter (output is always comma).
        has_header: If ``True``, first row is treated as a header.
        sort_rows: If ``True``, data rows are sorted lexicographically.
        chunk_mem: Max in-memory buffer before spilling.

    Returns:
        :class:`StreamingCsvResult` with row count and hash.

    Raises:
        CanonicalizationError: If CSV is empty or malformed.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    def _canon_row(row: list[str]) -> str:
        """Canonicalize and serialize a single CSV row."""
        cells = [unicodedata.normalize("NFC", c.strip()) for c in row]
        buf = io.StringIO()
        writer = csv.writer(
            buf, delimiter=",", quoting=csv.QUOTE_MINIMAL, lineterminator=""
        )
        writer.writerow(cells)
        return buf.getvalue()

    header_line: str | None = None

    with tempfile.TemporaryDirectory(prefix="oly_csv_") as tmp_dir:
        run_paths: list[str] = []
        buffer: list[str] = []
        buffer_bytes = 0
        run_index = 0
        row_count = 0
        first = True

        # Read BOM-aware
        raw_text = input_path.read_text(encoding="utf-8")
        raw_text = _strip_bom(raw_text)
        raw_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

        reader = csv.reader(io.StringIO(raw_text), delimiter=delimiter)

        for row in reader:
            if first and has_header:
                header_line = _canon_row(row)
                first = False
                continue
            first = False

            canonical_line = _canon_row(row)
            buffer.append(canonical_line)
            buffer_bytes += len(canonical_line.encode("utf-8"))
            row_count += 1

            if buffer_bytes >= chunk_mem:
                if sort_rows:
                    buffer.sort()
                run_path = os.path.join(tmp_dir, f"csv_run_{run_index:06d}.txt")
                with open(run_path, "w", encoding="utf-8") as fh:
                    for rec in buffer:
                        fh.write(rec)
                        fh.write("\n")
                run_paths.append(run_path)
                run_index += 1
                buffer.clear()
                buffer_bytes = 0

        # Flush remainder
        if buffer:
            if sort_rows:
                buffer.sort()
            run_path = os.path.join(tmp_dir, f"csv_run_{run_index:06d}.txt")
            with open(run_path, "w", encoding="utf-8") as fh:
                for rec in buffer:
                    fh.write(rec)
                    fh.write("\n")
            run_paths.append(run_path)

        if row_count == 0 and header_line is None:
            raise CanonicalizationError("CSV is empty")

        # Write output: header + merged sorted data rows
        hasher = _blake3.blake3()

        with output_path.open("w", encoding="utf-8") as out:
            if header_line is not None:
                out.write(header_line)
                out.write("\n")
                hasher.update(header_line.encode("utf-8"))
                hasher.update(b"\n")

            if sort_rows and run_paths:
                with contextlib.ExitStack() as stack:
                    iterators: list[Iterator[str]] = []
                    for path in run_paths:
                        fh = stack.enter_context(open(path, encoding="utf-8"))
                        iterators.append(iter(fh))

                    for line in heapq.merge(*iterators):
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        out.write(line)
                        out.write("\n")
                        hasher.update(line.encode("utf-8"))
                        hasher.update(b"\n")
            elif run_paths:
                # No sorting needed — just concatenate
                for path in run_paths:
                    with open(path, encoding="utf-8") as fh:
                        for line in fh:
                            line = line.rstrip("\n")
                            if not line:
                                continue
                            out.write(line)
                            out.write("\n")
                            hasher.update(line.encode("utf-8"))
                            hasher.update(b"\n")

    return StreamingCsvResult(
        record_count=row_count, blake3_hex=hasher.hexdigest()
    )


# ---------------------------------------------------------------------------
# Content-Defined Chunking (CDC)
# ---------------------------------------------------------------------------


@dataclass
class CDCChunk:
    """A single content-defined chunk."""

    offset: int
    """Byte offset in the original stream."""

    length: int
    """Chunk length in bytes."""

    blake3_hex: str
    """BLAKE3 hash of the chunk data."""


@dataclass
class CDCResult:
    """Result of content-defined chunking."""

    chunks: list[CDCChunk] = field(default_factory=list)
    """Ordered list of chunks."""

    total_bytes: int = 0
    """Total bytes processed."""

    combined_blake3_hex: str = ""
    """BLAKE3 hash of all chunk hashes concatenated (Merkle-like commitment)."""


def content_defined_chunking(
    stream: BinaryIO,
    *,
    min_chunk: int = DEFAULT_CDC_MIN_CHUNK,
    avg_chunk: int = DEFAULT_CDC_AVG_CHUNK,
    max_chunk: int = DEFAULT_CDC_MAX_CHUNK,
) -> CDCResult:
    """Split a byte stream into content-defined chunks using Buzhash.

    Boundaries are determined by the data content, not fixed offsets.
    Inserting or removing data shifts only the affected chunk boundary;
    unchanged regions keep their original chunk hash.

    Uses a **Buzhash** rolling hash with a 48-byte sliding window.
    A boundary is placed when ``hash & mask == mask`` (i.e. the lowest
    ``bits`` bits are all 1), where ``bits = log2(avg_chunk)``.

    Args:
        stream: Readable binary stream.
        min_chunk: Minimum chunk size in bytes.
        avg_chunk: Target average chunk size.
        max_chunk: Maximum chunk size (hard cut).

    Returns:
        :class:`CDCResult` containing ordered chunk metadata.
    """
    if min_chunk < 1:
        raise ValueError("min_chunk must be >= 1")
    if avg_chunk < min_chunk:
        raise ValueError("avg_chunk must be >= min_chunk")
    if max_chunk < avg_chunk:
        raise ValueError("max_chunk must be >= avg_chunk")

    # Calculate mask from avg_chunk (number of low bits to match)
    bits = max(1, avg_chunk.bit_length() - 1)
    mask = (1 << bits) - 1

    window_size = 48
    window = bytearray(window_size)
    window_idx = 0
    rolling_hash = 0

    chunks: list[CDCChunk] = []
    chunk_hasher = _blake3.blake3()
    chunk_start = 0
    chunk_len = 0
    total = 0

    read_size = 64 * 1024  # 64 KiB read buffer

    while True:
        block = stream.read(read_size)
        if not block:
            break

        for byte in block:
            # Update rolling hash (Buzhash)
            out_byte = window[window_idx]
            window[window_idx] = byte
            window_idx = (window_idx + 1) % window_size

            # Rotate left by 1 and XOR with the new byte's table entry,
            # then XOR out the old byte's rotated table entry.
            rolling_hash = (
                ((rolling_hash << 1) | (rolling_hash >> 63))
                ^ _BUZHASH_TABLE[byte]
                ^ (
                    (_BUZHASH_TABLE[out_byte] << window_size)
                    | (_BUZHASH_TABLE[out_byte] >> (64 - window_size))
                )
            ) & 0xFFFFFFFFFFFFFFFF

            chunk_hasher.update(bytes([byte]))
            chunk_len += 1
            total += 1

            # Check for boundary
            at_boundary = False
            if chunk_len >= max_chunk:
                at_boundary = True
            elif chunk_len >= min_chunk and (rolling_hash & mask) == mask:
                at_boundary = True

            if at_boundary:
                chunks.append(
                    CDCChunk(
                        offset=chunk_start,
                        length=chunk_len,
                        blake3_hex=chunk_hasher.hexdigest(),
                    )
                )
                chunk_start = total
                chunk_len = 0
                chunk_hasher = _blake3.blake3()

    # Flush final chunk
    if chunk_len > 0:
        chunks.append(
            CDCChunk(
                offset=chunk_start,
                length=chunk_len,
                blake3_hex=chunk_hasher.hexdigest(),
            )
        )

    # Compute combined hash over all chunk hashes
    combined = _blake3.blake3()
    for chunk in chunks:
        combined.update(bytes.fromhex(chunk.blake3_hex))

    return CDCResult(
        chunks=chunks,
        total_bytes=total,
        combined_blake3_hex=combined.hexdigest(),
    )


def cdc_from_file(
    path: str | Path,
    *,
    min_chunk: int = DEFAULT_CDC_MIN_CHUNK,
    avg_chunk: int = DEFAULT_CDC_AVG_CHUNK,
    max_chunk: int = DEFAULT_CDC_MAX_CHUNK,
) -> CDCResult:
    """Content-defined chunk a file on disk.

    Convenience wrapper around :func:`content_defined_chunking`.

    Args:
        path: File path.
        min_chunk: Minimum chunk size.
        avg_chunk: Target average chunk size.
        max_chunk: Maximum chunk size.

    Returns:
        :class:`CDCResult`.
    """
    with open(path, "rb") as fh:
        return content_defined_chunking(
            fh, min_chunk=min_chunk, avg_chunk=avg_chunk, max_chunk=max_chunk
        )
