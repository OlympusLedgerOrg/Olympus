"""
Cross-language conformance tests for canonical JSON key ordering.

Loads tests/conformance/vectors.json and asserts that the Python reference
implementation produces byte-for-byte identical canonical bytes and BLAKE3
hashes for every vector.

This file also cross-references the 768 existing vectors in
verifiers/test_vectors/canonicalizer_vectors.tsv to confirm that the UTF-16
sort fix did not regress any previously passing vector (the TSV vectors are
the full regression surface and are exercised by test_canonicalizer_vectors.py;
this test guards the *count* so a silent truncation of that file is caught).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from protocol.canonical_json import canonical_json_bytes
from protocol.canonicalizer import Canonicalizer

_CONFORMANCE_VECTORS_PATH = (
    Path(__file__).resolve().parent / "conformance" / "vectors.json"
)
_TSV_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_vectors.tsv"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_conformance_vectors() -> list[dict]:
    data = json.loads(_CONFORMANCE_VECTORS_PATH.read_text(encoding="utf-8"))
    return data["canonical_json_non_bmp"]


def _load_tsv_vectors() -> list[tuple[str, bytes, bytes, str]]:
    rows: list[tuple[str, bytes, bytes, str]] = []
    for line in _TSV_VECTORS_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        group_id, input_hex, canonical_hex, hash_hex = line.split("\t")
        rows.append(
            (group_id, bytes.fromhex(input_hex), bytes.fromhex(canonical_hex), hash_hex)
        )
    return rows


# ---------------------------------------------------------------------------
# Non-BMP conformance vectors (tests/conformance/vectors.json)
# ---------------------------------------------------------------------------


def test_conformance_vectors_file_is_present_and_parseable() -> None:
    """vectors.json must exist and contain at least the 4 non-BMP vectors."""
    vectors = _load_conformance_vectors()
    assert len(vectors) >= 4, (
        f"Expected at least 4 non-BMP vectors, found {len(vectors)}"
    )


def test_conformance_vectors_canonical_hex() -> None:
    """Python canonical_json_bytes must match canonical_hex for every vector."""
    vectors = _load_conformance_vectors()
    failures: list[str] = []
    for v in vectors:
        obj = json.loads(v["input_json"])
        canonical = canonical_json_bytes(obj)
        if canonical.hex() != v["canonical_hex"]:
            failures.append(
                f"[{v['id']}] canonical mismatch\n"
                f"  got : {canonical.hex()}\n"
                f"  want: {v['canonical_hex']}"
            )
    assert not failures, (
        "canonical_hex mismatch — cross-language consensus broken:\n"
        + "\n".join(failures)
    )


def test_conformance_vectors_blake3_hex() -> None:
    """BLAKE3(canonical bytes) must match blake3_hex for every vector."""
    vectors = _load_conformance_vectors()
    failures: list[str] = []
    for v in vectors:
        obj = json.loads(v["input_json"])
        canonical = canonical_json_bytes(obj)
        got = Canonicalizer.get_hash(canonical).hex()
        if got != v["blake3_hex"]:
            failures.append(
                f"[{v['id']}] BLAKE3 mismatch\n"
                f"  got : {got}\n"
                f"  want: {v['blake3_hex']}"
            )
    assert not failures, (
        "BLAKE3 mismatch — SMT leaf hashes will diverge across languages:\n"
        + "\n".join(failures)
    )


def test_conformance_vectors_input_hex_roundtrip() -> None:
    """input_hex must decode to valid UTF-8 that re-encodes to input_json."""
    vectors = _load_conformance_vectors()
    for v in vectors:
        decoded = bytes.fromhex(v["input_hex"]).decode("utf-8")
        assert decoded == v["input_json"], (
            f"[{v['id']}] input_hex decodes to {decoded!r}, "
            f"expected {v['input_json']!r}"
        )


# ---------------------------------------------------------------------------
# Cross-reference: 768 existing TSV vectors must still all pass
# ---------------------------------------------------------------------------


def test_existing_tsv_vector_count_unchanged() -> None:
    """The TSV must still contain at least 768 vectors (do not silently truncate)."""
    rows = _load_tsv_vectors()
    assert len(rows) >= 768, (
        f"Expected >= 768 TSV vectors but found {len(rows)}. "
        "Do not remove existing conformance vectors."
    )


def test_existing_tsv_vectors_all_pass() -> None:
    """All 768+ existing TSV vectors must still produce correct canonical bytes and hashes.

    This is the primary regression guard confirming the UTF-16 sort fix did not
    change the output for any previously correct vector.
    """
    rows = _load_tsv_vectors()
    grouped_outputs: dict[str, set[bytes]] = defaultdict(set)
    failures: list[str] = []

    for group_id, raw_input, canonical_bytes, hash_hex in rows:
        result = Canonicalizer.json_jcs(raw_input)
        if result != canonical_bytes:
            failures.append(
                f"[{group_id}] canonical mismatch\n"
                f"  got : {result.hex()}\n"
                f"  want: {canonical_bytes.hex()}"
            )
            continue
        if Canonicalizer.get_hash(result).hex() != hash_hex:
            failures.append(
                f"[{group_id}] BLAKE3 mismatch\n"
                f"  got : {Canonicalizer.get_hash(result).hex()}\n"
                f"  want: {hash_hex}"
            )
        grouped_outputs[group_id].add(result)

    assert not failures, (
        f"{len(failures)} existing TSV vector(s) now fail — regression introduced:\n"
        + "\n".join(failures[:10])
        + ("\n  (truncated)" if len(failures) > 10 else "")
    )

    for group_id, outputs in grouped_outputs.items():
        assert len(outputs) == 1, (
            f"group {group_id!r} now produces multiple canonical outputs — "
            "the sort is no longer deterministic for this group"
        )
