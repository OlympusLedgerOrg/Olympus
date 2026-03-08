"""Golden vector regression coverage for JCS canonicalization hardening."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from protocol.canonicalizer import CanonicalizationError, Canonicalizer


_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_vectors.tsv"
)
_REJECTED_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_rejected.tsv"
)


def _load_positive_vectors() -> list[tuple[str, bytes, bytes, str]]:
    rows: list[tuple[str, bytes, bytes, str]] = []
    for line in _VECTORS_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        group_id, input_hex, canonical_hex, hash_hex = line.split("\t")
        rows.append((group_id, bytes.fromhex(input_hex), bytes.fromhex(canonical_hex), hash_hex))
    return rows


def _load_negative_vectors() -> list[tuple[str, bytes, str]]:
    rows: list[tuple[str, bytes, str]] = []
    for line in _REJECTED_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        description, input_hex, error_substring = line.split("\t")
        rows.append((description, bytes.fromhex(input_hex), error_substring))
    return rows


def test_positive_canonicalizer_vector_count() -> None:
    rows = _load_positive_vectors()
    assert len(rows) >= 500


def test_positive_canonicalizer_vectors_match_expected_output_and_hash() -> None:
    rows = _load_positive_vectors()
    grouped_outputs: dict[str, set[bytes]] = defaultdict(set)
    grouped_hashes: dict[str, set[str]] = defaultdict(set)

    for group_id, raw_input, canonical_bytes, hash_hex in rows:
        result = Canonicalizer.json_jcs(raw_input)
        assert result == canonical_bytes
        assert Canonicalizer.get_hash(result).hex() == hash_hex
        grouped_outputs[group_id].add(result)
        grouped_hashes[group_id].add(hash_hex)

    assert all(len(outputs) == 1 for outputs in grouped_outputs.values())
    assert all(len(hashes) == 1 for hashes in grouped_hashes.values())


@pytest.mark.parametrize(("description", "raw_input", "error_substring"), _load_negative_vectors())
def test_negative_canonicalizer_vectors_are_rejected(
    description: str, raw_input: bytes, error_substring: str
) -> None:
    with pytest.raises(CanonicalizationError, match=error_substring):
        Canonicalizer.json_jcs(raw_input)
