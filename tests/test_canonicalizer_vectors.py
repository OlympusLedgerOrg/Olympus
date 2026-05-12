"""Golden vector regression coverage for JCS canonicalization hardening."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from protocol.canonical import document_to_bytes, document_to_commit_bytes
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
_DISTINCT_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_distinct.tsv"
)
_SPACE_EQUIV_PATH = (
    Path(__file__).resolve().parent.parent
    / "verifiers"
    / "test_vectors"
    / "canonicalizer_space_equiv.tsv"
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


def _load_distinct_vectors() -> list[tuple[str, bytes, bytes, str]]:
    rows: list[tuple[str, bytes, bytes, str]] = []
    for line in _DISTINCT_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        description, left_hex, right_hex, reason = line.split("\t")
        rows.append((description, bytes.fromhex(left_hex), bytes.fromhex(right_hex), reason))
    return rows


def _load_space_equiv_vectors() -> list[tuple[str, bytes, bytes, str]]:
    rows: list[tuple[str, bytes, bytes, str]] = []
    for line in _SPACE_EQUIV_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        description, unicode_hex, ascii_hex, reason = line.split("\t")
        rows.append((description, bytes.fromhex(unicode_hex), bytes.fromhex(ascii_hex), reason))
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

    for group_id, outputs in grouped_outputs.items():
        assert len(outputs) == 1, f"group {group_id} produced multiple canonical outputs"
    for group_id, hashes in grouped_hashes.items():
        assert len(hashes) == 1, f"group {group_id} produced multiple canonical hashes"


@pytest.mark.parametrize(("description", "left_input", "right_input", "reason"), _load_distinct_vectors())
def test_distinct_canonicalizer_vectors_do_not_collapse(
    description: str, left_input: bytes, right_input: bytes, reason: str
) -> None:
    left_obj = json.loads(left_input)
    right_obj = json.loads(right_input)
    left = Canonicalizer.json_jcs(left_input)
    right = Canonicalizer.json_jcs(right_input)

    assert left != right, f"{description} collapsed canonical bytes: {reason}"
    assert Canonicalizer.get_hash(left) != Canonicalizer.get_hash(right), (
        f"{description} collided canonical hashes: {reason}"
    )

    left_commit = document_to_commit_bytes(left_obj)
    right_commit = document_to_commit_bytes(right_obj)
    assert left_commit != right_commit, (
        f"{description} collapsed commitment canonical bytes: {reason}"
    )
    assert Canonicalizer.get_hash(left_commit) != Canonicalizer.get_hash(right_commit), (
        f"{description} collided commitment canonical hashes: {reason}"
    )


@pytest.mark.parametrize(
    ("description", "unicode_input", "ascii_input", "reason"), _load_space_equiv_vectors()
)
def test_unicode_space_equivalence_vectors_map_to_ascii_space(
    description: str, unicode_input: bytes, ascii_input: bytes, reason: str
) -> None:
    unicode_doc = json.loads(unicode_input.decode("utf-8"))
    ascii_doc = json.loads(ascii_input.decode("utf-8"))
    left = document_to_bytes(unicode_doc, normalize_unicode_spaces=True)
    right = document_to_bytes(ascii_doc, normalize_unicode_spaces=True)

    assert left == right, f"{description} did not map to ASCII space: {reason}"
    assert Canonicalizer.get_hash(left) == Canonicalizer.get_hash(right), (
        f"{description} produced a different hash after space folding: {reason}"
    )


@pytest.mark.parametrize(("description", "raw_input", "error_substring"), _load_negative_vectors())
def test_negative_canonicalizer_vectors_are_rejected(
    description: str, raw_input: bytes, error_substring: str
) -> None:
    with pytest.raises(CanonicalizationError, match=error_substring):
        Canonicalizer.json_jcs(raw_input)
