"""
Tests for canonical JSON key ordering with non-BMP (supplementary-plane) characters.

RFC 8785 §3.2.3 requires object keys to be sorted by their UTF-16 code-unit
sequence, not by Unicode scalar (code-point) order.  For all characters in the
Basic Multilingual Plane (U+0000–U+FFFF) the two orderings are identical.
They diverge for supplementary-plane characters (U+10000+): those characters
encode as a surrogate pair in UTF-16 (high surrogate 0xD800–0xDBFF followed by
low surrogate 0xDC00–0xDFFF).  Because 0xD800 < 0xE000, a supplementary-plane
key sorts *before* a U+E000–U+FFFF BMP key in UTF-16 order, but *after* it in
scalar order.

The four golden vectors exercised here are the same vectors stored in
tests/conformance/vectors.json and covered by the Rust unit tests in
services/cdhs-smf-rust/src/canonicalization.rs.  Any divergence between the
Python output and those pre-computed hex values is a consensus bug.

Cross-reference: tests/test_canonicalizer_vectors.py runs all 768 vectors in
verifiers/test_vectors/canonicalizer_vectors.tsv through Canonicalizer.json_jcs()
and confirms they are unchanged; that file is the authoritative regression guard
for the full BMP key-ordering surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from protocol.canonical_json import canonical_json_bytes, canonical_json_encode
from protocol.canonicalizer import Canonicalizer

_VECTORS_PATH = Path(__file__).resolve().parent / "conformance" / "vectors.json"


def _load_non_bmp_vectors() -> list[dict]:
    data = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    return data["canonical_json_non_bmp"]


# ---------------------------------------------------------------------------
# Parameterised golden-vector tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", _load_non_bmp_vectors(), ids=lambda v: v["id"])
def test_non_bmp_canonical_hex_matches_golden(vector: dict) -> None:
    """Canonical bytes must match the pre-computed golden hex value."""
    obj = json.loads(vector["input_json"])
    canonical = canonical_json_bytes(obj)
    assert canonical.hex() == vector["canonical_hex"], (
        f"[{vector['id']}] canonical bytes diverge from golden vector.\n"
        f"  got : {canonical.hex()}\n"
        f"  want: {vector['canonical_hex']}\n"
        f"  This is a consensus bug: cross-language verifiers will reject this hash."
    )


@pytest.mark.parametrize("vector", _load_non_bmp_vectors(), ids=lambda v: v["id"])
def test_non_bmp_blake3_matches_golden(vector: dict) -> None:
    """BLAKE3(canonical bytes) must match the pre-computed golden hash."""
    obj = json.loads(vector["input_json"])
    canonical = canonical_json_bytes(obj)
    got = Canonicalizer.get_hash(canonical).hex()
    assert got == vector["blake3_hex"], (
        f"[{vector['id']}] BLAKE3 hash diverges from golden vector.\n"
        f"  got : {got}\n"
        f"  want: {vector['blake3_hex']}\n"
        f"  This is a consensus bug: the SMT leaf hash will not match across languages."
    )


# ---------------------------------------------------------------------------
# Ordering assertions — make the UTF-16 vs scalar divergence explicit
# ---------------------------------------------------------------------------


def test_supplementary_key_sorts_before_upper_bmp_utf16() -> None:
    """A supplementary-plane key must sort *before* a U+E000–U+FFFF BMP key.

    In UTF-16 the high surrogate for U+10000 is 0xD800, which is numerically
    less than U+E000 (0xE000).  Scalar order would place U+10000 *after*
    U+FFFF, reversing the result.
    """
    obj = {"\uE000": "pua", "\U00010000": "first-supp"}
    encoded = canonical_json_encode(obj)
    # 𐀀 (U+10000) must appear first: {"𐀀":"first-supp","\uE000":"pua"}
    first_key_end = encoded.index(":")
    first_key = encoded[1:first_key_end]
    assert "\U00010000" in first_key, (
        f"U+10000 must sort before U+E000 under UTF-16 order, but got: {encoded!r}"
    )


def test_emoji_key_sorts_before_upper_bmp_utf16() -> None:
    """U+1F980 (🦀, high surrogate 0xD83E) sorts before U+E000 (0xE000)."""
    obj = {"\uE000": "pua", "\U0001F980": "crab"}
    encoded = canonical_json_encode(obj)
    first_key_end = encoded.index(":")
    first_key = encoded[1:first_key_end]
    assert "\U0001F980" in first_key, (
        f"🦀 (U+1F980) must sort before U+E000 under UTF-16 order, but got: {encoded!r}"
    )


def test_non_bmp_3_mixed_key_order() -> None:
    """non-bmp-3: all four keys must appear in UTF-16 order a < b < 𐐷 < 🦀."""
    obj = {"a": 1, "\U00010437": 2, "b": 3, "\U0001F980": 4}
    encoded = canonical_json_encode(obj)
    # Extract key order from the encoded string
    parsed_back = json.loads(encoded)
    keys = list(parsed_back.keys())
    assert keys == ["a", "b", "\U00010437", "\U0001F980"], (
        f"Expected UTF-16 key order [a, b, 𐐷, 🦀], got {keys!r}"
    )


def test_non_bmp_4_bmp_boundary_key_order() -> None:
    """non-bmp-4: UTF-16 sort must produce 𐀀 < U+E000 < U+FFFD."""
    obj = {"\uE000": "pua", "\uFFFD": "replacement", "\U00010000": "first-supp"}
    encoded = canonical_json_encode(obj)
    parsed_back = json.loads(encoded)
    keys = list(parsed_back.keys())
    assert keys == ["\U00010000", "\uE000", "\uFFFD"], (
        f"Expected UTF-16 key order [U+10000, U+E000, U+FFFD], got {keys!r}"
    )


def test_bmp_only_keys_unaffected() -> None:
    """BMP-only keys must still be sorted the same way under UTF-16 and scalar order."""
    obj = {"z": 1, "a": 2, "m": 3}
    assert canonical_json_encode(obj) == '{"a":2,"m":3,"z":1}'
