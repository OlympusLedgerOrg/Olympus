"""
Unit tests for document canonicalization.

These tests validate the canonicalize_document() function and related
canonicalization utilities in protocol/canonical.py.
"""

import pytest
from hypothesis import given, strategies as st

from protocol.canonical import (
    _scrub_homoglyphs,
    canonicalize_document,
    canonicalize_for_commit,
    canonicalize_json,
    document_to_bytes,
    document_to_commit_bytes,
    normalize_whitespace,
)
from protocol.canonicalizer import CanonicalizationError


def test_canonicalize_document_simple_dict():
    """Test canonicalization of a simple dictionary."""
    doc = {"name": "Alice", "age": 30}
    result = canonicalize_document(doc)

    # Keys should be sorted
    assert list(result.keys()) == ["age", "name"]
    assert result["name"] == "Alice"
    assert result["age"] == 30


def test_canonicalize_document_sorts_keys():
    """Test that keys are sorted alphabetically."""
    doc = {"z": 1, "a": 2, "m": 3, "b": 4}
    result = canonicalize_document(doc)

    assert list(result.keys()) == ["a", "b", "m", "z"]


def test_canonicalize_document_nested_dict():
    """Test canonicalization of nested dictionaries."""
    doc = {"outer": {"z": "last", "a": "first"}}
    result = canonicalize_document(doc)

    # Outer keys sorted
    assert list(result.keys()) == ["outer"]
    # Inner keys also sorted
    assert list(result["outer"].keys()) == ["a", "z"]


def test_canonicalize_document_preserves_string_whitespace():
    """Test that whitespace in string values is preserved exactly (CANON-2 fix).

    canonicalize_document() must NOT normalise whitespace in string values
    because {"0": " "} and {"0": ""} are semantically different documents and
    must produce different canonical hashes.  Business-level whitespace
    normalisation belongs in the caller, not in the cryptographic hash path.
    """
    doc = {"field1": "hello   world", "field2": "multiple  \t  spaces"}
    result = canonicalize_document(doc)

    assert result["field1"] == "hello   world"
    assert result["field2"] == "multiple  \t  spaces"


def test_canonicalize_document_distinguishes_empty_from_space():
    """CANON-2 regression: {"0": " "} and {"0": ""} must produce different hashes."""
    from protocol.hashes import hash_bytes

    hash_space = hash_bytes(document_to_bytes({"0": " "}))
    hash_empty = hash_bytes(document_to_bytes({"0": ""}))
    assert hash_space != hash_empty, (
        "CANON-2 regression: space and empty string produce the same hash"
    )


def test_canonicalize_document_whitespace_string_distinctions():
    """CANON-2: each distinct whitespace-containing string must hash differently."""
    from protocol.hashes import hash_bytes

    strings = ["", " ", "  ", "a", " a", "a ", "\t", "\n", " a ", "a  b", "a b"]
    hashes = [hash_bytes(document_to_bytes({"v": s})) for s in strings]
    # All must be distinct
    assert len(set(hashes)) == len(strings), (
        "CANON-2: two or more whitespace-distinct strings produced the same hash"
    )


def test_canonicalize_document_with_list():
    """Test canonicalization of documents containing lists."""
    # List items that are plain ASCII strings are unchanged.
    # NFD-form strings (e.g. "cafe\u0301") are no longer NFC-normalised by
    # canonicalize_document(); exact string values are preserved so that the
    # cryptographic hash reflects the exact bytes present in the document.
    doc = {"items": ["apple", "banana", "cherry"]}
    result = canonicalize_document(doc)

    # List order should be preserved
    assert result["items"] == ["apple", "banana", "cherry"]


def test_canonicalize_document_normalizes_nested_list_dict_strings():
    """String values in dicts nested inside lists are passed through unchanged."""
    # NFD "cafe\u0301" is no longer NFC-converted; exact values are preserved.
    doc = {"items": [{"name": "cafe\u0301"}]}
    result = canonicalize_document(doc)
    assert result["items"][0]["name"] == "cafe\u0301"


def test_canonicalize_document_list_with_dicts():
    """Test canonicalization of lists containing dictionaries."""
    doc = {"people": [{"name": "Bob", "age": 25}, {"name": "Alice", "age": 30}]}
    result = canonicalize_document(doc)

    # Each dict in the list should be canonicalized
    assert list(result["people"][0].keys()) == ["age", "name"]
    assert list(result["people"][1].keys()) == ["age", "name"]


def test_canonicalize_document_preserves_non_string_values():
    """Test that non-string values are preserved (numerics are normalized)."""
    doc = {"number": 42, "boolean": True, "null": None, "float": 3.14}
    result = canonicalize_document(doc)

    assert result["number"] == 42
    assert result["boolean"] is True
    assert result["null"] is None
    # float 3.14 is normalized to Decimal for deterministic representation
    assert float(result["float"]) == pytest.approx(3.14)


def test_canonicalize_document_rejects_non_dict():
    """Test that non-dictionary input raises ValueError."""
    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document("not a dict")

    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document([1, 2, 3])

    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document(42)


def test_canonicalize_document_rejects_non_string_keys():
    """Document keys must be strings for deterministic canonicalization."""
    with pytest.raises(ValueError, match="keys must be strings"):
        canonicalize_document({"ok": 1, 2: "bad"})


def test_canonicalize_document_empty_dict():
    """Test canonicalization of empty dictionary."""
    doc = {}
    result = canonicalize_document(doc)
    assert result == {}


def test_canonicalize_document_deeply_nested():
    """Test canonicalization of deeply nested structures."""
    doc = {"level1": {"level2": {"level3": {"z": "deep", "a": "value"}}}}
    result = canonicalize_document(doc)

    # Navigate to deep level and check sorting
    deep = result["level1"]["level2"]["level3"]
    assert list(deep.keys()) == ["a", "z"]


def test_canonicalize_document_deterministic():
    """Test that canonicalization is deterministic."""
    doc = {"z": "last", "a": "first", "nested": {"b": 2, "a": 1}}

    result1 = canonicalize_document(doc)
    result2 = canonicalize_document(doc)
    result3 = canonicalize_document(doc)

    assert result1 == result2 == result3


def test_canonicalize_document_idempotent_with_unicode():
    """Test idempotence and unicode handling in nested documents.

    canonicalize_document() is still idempotent: calling it twice on the same
    dict returns the same result.  Whitespace inside string values is preserved
    exactly (CANON-2 fix) — collapsing must be done by callers before this call.
    """
    doc = {
        "title": "Résumé   of  José",
        "meta": {"author": "Zoë  Ångström"},
        "sections": [{"heading": "Intro   🌟", "body": "Hello   world"}],
    }

    first = canonicalize_document(doc)
    second = canonicalize_document(first)

    assert first == second
    # Whitespace is preserved, not collapsed
    assert first["title"] == "Résumé   of  José"
    assert first["meta"]["author"] == "Zoë  Ångström"
    assert first["sections"][0]["heading"] == "Intro   🌟"
    assert first["sections"][0]["body"] == "Hello   world"


def test_document_to_bytes_nfc_normalised_by_canonical_json():
    """document_to_bytes produces NFC-stable output via canonical JSON NFC normalisation.

    RFC 8785 / JCS mandates NFC normalisation of all string values before
    encoding.  NFC and NFD forms of visually identical characters therefore
    produce the same canonical bytes — equivalence is preserved at the JSON
    layer, not in canonicalize_document().
    """
    precomposed = {"name": "café"}  # é = U+00E9 (NFC)
    decomposed = {"name": "cafe\u0301"}  # e + combining accent (NFD)
    # canonical_json_encode applies NFC → both map to the same bytes
    assert document_to_bytes(precomposed) == document_to_bytes(decomposed)


def test_canonicalize_json():
    """Test canonicalize_json produces canonical JSON string."""
    data = {"z": 1, "a": 2}
    result = canonicalize_json(data)

    # Should be sorted, compact, ASCII
    assert result == '{"a":2,"z":1}'


def test_document_to_bytes():
    """Test document_to_bytes produces canonical bytes.

    Keys are sorted; string values are preserved exactly (whitespace not collapsed).
    """
    doc = {"name": "Alice  Smith", "id": 123}
    result = document_to_bytes(doc)

    assert isinstance(result, bytes)
    # Keys sorted, string preserved as-is (CANON-2 fix: whitespace not collapsed)
    assert result == b'{"id":123,"name":"Alice  Smith"}'


def test_document_to_bytes_deterministic():
    """Test that document_to_bytes is deterministic."""
    doc = {"z": "value", "a": "other"}

    result1 = document_to_bytes(doc)
    result2 = document_to_bytes(doc)

    assert result1 == result2


def test_normalize_whitespace():
    """Test normalize_whitespace function."""
    # Multiple spaces
    assert normalize_whitespace("hello   world") == "hello world"

    # Leading/trailing spaces
    assert normalize_whitespace("  hello  ") == "hello"

    # Tabs
    assert normalize_whitespace("hello\tworld") == "hello world"

    # Newlines
    assert normalize_whitespace("hello\nworld") == "hello world"

    # Mixed whitespace
    assert normalize_whitespace("  hello  \t \n  world  ") == "hello world"


# ---------------------------------------------------------------------------
# H-1 security regression: commit-path canonicalization must be injective
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ascii_char, homoglyph",
    [
        ("A", "Ａ"),  # FULLWIDTH LATIN CAPITAL LETTER A
        ("B", "Ｂ"),  # FULLWIDTH LATIN CAPITAL LETTER B
        ("a", "ａ"),  # FULLWIDTH LATIN SMALL LETTER A
        ("A", "\U0001d400"),  # MATHEMATICAL BOLD CAPITAL A
        ("Z", "Ⓩ"),  # ENCLOSED ALPHANUMERIC Z (circled)
    ],
)
def test_commit_bytes_distinguishes_homoglyphs(ascii_char: str, homoglyph: str) -> None:
    """H-1: document_to_commit_bytes must produce distinct bytes for homoglyph-distinct docs.

    Homoglyph scrubbing is lossy and non-injective; enabling it in the commit
    path collapses semantically distinct documents to the same hash.
    document_to_commit_bytes() must disable scrubbing so that a document
    containing a Unicode homoglyph differs from one containing its ASCII
    equivalent.
    """
    doc_ascii = {"field": ascii_char}
    doc_homoglyph = {"field": homoglyph}

    bytes_ascii = document_to_commit_bytes(doc_ascii)
    bytes_homoglyph = document_to_commit_bytes(doc_homoglyph)

    assert bytes_ascii != bytes_homoglyph, (
        f"H-1: document_to_commit_bytes collapsed homoglyph {homoglyph!r} "
        f"(U+{ord(homoglyph):04X}) to its ASCII equivalent {ascii_char!r}"
    )


def test_canonicalize_for_commit_is_injective_on_homoglyphs() -> None:
    """H-1: canonicalize_for_commit() must not collapse homoglyphs to ASCII."""
    doc_ascii = {"text": "ABC"}
    doc_fullwidth = {"text": "ＡＢＣ"}  # Ａ Ｂ Ｃ

    result_ascii = canonicalize_for_commit(doc_ascii)
    result_fullwidth = canonicalize_for_commit(doc_fullwidth)

    assert result_ascii["text"] != result_fullwidth["text"], (
        "H-1: canonicalize_for_commit() scrubbed fullwidth chars to ASCII"
    )


def test_canonicalize_document_still_scrubs_by_default() -> None:
    """canonicalize_document() default (scrub_homoglyphs=True) is unchanged.

    This confirms backward-compatibility: display/comparison paths still
    normalise homoglyphs; only the commit path uses the injective variant.
    """
    doc = {"text": "ＡＢＣ"}  # Ａ Ｂ Ｃ
    result = canonicalize_document(doc)
    assert result["text"] == "ABC", (
        "canonicalize_document() default should still scrub homoglyphs to ASCII"
    )


def test_normalize_whitespace_empty_string():
    """Test normalize_whitespace with empty string."""
    assert normalize_whitespace("") == ""
    assert normalize_whitespace("   ") == ""


def test_canonicalize_document_with_whitespace_in_nested_strings():
    """String values in nested structures are preserved exactly (CANON-2 fix)."""
    doc = {
        "outer": {"text": "multiple   spaces"},
        "items": [{"description": "  leading and trailing  "}],
    }
    result = canonicalize_document(doc)

    assert result["outer"]["text"] == "multiple   spaces"
    assert result["items"][0]["description"] == "  leading and trailing  "


def test_canonicalize_document_complex_real_world():
    """Test canonicalization with a realistic document structure."""
    doc = {
        "title": "Important  Document",
        "version": 2,
        "metadata": {
            "author": "John   Doe",
            "created": "2024-01-01",
            "tags": ["public", "archived"],
        },
        "content": {
            "sections": [
                {"heading": "Section  1", "text": "This  is   content"},
                {"heading": "Section  2", "text": "More   content"},
            ]
        },
    }

    result = canonicalize_document(doc)

    # Check key ordering at each level
    assert list(result.keys()) == ["content", "metadata", "title", "version"]
    assert list(result["metadata"].keys()) == ["author", "created", "tags"]

    # String values are preserved exactly — whitespace is no longer collapsed
    # (CANON-2 fix: business-level normalisation must happen before this call)
    assert result["title"] == "Important  Document"
    assert result["metadata"]["author"] == "John   Doe"
    assert result["content"]["sections"][0]["heading"] == "Section  1"
    assert result["content"]["sections"][0]["text"] == "This  is   content"


def test_normalize_whitespace_nbsp():
    """Test that NO-BREAK SPACE (U+00A0) is normalized to regular space."""
    nbsp = "\u00a0"
    assert normalize_whitespace(f"hello{nbsp}world") == "hello world"
    assert normalize_whitespace(f"hello{nbsp}{nbsp}world") == "hello world"


def test_normalize_whitespace_narrow_nbsp():
    """Test that NARROW NO-BREAK SPACE (U+202F) is normalized to regular space."""
    nnbsp = "\u202f"
    assert normalize_whitespace(f"hello{nnbsp}world") == "hello world"


def test_normalize_whitespace_thin_space():
    """Test that THIN SPACE (U+2009) is normalized to regular space via NFKC."""
    thin = "\u2009"
    assert normalize_whitespace(f"hello{thin}world") == "hello world"


def test_normalize_whitespace_unicode_spaces_nfkc():
    """Test that various Unicode space variants (normalized by NFKC) collapse correctly."""
    en_space = "\u2002"
    em_space = "\u2003"
    hair_space = "\u200a"
    assert normalize_whitespace(f"a{en_space}b") == "a b"
    assert normalize_whitespace(f"a{em_space}b") == "a b"
    assert normalize_whitespace(f"a{hair_space}b") == "a b"


def test_normalize_whitespace_mixed_unicode():
    """Test mixing NBSP and standard whitespace collapses to single space."""
    nbsp = "\u00a0"
    nnbsp = "\u202f"
    # NBSP + regular space should collapse to single space
    assert normalize_whitespace(f"hello{nbsp} world") == "hello world"
    # Multiple different unicode spaces collapse to single space
    assert normalize_whitespace(f"a{nbsp}{nnbsp} b") == "a b"


def test_document_to_bytes_nbsp_identical_to_regular_space():
    """
    NBSP and regular space in document string values must produce identical
    document_to_bytes() output (critical for canonicalization determinism).
    """
    nbsp = "\u00a0"
    doc_with_nbsp = {"text": f"hello{nbsp}world"}
    doc_with_space = {"text": "hello world"}
    assert document_to_bytes(doc_with_nbsp) == document_to_bytes(doc_with_space)


def test_document_to_bytes_narrow_nbsp_identical_to_regular_space():
    """NARROW NO-BREAK SPACE must canonicalize identically to regular space."""
    nnbsp = "\u202f"
    doc_with_nnbsp = {"text": f"hello{nnbsp}world"}
    doc_with_space = {"text": "hello world"}
    assert document_to_bytes(doc_with_nnbsp) == document_to_bytes(doc_with_space)


def test_document_to_bytes_thin_space_identical_to_regular_space():
    """THIN SPACE (U+2009, handled by NFKC) must canonicalize identically to regular space."""
    thin = "\u2009"
    doc_with_thin = {"text": f"hello{thin}world"}
    doc_with_space = {"text": "hello world"}
    assert document_to_bytes(doc_with_thin) == document_to_bytes(doc_with_space)


# ---------------------------------------------------------------------------
# Numeric canonicalization tests (Finding #1 — Red Team Hardening)
# ---------------------------------------------------------------------------


@given(st.integers(min_value=-(2**53), max_value=2**53))
def test_int_and_equivalent_float_same_hash(n: int) -> None:
    """{"amount": n} and {"amount": float(n)} must produce identical canonical bytes.

    Restricted to the range where float can represent the integer exactly
    (within IEEE 754 double-precision 53-bit mantissa).
    """
    int_doc = canonicalize_document({"amount": n})
    float_doc = canonicalize_document({"amount": float(n)})
    assert document_to_bytes(int_doc) == document_to_bytes(float_doc)


@given(st.floats(allow_nan=False, allow_infinity=False))
def test_whole_floats_canonicalize_to_int(f: float) -> None:
    """If float(f) == int(f), canonical output must equal that of the int."""
    try:
        i = int(f)
    except (OverflowError, ValueError):
        return
    if f != i:
        return
    float_doc = canonicalize_document({"value": f})
    int_doc = canonicalize_document({"value": i})
    assert document_to_bytes(float_doc) == document_to_bytes(int_doc)


def test_nan_raises() -> None:
    """NaN values must raise CanonicalizationError."""
    with pytest.raises(CanonicalizationError):
        canonicalize_document({"value": float("nan")})


def test_inf_raises() -> None:
    """Infinity values must raise CanonicalizationError."""
    with pytest.raises(CanonicalizationError):
        canonicalize_document({"value": float("inf")})


def test_neg_inf_raises() -> None:
    """Negative infinity values must raise CanonicalizationError."""
    with pytest.raises(CanonicalizationError):
        canonicalize_document({"value": float("-inf")})


def test_numeric_equivalence_basic() -> None:
    """Semantically identical numeric representations must produce the same bytes."""
    assert document_to_bytes({"amount": 100}) == document_to_bytes({"amount": 100.0})
    assert document_to_bytes({"amount": 100}) == document_to_bytes({"amount": 1e2})


def test_non_whole_float_preserved() -> None:
    """Non-whole floats are preserved as Decimal, not coerced to int."""
    doc = canonicalize_document({"value": 3.14})
    assert doc["value"] != 3  # should not become int
    assert float(doc["value"]) == pytest.approx(3.14)


def test_bool_not_coerced_to_int() -> None:
    """Booleans must not be treated as integers during canonicalization."""
    doc = canonicalize_document({"flag": True, "other": False})
    assert doc["flag"] is True
    assert doc["other"] is False


# ---------------------------------------------------------------------------
# Homoglyph scrub tests (Finding #3 — Red Team Hardening Round 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("US\uff24", "USD"),  # fullwidth D
        ("\U0001d414\U0001d412\U0001d403", "USD"),  # mathematical bold
        ("\uff35\uff33\uff24", "USD"),  # all fullwidth
        ("USD", "USD"),  # already clean — no change
    ],
)
def test_homoglyph_scrub_normalizes_to_ascii(variant: str, expected: str) -> None:
    assert _scrub_homoglyphs(variant) == expected


def test_homoglyph_variants_produce_identical_canonical_bytes() -> None:
    base = {"invoice_id": "INV-8842", "amount": 100}
    variants = [
        {**base, "currency": "USD"},
        {**base, "currency": "US\uff24"},
        {**base, "currency": "\U0001d414\U0001d412\U0001d403"},
        {**base, "currency": "\uff35\uff33\uff24"},
    ]
    hashes = [document_to_bytes(v) for v in variants]
    assert len(set(hashes)) == 1, "Homoglyph variants produced divergent bytes"


def test_non_ascii_legitimate_content_survives_scrub() -> None:
    """Arabic, CJK, accented Latin must not be destroyed."""
    assert _scrub_homoglyphs("\u0645\u0631\u062d\u0628\u0627") == "\u0645\u0631\u062d\u0628\u0627"
    assert _scrub_homoglyphs("\u65e5\u672c\u8a9e") == "\u65e5\u672c\u8a9e"
    assert _scrub_homoglyphs("caf\u00e9") == "caf\u00e9"


def test_scrub_homoglyphs_false_preserves_fullwidth() -> None:
    doc = {"currency": "\uff35\uff33\uff24"}
    bytes_on = document_to_bytes(doc, scrub_homoglyphs=True)
    bytes_off = document_to_bytes(doc, scrub_homoglyphs=False)
    assert bytes_on != bytes_off


# ---------------------------------------------------------------------------
# Sorted list keys tests (Finding #2 — Red Team Hardening)
# ---------------------------------------------------------------------------


def test_sorted_list_keys_sorts_annotated_field() -> None:
    """Fields in sorted_list_keys have their arrays sorted."""
    doc = {"tags": ["banana", "apple", "cherry"]}
    result = canonicalize_document(doc, sorted_list_keys={"tags"})
    assert result["tags"] == ["apple", "banana", "cherry"]


def test_sorted_list_keys_preserves_unannotated_field() -> None:
    """Fields NOT in sorted_list_keys preserve original order."""
    doc = {"sections": ["intro", "body", "conclusion"], "tags": ["b", "a"]}
    result = canonicalize_document(doc, sorted_list_keys={"tags"})
    assert result["sections"] == ["intro", "body", "conclusion"]
    assert result["tags"] == ["a", "b"]


def test_sorted_list_keys_none_preserves_all_order() -> None:
    """Default (None) preserves all list orderings — backward compatible."""
    doc = {"items": [3, 1, 2]}
    result = canonicalize_document(doc)
    assert result["items"] == [3, 1, 2]


def test_sorted_list_keys_deterministic_across_orderings() -> None:
    """Two docs differing only in array order produce identical bytes."""
    doc_a = {"tags": ["b", "a", "c"], "id": "x"}
    doc_b = {"tags": ["c", "a", "b"], "id": "x"}
    assert document_to_bytes(doc_a, sorted_list_keys={"tags"}) == document_to_bytes(
        doc_b, sorted_list_keys={"tags"}
    )


def test_sorted_list_keys_nested_dict_arrays() -> None:
    """Sorting works on arrays of dicts using canonical JSON as sort key."""
    doc = {"records": [{"z": 1}, {"a": 2}]}
    result = canonicalize_document(doc, sorted_list_keys={"records"})
    # {"a":2} sorts before {"z":1} lexicographically
    assert list(result["records"][0].keys()) == ["a"]
    assert list(result["records"][1].keys()) == ["z"]


def test_sorted_list_keys_propagates_to_nested_docs() -> None:
    """sorted_list_keys applies at any nesting depth."""
    doc = {"outer": {"tags": ["z", "a"]}}
    result = canonicalize_document(doc, sorted_list_keys={"tags"})
    assert result["outer"]["tags"] == ["a", "z"]


def test_sorted_list_keys_document_to_bytes() -> None:
    """sorted_list_keys is forwarded through document_to_bytes."""
    doc = {"tags": ["b", "a"]}
    unsorted = document_to_bytes(doc)
    sorted_ = document_to_bytes(doc, sorted_list_keys={"tags"})
    assert unsorted != sorted_
