"""
Unit tests for document canonicalization.

These tests validate the canonicalize_document() function and related
canonicalization utilities in protocol/canonical.py.
"""

import pytest

from protocol.canonical import (
    canonicalize_document,
    canonicalize_json,
    document_to_bytes,
    normalize_whitespace,
)


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


def test_canonicalize_document_normalizes_whitespace():
    """Test that whitespace in string values is normalized."""
    doc = {"field1": "hello   world", "field2": "multiple  \t  spaces"}
    result = canonicalize_document(doc)

    assert result["field1"] == "hello world"
    assert result["field2"] == "multiple spaces"


def test_canonicalize_document_with_list():
    """Test canonicalization of documents containing lists."""
    doc = {"items": ["apple", "banana", "cherry"]}
    result = canonicalize_document(doc)

    # List order should be preserved
    assert result["items"] == ["apple", "banana", "cherry"]


def test_canonicalize_document_list_with_dicts():
    """Test canonicalization of lists containing dictionaries."""
    doc = {"people": [{"name": "Bob", "age": 25}, {"name": "Alice", "age": 30}]}
    result = canonicalize_document(doc)

    # Each dict in the list should be canonicalized
    assert list(result["people"][0].keys()) == ["age", "name"]
    assert list(result["people"][1].keys()) == ["age", "name"]


def test_canonicalize_document_preserves_non_string_values():
    """Test that non-string values are preserved."""
    doc = {"number": 42, "boolean": True, "null": None, "float": 3.14}
    result = canonicalize_document(doc)

    assert result["number"] == 42
    assert result["boolean"] is True
    assert result["null"] is None
    assert result["float"] == 3.14


def test_canonicalize_document_rejects_non_dict():
    """Test that non-dictionary input raises ValueError."""
    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document("not a dict")

    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document([1, 2, 3])

    with pytest.raises(ValueError, match="must be a dictionary"):
        canonicalize_document(42)


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
    """Test idempotence and unicode handling in nested documents."""
    doc = {
        "title": "Résumé   of  José",
        "meta": {"author": "Zoë  Ångström"},
        "sections": [{"heading": "Intro   🌟", "body": "Hello   world"}],
    }

    first = canonicalize_document(doc)
    second = canonicalize_document(first)

    assert first == second
    assert first["title"] == "Résumé of José"
    assert first["meta"]["author"] == "Zoë Ångström"
    assert first["sections"][0]["heading"] == "Intro 🌟"
    assert first["sections"][0]["body"] == "Hello world"


def test_canonicalize_json():
    """Test canonicalize_json produces canonical JSON string."""
    data = {"z": 1, "a": 2}
    result = canonicalize_json(data)

    # Should be sorted, compact, ASCII
    assert result == '{"a":2,"z":1}'


def test_document_to_bytes():
    """Test document_to_bytes produces canonical bytes."""
    doc = {"name": "Alice  Smith", "id": 123}
    result = document_to_bytes(doc)

    assert isinstance(result, bytes)
    # Should be canonical JSON with normalized whitespace
    assert result == b'{"id":123,"name":"Alice Smith"}'


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


def test_normalize_whitespace_empty_string():
    """Test normalize_whitespace with empty string."""
    assert normalize_whitespace("") == ""
    assert normalize_whitespace("   ") == ""


def test_canonicalize_document_with_whitespace_in_nested_strings():
    """Test whitespace normalization in nested structures."""
    doc = {
        "outer": {"text": "multiple   spaces"},
        "items": [{"description": "  leading and trailing  "}],
    }
    result = canonicalize_document(doc)

    assert result["outer"]["text"] == "multiple spaces"
    assert result["items"][0]["description"] == "leading and trailing"


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

    # Check whitespace normalization
    assert result["title"] == "Important Document"
    assert result["metadata"]["author"] == "John Doe"
    assert result["content"]["sections"][0]["heading"] == "Section 1"
    assert result["content"]["sections"][0]["text"] == "This is content"


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
