"""
Unit tests for canonical JSON encoding.

These tests validate the canonical_json_encode() function which provides
deterministic JSON encoding for the Olympus protocol.
"""

import pytest

from protocol.canonical_json import canonical_json_bytes, canonical_json_encode


def test_canonical_json_encode_basic_types():
    """Test encoding of basic JSON types."""
    # String
    assert canonical_json_encode("hello") == '"hello"'

    # Number (integer)
    assert canonical_json_encode(42) == "42"

    # Number (float)
    assert canonical_json_encode(3.14) == "3.14"

    # Boolean
    assert canonical_json_encode(True) == "true"
    assert canonical_json_encode(False) == "false"

    # Null
    assert canonical_json_encode(None) == "null"


def test_canonical_json_encode_sorted_keys():
    """Test that object keys are sorted alphabetically."""
    obj = {"z": 1, "a": 2, "m": 3}
    result = canonical_json_encode(obj)
    # Keys should be in alphabetical order
    assert result == '{"a":2,"m":3,"z":1}'


def test_canonical_json_encode_compact_separators():
    """Test that output uses compact separators (no whitespace)."""
    obj = {"key": "value", "nested": {"a": 1, "b": 2}}
    result = canonical_json_encode(obj)
    # Should have no spaces after colons or commas
    assert result == '{"key":"value","nested":{"a":1,"b":2}}'
    assert " " not in result


def test_canonical_json_encode_ascii_only():
    """Test that non-ASCII characters are escaped."""
    obj = {"unicode": "hello 世界"}
    result = canonical_json_encode(obj)
    # Non-ASCII characters should be escaped
    assert "\\u" in result
    # Should not contain raw non-ASCII bytes
    result.encode("ascii")  # Should not raise


def test_canonical_json_encode_nested_objects():
    """Test encoding of nested objects."""
    obj = {"outer": {"middle": {"inner": "value"}}}
    result = canonical_json_encode(obj)
    assert result == '{"outer":{"middle":{"inner":"value"}}}'


def test_canonical_json_encode_arrays():
    """Test encoding of arrays."""
    obj = {"items": [3, 1, 2], "nested": [[1, 2], [3, 4]]}
    result = canonical_json_encode(obj)
    # Arrays should maintain order
    assert result == '{"items":[3,1,2],"nested":[[1,2],[3,4]]}'


def test_canonical_json_encode_mixed_types():
    """Test encoding of mixed types in arrays."""
    obj = {"mixed": [1, "two", True, None, {"key": "value"}]}
    result = canonical_json_encode(obj)
    assert result == '{"mixed":[1,"two",true,null,{"key":"value"}]}'


def test_canonical_json_encode_rejects_nan():
    """Test that NaN values are rejected."""
    obj = {"value": float("nan")}
    with pytest.raises(ValueError, match="NaN"):
        canonical_json_encode(obj)


def test_canonical_json_encode_rejects_infinity():
    """Test that Infinity values are rejected."""
    obj = {"value": float("inf")}
    with pytest.raises(ValueError, match="Infinity"):
        canonical_json_encode(obj)


def test_canonical_json_encode_rejects_negative_infinity():
    """Test that -Infinity values are rejected."""
    obj = {"value": float("-inf")}
    with pytest.raises(ValueError, match="Infinity"):
        canonical_json_encode(obj)


def test_canonical_json_encode_rejects_nan_in_nested_object():
    """Test that NaN in nested objects is rejected."""
    obj = {"outer": {"inner": {"value": float("nan")}}}
    with pytest.raises(ValueError, match="NaN"):
        canonical_json_encode(obj)


def test_canonical_json_encode_rejects_nan_in_array():
    """Test that NaN in arrays is rejected."""
    obj = {"values": [1, 2, float("nan"), 4]}
    with pytest.raises(ValueError, match="NaN"):
        canonical_json_encode(obj)


def test_canonical_json_encode_deterministic():
    """Test that encoding is deterministic across multiple calls."""
    obj = {"z": [3, 2, 1], "a": {"nested": True}, "m": "value"}

    result1 = canonical_json_encode(obj)
    result2 = canonical_json_encode(obj)
    result3 = canonical_json_encode(obj)

    assert result1 == result2 == result3


def test_canonical_json_encode_nested_deterministic():
    """Test deterministic encoding for nested objects with reordered keys."""
    obj1 = {"meta": {"z": 3, "a": 1}, "items": [{"b": 2, "a": 1}]}
    obj2 = {"items": [{"a": 1, "b": 2}], "meta": {"a": 1, "z": 3}}

    assert canonical_json_encode(obj1) == canonical_json_encode(obj2)


def test_canonical_json_encode_equivalent_objects():
    """Test that semantically equivalent objects produce identical output."""
    # Same object with different key order
    obj1 = {"z": 1, "a": 2, "m": 3}
    obj2 = {"a": 2, "m": 3, "z": 1}
    obj3 = {"m": 3, "z": 1, "a": 2}

    result1 = canonical_json_encode(obj1)
    result2 = canonical_json_encode(obj2)
    result3 = canonical_json_encode(obj3)

    assert result1 == result2 == result3


def test_canonical_json_bytes():
    """Test canonical_json_bytes returns UTF-8 bytes."""
    obj = {"key": "value"}
    result = canonical_json_bytes(obj)

    assert isinstance(result, bytes)
    assert result == b'{"key":"value"}'


def test_canonical_json_bytes_unicode():
    """Test canonical_json_bytes handles unicode correctly."""
    obj = {"unicode": "hello 世界"}
    result = canonical_json_bytes(obj)

    assert isinstance(result, bytes)
    # Should be ASCII-escaped in the JSON
    decoded = result.decode("utf-8")
    assert "\\u" in decoded


def test_canonical_json_encode_empty_object():
    """Test encoding of empty object."""
    assert canonical_json_encode({}) == "{}"


def test_canonical_json_encode_empty_array():
    """Test encoding of empty array."""
    assert canonical_json_encode([]) == "[]"


def test_canonical_json_encode_deeply_nested():
    """Test encoding of deeply nested structures."""
    obj = {"l1": {"l2": {"l3": {"l4": {"l5": "deep"}}}}}
    result = canonical_json_encode(obj)
    assert result == '{"l1":{"l2":{"l3":{"l4":{"l5":"deep"}}}}}'


def test_canonical_json_encode_special_characters():
    """Test encoding of special characters that need escaping."""
    obj = {
        "quotes": 'He said "hello"',
        "backslash": "path\\to\\file",
        "newline": "line1\nline2",
        "tab": "col1\tcol2",
    }
    result = canonical_json_encode(obj)

    # All special characters should be properly escaped
    assert '\\"' in result or r"\"" in result
    assert "\\n" in result
    assert "\\t" in result


def test_canonical_json_encode_trims_trailing_zeros_and_bounds():
    """Canonical numbers: trim zeros, fixed/scientific boundaries."""
    assert (
        canonical_json_encode({"micro": 0.0000001, "huge": 1e21}) == '{"huge":1e+21,"micro":1e-7}'
    )
    assert canonical_json_encode({"value": 1.0, "precise": 3.1400}) == '{"precise":3.14,"value":1}'


def test_canonical_json_encode_numeric_edge_cases():
    """Float traps, exponent limits, and negative zero normalization."""
    assert canonical_json_encode({"z": -0.0}) == '{"z":0}'
    assert canonical_json_encode({"tenth": 0.1}) == '{"tenth":0.1}'
    assert canonical_json_encode({"int": 9007199254740993}) == '{"int":9007199254740993}'
    assert canonical_json_encode({"deep": 1e-308}) == '{"deep":1e-308}'
    assert canonical_json_encode({"wide": 1e308}) == '{"wide":1e+308}'
    assert canonical_json_encode({"fixed_min": 1e-6}) == '{"fixed_min":0.000001}'
    assert canonical_json_encode({"sci_min": 1e-7}) == '{"sci_min":1e-7}'
    # fixed_max is 1 followed by 20 zeros (fixed-notation upper bound)
    expected_fixed_max = '{"fixed_max":' + ("1" + "0" * 20) + "}"
    assert canonical_json_encode({"fixed_max": 1e20}) == expected_fixed_max
    assert canonical_json_encode({"sci_max": 1e21}) == '{"sci_max":1e+21}'
    assert (
        canonical_json_encode({"precise": 1.2345678901234567}) == '{"precise":1.2345678901234567}'
    )
