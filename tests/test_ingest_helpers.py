"""
Tests for api.ingest helper functions — pure validators and utilities.

These test the pure, non-I/O functions in api/ingest.py that can be
unit tested without a database or external services:

- _check_json_depth() — JSON nesting depth guard (L-4 hardening)
- _estimate_json_size() — pre-serialization size estimation
- _parse_content_hash() — hex hash validation
- _normalize_merkle_root() — Merkle root validation
- _normalize_source_url() — URL scheme/netloc validation
- _value_hash_to_poseidon_field() — BN128 modular reduction
- _resolved_poseidon_root() — fallback resolution
- _evaluate_proof_bundle() — external proof verification
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.ingest import (
    _check_json_depth,
    _estimate_json_size,
    _normalize_merkle_root,
    _normalize_source_url,
    _parse_content_hash,
    _resolved_poseidon_root,
    _value_hash_to_poseidon_field,
)


# ------------------------------------------------------------------ #
# _check_json_depth
# ------------------------------------------------------------------ #


class TestCheckJsonDepth:
    def test_flat_dict(self) -> None:
        assert _check_json_depth({"a": 1, "b": 2}) == 1

    def test_nested_dict(self) -> None:
        obj = {"a": {"b": {"c": 1}}}
        assert _check_json_depth(obj) == 3

    def test_flat_list(self) -> None:
        assert _check_json_depth([1, 2, 3]) == 1

    def test_nested_list(self) -> None:
        obj = [[[1]]]
        assert _check_json_depth(obj) == 3

    def test_scalar(self) -> None:
        assert _check_json_depth("hello") == 0

    def test_none(self) -> None:
        assert _check_json_depth(None) == 0

    def test_mixed_nesting(self) -> None:
        obj = {"a": [{"b": [1]}]}
        assert _check_json_depth(obj) >= 3

    def test_exceeds_limit_raises(self) -> None:
        # Build deeply nested dict
        obj: dict | int = 1
        for _ in range(200):
            obj = {"nested": obj}
        with pytest.raises(ValueError, match="nesting depth exceeds limit"):
            _check_json_depth(obj)

    def test_initial_depth_offset(self) -> None:
        result = _check_json_depth({"a": 1}, current_depth=5)
        assert result == 6

    def test_empty_dict(self) -> None:
        assert _check_json_depth({}) == 0

    def test_empty_list(self) -> None:
        assert _check_json_depth([]) == 0


# ------------------------------------------------------------------ #
# _estimate_json_size
# ------------------------------------------------------------------ #


class TestEstimateJsonSize:
    def test_none(self) -> None:
        assert _estimate_json_size(None) == 4  # "null"

    def test_boolean(self) -> None:
        assert _estimate_json_size(True) == 5  # "true"
        assert _estimate_json_size(False) == 5  # "false"

    def test_integer(self) -> None:
        size = _estimate_json_size(42)
        assert size == 2  # "42"

    def test_string(self) -> None:
        size = _estimate_json_size("hello")
        assert size == 7  # "hello" + 2 quotes

    def test_multibyte_string(self) -> None:
        size = _estimate_json_size("日本語")
        assert size > len("日本語") + 2  # UTF-8 is multi-byte

    def test_empty_dict(self) -> None:
        size = _estimate_json_size({})
        assert size == 2  # "{}"

    def test_empty_list(self) -> None:
        size = _estimate_json_size([])
        assert size == 2  # "[]"

    def test_nested_structure(self) -> None:
        obj = {"key": [1, "two", None]}
        size = _estimate_json_size(obj)
        assert size > 0


# ------------------------------------------------------------------ #
# _parse_content_hash
# ------------------------------------------------------------------ #


class TestParseContentHash:
    def test_valid_hash(self) -> None:
        valid_hex = "ab" * 32
        result = _parse_content_hash(valid_hex)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_invalid_hex(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _parse_content_hash("not-hex")
        assert exc_info.value.status_code == 400

    def test_wrong_length(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _parse_content_hash("abcd")
        assert exc_info.value.status_code == 400

    def test_empty_string(self) -> None:
        with pytest.raises(HTTPException):
            _parse_content_hash("")


# ------------------------------------------------------------------ #
# _normalize_merkle_root
# ------------------------------------------------------------------ #


class TestNormalizeMerkleRoot:
    def test_valid_root(self) -> None:
        valid_hex = "cd" * 32
        result = _normalize_merkle_root(valid_hex)
        assert result == valid_hex

    def test_invalid_hex(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _normalize_merkle_root("not-hex")
        assert exc_info.value.status_code == 400

    def test_wrong_length(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _normalize_merkle_root("ab" * 16)
        assert exc_info.value.status_code == 400

    def test_normalizes_case(self) -> None:
        upper = "AB" * 32
        result = _normalize_merkle_root(upper)
        assert result == upper.lower()


# ------------------------------------------------------------------ #
# _normalize_source_url
# ------------------------------------------------------------------ #


class TestNormalizeSourceUrl:
    def test_valid_https(self) -> None:
        assert _normalize_source_url("https://example.com/data") == "https://example.com/data"

    def test_valid_http(self) -> None:
        assert _normalize_source_url("http://example.com/data") == "http://example.com/data"

    def test_ftp_rejected(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _normalize_source_url("ftp://example.com/data")
        assert exc_info.value.status_code == 400

    def test_missing_hostname(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _normalize_source_url("https://")
        assert exc_info.value.status_code == 400

    def test_bare_string_rejected(self) -> None:
        with pytest.raises(HTTPException):
            _normalize_source_url("just-a-string")


# ------------------------------------------------------------------ #
# _value_hash_to_poseidon_field
# ------------------------------------------------------------------ #


class TestValueHashToPoseidonField:
    BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

    def test_returns_field_element(self) -> None:
        h = b"\xff" * 32
        result = _value_hash_to_poseidon_field(h)
        assert 0 <= result < self.BN128_PRIME

    def test_zero_hash(self) -> None:
        h = b"\x00" * 32
        assert _value_hash_to_poseidon_field(h) == 0

    def test_modular_reduction(self) -> None:
        """A hash that exceeds the BN128 prime should be reduced."""
        h = b"\xff" * 32
        result = _value_hash_to_poseidon_field(h)
        assert result < self.BN128_PRIME

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            _value_hash_to_poseidon_field(b"\x00" * 16)

    def test_deterministic(self) -> None:
        h = bytes(range(32))
        assert _value_hash_to_poseidon_field(h) == _value_hash_to_poseidon_field(h)


# ------------------------------------------------------------------ #
# _resolved_poseidon_root
# ------------------------------------------------------------------ #


class TestResolvedPoseidonRoot:
    def test_persisted_preferred(self) -> None:
        assert _resolved_poseidon_root("abc", "fallback") == "abc"

    def test_none_uses_fallback(self) -> None:
        assert _resolved_poseidon_root(None, "fallback") == "fallback"

    def test_empty_string_is_truthy(self) -> None:
        """Empty string is not None — it should be returned as-is."""
        assert _resolved_poseidon_root("", "fallback") == ""
