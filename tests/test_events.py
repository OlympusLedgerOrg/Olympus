"""
Tests for protocol.events — CanonicalEvent container.

Covers:
- from_raw() canonicalization and hashing
- Input validation (non-dict, empty schema_version)
- Deterministic hashing (same input => same hash)
- to_dict() serialization
- Frozen dataclass invariant
"""

from __future__ import annotations

import pytest

from protocol.events import CanonicalEvent


class TestCanonicalEventFromRaw:
    """Tests for CanonicalEvent.from_raw() factory method."""

    def test_basic_event(self) -> None:
        event = CanonicalEvent.from_raw({"key": "value"}, schema_version="v1")
        assert event.schema_version == "v1"
        assert isinstance(event.payload, dict)
        assert isinstance(event.canonical_bytes, bytes)
        assert isinstance(event.hash_hex, str)
        assert len(event.hash_hex) == 64  # 32-byte BLAKE3 in hex

    def test_deterministic_hash(self) -> None:
        """Same input always produces the same hash."""
        e1 = CanonicalEvent.from_raw({"a": 1, "b": 2}, schema_version="v1")
        e2 = CanonicalEvent.from_raw({"b": 2, "a": 1}, schema_version="v1")
        assert e1.hash_hex == e2.hash_hex
        assert e1.canonical_bytes == e2.canonical_bytes

    def test_different_content_different_hash(self) -> None:
        e1 = CanonicalEvent.from_raw({"x": "hello"}, schema_version="v1")
        e2 = CanonicalEvent.from_raw({"x": "world"}, schema_version="v1")
        assert e1.hash_hex != e2.hash_hex

    def test_different_schema_same_payload_same_hash(self) -> None:
        """schema_version is not part of the content hash."""
        e1 = CanonicalEvent.from_raw({"x": 1}, schema_version="v1")
        e2 = CanonicalEvent.from_raw({"x": 1}, schema_version="v2")
        # The hash is over canonical_bytes only, not schema_version
        assert e1.hash_hex == e2.hash_hex

    def test_nested_dict(self) -> None:
        event = CanonicalEvent.from_raw(
            {"outer": {"inner": "value", "z": 1, "a": 2}},
            schema_version="v1",
        )
        assert event.hash_hex
        assert isinstance(event.canonical_bytes, bytes)

    def test_empty_dict(self) -> None:
        event = CanonicalEvent.from_raw({}, schema_version="v1")
        assert event.hash_hex
        assert event.canonical_bytes

    def test_whitespace_normalization(self) -> None:
        """Multiple spaces should be normalized to single spaces."""
        e1 = CanonicalEvent.from_raw({"text": "hello  world"}, schema_version="v1")
        e2 = CanonicalEvent.from_raw({"text": "hello world"}, schema_version="v1")
        assert e1.hash_hex == e2.hash_hex


class TestCanonicalEventValidation:
    """Tests for input validation in from_raw()."""

    def test_non_dict_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dictionary"):
            CanonicalEvent.from_raw("not a dict", schema_version="v1")  # type: ignore[arg-type]

    def test_list_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dictionary"):
            CanonicalEvent.from_raw([1, 2, 3], schema_version="v1")  # type: ignore[arg-type]

    def test_empty_schema_version_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            CanonicalEvent.from_raw({"key": "val"}, schema_version="")

    def test_none_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a dictionary"):
            CanonicalEvent.from_raw(None, schema_version="v1")  # type: ignore[arg-type]


class TestCanonicalEventToDict:
    """Tests for to_dict() serialization."""

    def test_to_dict_contains_required_keys(self) -> None:
        event = CanonicalEvent.from_raw({"k": "v"}, schema_version="v2")
        d = event.to_dict()
        assert "schema_version" in d
        assert "payload" in d
        assert "hash_hex" in d

    def test_to_dict_values_match(self) -> None:
        event = CanonicalEvent.from_raw({"x": 1}, schema_version="v1.0")
        d = event.to_dict()
        assert d["schema_version"] == "v1.0"
        assert d["hash_hex"] == event.hash_hex


class TestCanonicalEventFrozen:
    """Tests for frozen dataclass invariant."""

    def test_immutable(self) -> None:
        event = CanonicalEvent.from_raw({"a": 1}, schema_version="v1")
        with pytest.raises(AttributeError):
            event.hash_hex = "tampered"  # type: ignore[misc]
