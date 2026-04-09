"""
Tests for api.services.hasher — BLAKE3 hashing utilities.

Covers:
- hash_request() determinism and canonical ordering
- hash_document() basic functionality
- generate_commit_id() format and uniqueness
"""

from __future__ import annotations

from datetime import datetime, timezone

from api.services.hasher import generate_commit_id, hash_document, hash_request


# ------------------------------------------------------------------ #
# hash_request
# ------------------------------------------------------------------ #


class TestHashRequest:
    """Tests for hash_request()."""

    def test_deterministic(self) -> None:
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        h1 = hash_request("subject", "desc", "agency", ts)
        h2 = hash_request("subject", "desc", "agency", ts)
        assert h1 == h2

    def test_returns_hex_string(self) -> None:
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = hash_request("s", "d", "a", ts)
        assert isinstance(result, str)
        assert len(result) == 64  # 32-byte BLAKE3 in hex
        # Verify it's valid hex
        bytes.fromhex(result)

    def test_different_subject_different_hash(self) -> None:
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        h1 = hash_request("subject1", "desc", "agency", ts)
        h2 = hash_request("subject2", "desc", "agency", ts)
        assert h1 != h2

    def test_different_agency_different_hash(self) -> None:
        ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        h1 = hash_request("s", "d", "agency1", ts)
        h2 = hash_request("s", "d", "agency2", ts)
        assert h1 != h2

    def test_different_timestamp_different_hash(self) -> None:
        ts1 = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2024, 1, 16, 12, 0, 0, tzinfo=timezone.utc)
        h1 = hash_request("s", "d", "a", ts1)
        h2 = hash_request("s", "d", "a", ts2)
        assert h1 != h2

    def test_canonical_ordering(self) -> None:
        """Hash is computed over sorted-key canonical JSON, so the result
        must be identical to a manually constructed sorted payload."""
        from protocol.canonical_json import canonical_json_encode
        from protocol.hashes import hash_bytes

        ts = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        h = hash_request("Test Subject", "Test Desc", "FBI", ts)
        # Manually construct the expected canonical JSON with sorted keys
        expected_canonical = canonical_json_encode(
            {
                "agency": "FBI",
                "description": "Test Desc",
                "filed_at": ts.isoformat(),
                "subject": "Test Subject",
            }
        )
        expected_hash = hash_bytes(expected_canonical.encode("utf-8")).hex()
        assert h == expected_hash


# ------------------------------------------------------------------ #
# hash_document
# ------------------------------------------------------------------ #


class TestHashDocument:
    """Tests for hash_document()."""

    def test_deterministic(self) -> None:
        data = b"hello world"
        assert hash_document(data) == hash_document(data)

    def test_returns_hex_string(self) -> None:
        result = hash_document(b"test")
        assert isinstance(result, str)
        assert len(result) == 64
        bytes.fromhex(result)

    def test_different_content_different_hash(self) -> None:
        assert hash_document(b"abc") != hash_document(b"def")

    def test_empty_bytes(self) -> None:
        result = hash_document(b"")
        assert isinstance(result, str)
        assert len(result) == 64


# ------------------------------------------------------------------ #
# generate_commit_id
# ------------------------------------------------------------------ #


class TestGenerateCommitId:
    """Tests for generate_commit_id()."""

    def test_format(self) -> None:
        cid = generate_commit_id()
        assert cid.startswith("0x")
        assert len(cid) == 66  # "0x" + 64 hex chars

    def test_valid_hex(self) -> None:
        cid = generate_commit_id()
        bytes.fromhex(cid[2:])  # Should not raise

    def test_unique(self) -> None:
        ids = {generate_commit_id() for _ in range(100)}
        assert len(ids) == 100  # All unique
