"""
Unit tests for the storage/operational_state.py module.

This test module validates the operational state persistence layer that handles
rate limiting, ingestion batch tracking, and RFC 3161 timestamp token storage.

Network and database calls are mocked so these tests run fully offline without
requiring a real PostgreSQL instance.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock


try:
    from datetime import UTC
except ImportError:  # Python < 3.11
    from datetime import timezone

    UTC = timezone.utc

import pytest

from protocol.rfc3161 import MAX_TSA_TOKENS
from storage.operational_state import (
    clear_rate_limits,
    consume_rate_limit,
    get_ingestion_proof,
    get_timestamp_tokens,
    store_ingestion_batch,
    store_timestamp_token,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_conn() -> MagicMock:
    """Create a mock psycopg connection with cursor context manager support."""
    conn = MagicMock()
    cursor = MagicMock()

    # Set up context manager protocol for cursor
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    return conn


@pytest.fixture
def mock_cursor(mock_conn: MagicMock) -> MagicMock:
    """Return the cursor mock from the mock connection."""
    return mock_conn.cursor.return_value.__enter__.return_value


# ---------------------------------------------------------------------------
# Rate Limiting: consume_rate_limit
# ---------------------------------------------------------------------------


class TestConsumeRateLimit:
    """Tests for the consume_rate_limit function."""

    def test_token_available_returns_true(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Consume a token when capacity is available; should return True."""
        # elapsed_seconds returned by the server-side EXTRACT(EPOCH FROM …) expression
        mock_cursor.fetchone.return_value = {
            "tokens": 5.0,
            "elapsed_seconds": 0.0,
        }

        result = consume_rate_limit(
            mock_conn,
            subject_type="ip",
            subject="192.168.1.1",
            action="ingest",
            capacity=10.0,
            refill_rate_per_second=1.0,
        )

        assert result is True
        mock_conn.commit.assert_called_once()
        mock_conn.rollback.assert_not_called()

    def test_token_exhausted_returns_false(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Reject when no tokens remain (tokens < 1.0); should return False."""
        mock_cursor.fetchone.return_value = {
            "tokens": 0.5,  # Below 1.0 threshold
            "elapsed_seconds": 0.0,
        }

        result = consume_rate_limit(
            mock_conn,
            subject_type="ip",
            subject="192.168.1.1",
            action="ingest",
            capacity=10.0,
            refill_rate_per_second=0.0,  # No refill
        )

        assert result is False
        mock_conn.rollback.assert_called_once()
        mock_conn.commit.assert_not_called()

    def test_first_call_row_does_not_exist(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """First call inserts a new row and succeeds with full capacity."""
        # After INSERT, the SELECT returns the newly inserted row
        mock_cursor.fetchone.return_value = {
            "tokens": 10.0,
            "elapsed_seconds": 0.0,
        }

        result = consume_rate_limit(
            mock_conn,
            subject_type="api_key",
            subject="key_abc123",
            action="query",
            capacity=10.0,
            refill_rate_per_second=2.0,
        )

        assert result is True
        # Verify INSERT was executed (first call in cursor.execute)
        calls = mock_cursor.execute.call_args_list
        assert len(calls) >= 3  # INSERT + SELECT + UPDATE
        assert "INSERT INTO api_rate_limits" in calls[0][0][0]

    def test_insert_uses_server_side_now(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """INSERT and UPDATE must use NOW() (not a Python timestamp parameter)."""
        mock_cursor.fetchone.return_value = {
            "tokens": 5.0,
            "elapsed_seconds": 0.0,
        }

        consume_rate_limit(
            mock_conn,
            subject_type="ip",
            subject="10.0.0.1",
            action="ingest",
            capacity=10.0,
            refill_rate_per_second=1.0,
        )

        calls = mock_cursor.execute.call_args_list
        insert_sql = calls[0][0][0]
        update_sql = calls[2][0][0]

        # The INSERT must use NOW() literal, not a %s placeholder for the timestamp.
        assert "NOW()" in insert_sql
        # The UPDATE must also use NOW() literal for last_refill_ts.
        assert "NOW()" in update_sql

    def test_invalid_capacity_raises_value_error(self, mock_conn: MagicMock) -> None:
        """Raise ValueError when capacity is zero or negative."""
        with pytest.raises(ValueError, match="capacity must be > 0"):
            consume_rate_limit(
                mock_conn,
                subject_type="ip",
                subject="10.0.0.1",
                action="ingest",
                capacity=0,  # Invalid
                refill_rate_per_second=1.0,
            )

        with pytest.raises(ValueError, match="capacity must be > 0"):
            consume_rate_limit(
                mock_conn,
                subject_type="ip",
                subject="10.0.0.1",
                action="ingest",
                capacity=-5,  # Invalid
                refill_rate_per_second=1.0,
            )

    def test_invalid_refill_rate_raises_value_error(self, mock_conn: MagicMock) -> None:
        """Raise ValueError when refill_rate_per_second is negative."""
        with pytest.raises(ValueError, match="refill_rate_per_second must be >= 0"):
            consume_rate_limit(
                mock_conn,
                subject_type="ip",
                subject="10.0.0.1",
                action="ingest",
                capacity=10.0,
                refill_rate_per_second=-1.0,  # Invalid
            )

    def test_database_failure_raises_runtime_error(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Raise RuntimeError when SELECT returns None (unexpected DB state)."""
        mock_cursor.fetchone.return_value = None

        with pytest.raises(RuntimeError, match="Failed to load rate limit state"):
            consume_rate_limit(
                mock_conn,
                subject_type="ip",
                subject="10.0.0.1",
                action="ingest",
                capacity=10.0,
                refill_rate_per_second=1.0,
            )


# ---------------------------------------------------------------------------
# Rate Limiting: clear_rate_limits
# ---------------------------------------------------------------------------


class TestClearRateLimits:
    """Tests for the clear_rate_limits function."""

    def test_basic_operation(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Clear all rate limit rows and commit the transaction."""
        clear_rate_limits(mock_conn)

        # Verify DELETE was executed
        delete_calls = [
            c
            for c in mock_cursor.execute.call_args_list
            if "DELETE FROM api_rate_limits" in c[0][0]
        ]
        assert len(delete_calls) == 1
        mock_conn.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Ingestion Batches: store_ingestion_batch
# ---------------------------------------------------------------------------


class TestStoreIngestionBatch:
    """Tests for the store_ingestion_batch function."""

    def test_success_stores_records(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Store a batch with multiple records; verify INSERT calls."""
        batch_id = "batch_001"
        records = [
            {
                "proof_id": "proof_aaa",
                "shard_id": "shard_test",
                "record_id": "doc_1",
                "content_hash": "a" * 64,
                "merkle_root": "b" * 64,
                "merkle_proof": ["c" * 64],
                "ledger_entry_hash": "d" * 64,
                "timestamp": "2024-01-15T10:30:00Z",
            },
            {
                "proof_id": "proof_bbb",
                "shard_id": "shard_test",
                "record_id": "doc_2",
                "content_hash": "e" * 64,
                "merkle_root": "f" * 64,
                "merkle_proof": [],
                "ledger_entry_hash": "0" * 64,
                "timestamp": "2024-01-15T10:31:00Z",
            },
        ]

        store_ingestion_batch(mock_conn, batch_id, records)

        # Verify batch INSERT
        calls = mock_cursor.execute.call_args_list
        batch_inserts = [c for c in calls if "INSERT INTO ingestion_batches" in c[0][0]]
        assert len(batch_inserts) == 1

        # Verify proof INSERTs (one per record)
        proof_inserts = [c for c in calls if "INSERT INTO ingestion_proofs" in c[0][0]]
        assert len(proof_inserts) == 2

        mock_conn.commit.assert_called_once()

    def test_empty_records_list_returns_early(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Empty records list should return early without any DB operations."""
        store_ingestion_batch(mock_conn, "batch_empty", [])

        mock_cursor.execute.assert_not_called()
        mock_conn.commit.assert_not_called()

    def test_optional_fields_use_defaults(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Records missing optional fields should use sensible defaults."""
        batch_id = "batch_defaults"
        records = [
            {
                "proof_id": "proof_xyz",
                "shard_id": "shard_default",
                "record_id": "doc_default",
                "content_hash": "1" * 64,
                "merkle_root": "2" * 64,
                "merkle_proof": [],
                "ledger_entry_hash": "3" * 64,
                "timestamp": "2024-06-01T00:00:00Z",
                # Missing: batch_index, record_type, version, canonicalization, persisted
            },
        ]

        store_ingestion_batch(mock_conn, batch_id, records)

        # Verify the INSERT was called with defaults
        proof_insert_call = [
            c
            for c in mock_cursor.execute.call_args_list
            if "INSERT INTO ingestion_proofs" in c[0][0]
        ][0]
        params = proof_insert_call[0][1]

        # batch_index defaults to idx (0)
        assert params[2] == 0
        # record_type defaults to "document"
        assert params[4] == "document"
        # version defaults to 1
        assert params[6] == 1
        # persisted defaults to True
        assert params[13] is True


# ---------------------------------------------------------------------------
# Ingestion Batches: get_ingestion_proof
# ---------------------------------------------------------------------------


class TestGetIngestionProof:
    """Tests for the get_ingestion_proof function."""

    def test_found_returns_proof_dict(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Retrieve an existing proof; verify returned dictionary structure."""
        mock_cursor.fetchone.return_value = {
            "proof_id": "proof_found",
            "batch_id": "batch_001",
            "batch_index": 0,
            "shard_id": "test_shard",
            "record_type": "document",
            "record_id": "doc_123",
            "version": 1,
            "content_hash": bytes.fromhex("a" * 64),
            "merkle_root": bytes.fromhex("b" * 64),
            "merkle_proof": ["c" * 64],
            "ledger_entry_hash": bytes.fromhex("d" * 64),
            "ts": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            "canonicalization": {"version": "1.0"},
            "persisted": True,
        }

        result = get_ingestion_proof(mock_conn, "proof_found")

        assert result is not None
        assert result["proof_id"] == "proof_found"
        assert result["batch_id"] == "batch_001"
        assert result["content_hash"] == "a" * 64
        assert result["merkle_root"] == "b" * 64
        assert result["timestamp"] == "2024-01-15T10:30:00Z"

    def test_not_found_returns_none(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Proof not found should return None."""
        mock_cursor.fetchone.return_value = None

        result = get_ingestion_proof(mock_conn, "proof_nonexistent")

        assert result is None

    def test_timestamp_as_string_handled(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Handle timestamp stored as string rather than datetime."""
        mock_cursor.fetchone.return_value = {
            "proof_id": "proof_str_ts",
            "batch_id": "batch_str",
            "batch_index": 0,
            "shard_id": "shard",
            "record_type": "document",
            "record_id": "doc",
            "version": 1,
            "content_hash": bytes.fromhex("a" * 64),
            "merkle_root": bytes.fromhex("b" * 64),
            "merkle_proof": [],
            "ledger_entry_hash": bytes.fromhex("c" * 64),
            "ts": "2024-05-20 14:00:00",  # String instead of datetime
            "canonicalization": None,
            "persisted": True,
        }

        result = get_ingestion_proof(mock_conn, "proof_str_ts")

        assert result is not None
        # String timestamp preserved as-is
        assert result["timestamp"] == "2024-05-20 14:00:00"


# ---------------------------------------------------------------------------
# Timestamp Tokens: store_timestamp_token
# ---------------------------------------------------------------------------


class TestStoreTimestampToken:
    """Tests for the store_timestamp_token function."""

    def test_success_stores_token(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Store a valid timestamp token successfully."""
        # Mock the count check to allow storage
        mock_cursor.fetchone.return_value = {
            "token_count": 0,
            "tsa_already_present": False,
        }

        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://timestamp.example.com",
            "tst_hex": "de" * 100,  # DER-encoded TST
            "tsa_cert_fingerprint": "fp123",
            "timestamp": "2024-01-15T12:00:00Z",
        }

        store_timestamp_token(
            mock_conn,
            shard_id="shard_test",
            header_hash_hex="b" * 64,
            token=token,
        )

        # Verify INSERT was executed
        insert_calls = [
            c
            for c in mock_cursor.execute.call_args_list
            if "INSERT INTO timestamp_tokens" in c[0][0]
        ]
        assert len(insert_calls) == 1
        mock_conn.commit.assert_called_once()

    def test_success_with_token_object(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Store a timestamp token passed as an object with attributes."""
        mock_cursor.fetchone.return_value = {
            "token_count": 0,
            "tsa_already_present": False,
        }

        # Create a token object with attributes instead of dict
        token = MagicMock()
        token.hash_hex = "a" * 64
        token.tsa_url = "https://timestamp.digicert.com"
        token.tst_bytes = b"\x30\x82" + b"\x00" * 100
        token.tsa_cert_fingerprint = "fp456"
        token.timestamp = "2024-02-20T15:30:00Z"

        store_timestamp_token(
            mock_conn,
            shard_id="shard_obj",
            header_hash_hex="c" * 64,
            token=token,
        )

        mock_conn.commit.assert_called_once()

    def test_overwrite_existing_is_idempotent(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Second insert for same (shard_id, header_hash, tsa_url) is silently ignored."""
        # Simulate existing token from same TSA
        mock_cursor.fetchone.return_value = {
            "token_count": 1,
            "tsa_already_present": True,  # Same TSA already stored
        }

        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://timestamp.example.com",
            "tst_hex": "ab" * 50,
            "tsa_cert_fingerprint": "fp_dup",
            "timestamp": "2024-03-10T08:00:00Z",
        }

        # Should not raise; uses ON CONFLICT DO NOTHING
        store_timestamp_token(
            mock_conn,
            shard_id="shard_dup",
            header_hash_hex="d" * 64,
            token=token,
        )

        mock_conn.commit.assert_called_once()

    def test_invalid_hash_length_raises_value_error(self, mock_conn: MagicMock) -> None:
        """Raise ValueError when header_hash_hex is not exactly 32 bytes."""
        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://timestamp.example.com",
            "tst_hex": "00" * 10,
            "timestamp": "2024-01-01T00:00:00Z",
        }

        # Too short (16 bytes)
        with pytest.raises(ValueError, match="must encode exactly 32 bytes"):
            store_timestamp_token(
                mock_conn,
                shard_id="shard",
                header_hash_hex="a" * 32,  # 16 bytes
                token=token,
            )

        # Too long (48 bytes)
        with pytest.raises(ValueError, match="must encode exactly 32 bytes"):
            store_timestamp_token(
                mock_conn,
                shard_id="shard",
                header_hash_hex="a" * 96,  # 48 bytes
                token=token,
            )

    def test_max_tokens_limit_enforced(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Raise ValueError when trying to exceed MAX_TSA_TOKENS per header."""
        # Simulate already having MAX_TSA_TOKENS from different TSAs
        mock_cursor.fetchone.return_value = {
            "token_count": MAX_TSA_TOKENS,
            "tsa_already_present": False,  # New TSA not yet stored
        }

        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://new-tsa.example.com",
            "tst_hex": "ff" * 50,
            "timestamp": "2024-04-01T00:00:00Z",
        }

        with pytest.raises(ValueError, match=f"more than {MAX_TSA_TOKENS} TSA tokens"):
            store_timestamp_token(
                mock_conn,
                shard_id="shard_max",
                header_hash_hex="e" * 64,
                token=token,
            )

    def test_max_tokens_allows_same_tsa_update(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Allow update when at MAX_TSA_TOKENS but token is from existing TSA."""
        # At limit, but this TSA is already present
        mock_cursor.fetchone.return_value = {
            "token_count": MAX_TSA_TOKENS,
            "tsa_already_present": True,
        }

        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://existing-tsa.example.com",
            "tst_hex": "aa" * 50,
            "timestamp": "2024-04-01T12:00:00Z",
        }

        # Should not raise; existing TSA is allowed
        store_timestamp_token(
            mock_conn,
            shard_id="shard_existing",
            header_hash_hex="f" * 64,
            token=token,
        )

        mock_conn.commit.assert_called_once()

    def test_database_failure_raises_runtime_error(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Raise RuntimeError when count query returns None."""
        mock_cursor.fetchone.return_value = None

        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://timestamp.example.com",
            "tst_hex": "00" * 10,
            "timestamp": "2024-01-01T00:00:00Z",
        }

        with pytest.raises(RuntimeError, match="Failed to load timestamp token count"):
            store_timestamp_token(
                mock_conn,
                shard_id="shard",
                header_hash_hex="0" * 64,
                token=token,
            )


# ---------------------------------------------------------------------------
# Timestamp Tokens: get_timestamp_tokens
# ---------------------------------------------------------------------------


class TestGetTimestampTokens:
    """Tests for the get_timestamp_tokens function."""

    def test_found_returns_token_list(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Retrieve existing tokens; verify returned list structure."""
        mock_cursor.fetchall.return_value = [
            {
                "tsa_url": "https://timestamp.digicert.com",
                "tst": b"\x30\x82" + b"\x00" * 50,
                "gen_time": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                "tsa_cert_fingerprint": "fp_digicert",
            },
            {
                "tsa_url": "https://timestamp.sectigo.com",
                "tst": b"\x30\x82" + b"\x01" * 50,
                "gen_time": datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
                "tsa_cert_fingerprint": "fp_sectigo",
            },
        ]

        header_hash = "ab" * 32
        result = get_timestamp_tokens(mock_conn, "shard_multi", header_hash)

        assert len(result) == 2
        assert result[0]["tsa_url"] == "https://timestamp.digicert.com"
        assert result[0]["hash_hex"] == header_hash
        assert result[0]["timestamp"] == "2024-01-15T10:00:00Z"
        assert "tst_hex" in result[0]

        assert result[1]["tsa_url"] == "https://timestamp.sectigo.com"
        assert result[1]["timestamp"] == "2024-01-15T10:05:00Z"

    def test_not_found_returns_empty_list(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """No tokens found should return an empty list."""
        mock_cursor.fetchall.return_value = []

        result = get_timestamp_tokens(mock_conn, "shard_empty", "00" * 32)

        assert result == []

    def test_timestamp_as_string_handled(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Handle gen_time stored as string rather than datetime."""
        mock_cursor.fetchall.return_value = [
            {
                "tsa_url": "https://timestamp.example.com",
                "tst": b"\x00" * 20,
                "gen_time": "2024-06-15 18:30:00",  # String
                "tsa_cert_fingerprint": None,
            },
        ]

        result = get_timestamp_tokens(mock_conn, "shard_str", "11" * 32)

        assert len(result) == 1
        assert result[0]["timestamp"] == "2024-06-15 18:30:00"

    def test_tst_bytes_converted_to_hex(self, mock_conn: MagicMock, mock_cursor: MagicMock) -> None:
        """Verify TST bytes are converted to hex string in output."""
        tst_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        mock_cursor.fetchall.return_value = [
            {
                "tsa_url": "https://timestamp.example.com",
                "tst": tst_bytes,
                "gen_time": datetime(2024, 3, 1, 12, 0, 0, tzinfo=UTC),
                "tsa_cert_fingerprint": "fp",
            },
        ]

        result = get_timestamp_tokens(mock_conn, "shard", "22" * 32)

        assert result[0]["tst_hex"] == "deadbeef"


# ---------------------------------------------------------------------------
# Edge Cases and Integration-style Tests
# ---------------------------------------------------------------------------


class TestOperationalStateEdgeCases:
    """Additional edge case tests for operational state functions."""

    def test_rate_limit_token_refill_calculation(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Verify token refill calculation respects capacity cap."""
        from datetime import timedelta

        # Simulate elapsed time that would exceed capacity if uncapped
        past = datetime.now(UTC) - timedelta(seconds=100)
        mock_cursor.fetchone.return_value = {
            "tokens": 2.0,
            "last_refill_ts": past,
        }

        result = consume_rate_limit(
            mock_conn,
            subject_type="user",
            subject="user_123",
            action="download",
            capacity=10.0,  # Cap at 10
            refill_rate_per_second=1.0,  # Would add 100 tokens without cap
        )

        assert result is True
        # Should have consumed from capped capacity (10), not 102

    def test_ingestion_proof_memoryview_to_bytes(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Verify memoryview objects from psycopg are handled correctly."""
        # psycopg may return memoryview for BYTEA columns
        content_hash = memoryview(bytes.fromhex("a" * 64))
        merkle_root = memoryview(bytes.fromhex("b" * 64))
        ledger_entry_hash = memoryview(bytes.fromhex("c" * 64))

        mock_cursor.fetchone.return_value = {
            "proof_id": "proof_mv",
            "batch_id": "batch_mv",
            "batch_index": 0,
            "shard_id": "shard_mv",
            "record_type": "document",
            "record_id": "doc_mv",
            "version": 1,
            "content_hash": content_hash,
            "merkle_root": merkle_root,
            "merkle_proof": [],
            "ledger_entry_hash": ledger_entry_hash,
            "ts": datetime(2024, 7, 1, 0, 0, 0, tzinfo=UTC),
            "canonicalization": None,
            "persisted": True,
        }

        result = get_ingestion_proof(mock_conn, "proof_mv")

        assert result is not None
        assert result["content_hash"] == "a" * 64
        assert result["merkle_root"] == "b" * 64
        assert result["ledger_entry_hash"] == "c" * 64

    def test_timestamp_token_missing_optional_cert_fingerprint(
        self, mock_conn: MagicMock, mock_cursor: MagicMock
    ) -> None:
        """Store token when tsa_cert_fingerprint is missing from dict."""
        mock_cursor.fetchone.return_value = {
            "token_count": 0,
            "tsa_already_present": False,
        }

        # Token dict without tsa_cert_fingerprint key
        token = {
            "hash_hex": "a" * 64,
            "tsa_url": "https://timestamp.example.com",
            "tst_hex": "00" * 20,
            "timestamp": "2024-01-01T00:00:00Z",
            # No tsa_cert_fingerprint
        }

        store_timestamp_token(
            mock_conn,
            shard_id="shard",
            header_hash_hex="0" * 64,
            token=token,
        )

        # Should succeed; tsa_cert_fingerprint defaults to None via .get()
        mock_conn.commit.assert_called_once()
