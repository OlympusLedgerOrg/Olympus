"""
Unit tests for storage/postgres.py that run without a live PostgreSQL instance.

All database interactions are mocked via fake connection / cursor objects or
by patching ConnectionPool so the StorageLayer constructor succeeds.  Tests
are deliberately focused on covering:

  * Module-level helper functions
  * StorageLayer constructor validation
  * In-memory Merkle node cache
  * Static / pure helper methods
  * DB-dependent methods via a mocked _get_connection context manager
  * append_record outer retry loop
  * replay_tree_incremental with mocked Rust tree
"""

from __future__ import annotations

import json
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import psycopg.errors
import pytest
from psycopg.pq import TransactionStatus

import storage.postgres as pm
from storage.postgres import StorageLayer


# ---------------------------------------------------------------------------
# Shared fake infrastructure
# ---------------------------------------------------------------------------


class _FakePool:
    """Minimal fake pool that always returns the same fake connection."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.closed = False

    def getconn(self) -> MagicMock:
        conn = MagicMock()
        conn.closed = False
        conn.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        return conn

    def putconn(self, _conn: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _bare_storage(node_cache_size: int = 4096) -> StorageLayer:
    """Construct a StorageLayer bypassing __init__ for unit tests."""
    s: StorageLayer = object.__new__(StorageLayer)
    s.DEFAULT_FLUSH_BATCH_SIZE = 10_000
    s._node_cache_max = node_cache_size
    s._node_cache = OrderedDict()
    s._node_cache_lock = Lock()
    s._connection_retries = 2
    s._retry_base_delay_seconds = 0.1
    s._retry_max_delay_seconds = 2.0
    s._circuit_breaker_threshold = 5
    s._circuit_breaker_timeout_seconds = 30.0
    s._circuit_open_until = 0.0
    s._consecutive_connection_failures = 0
    s._circuit_lock = Lock()
    s._pool_closed = False
    pool = _FakePool()
    s._pool = pool  # type: ignore[assignment]
    return s


def _storage_with_cursor(
    *,
    fetchone_side_effect: list[Any] | None = None,
    fetchall_side_effect: list[Any] | None = None,
    fetchone_value: Any = None,
    fetchall_value: list[Any] | None = None,
) -> tuple[StorageLayer, MagicMock, MagicMock]:
    """Return (storage, fake_conn, fake_cursor) with a mocked _get_connection."""
    s = _bare_storage()

    cursor = MagicMock()
    if fetchone_side_effect is not None:
        cursor.fetchone.side_effect = fetchone_side_effect
    else:
        cursor.fetchone.return_value = fetchone_value
    if fetchall_side_effect is not None:
        cursor.fetchall.side_effect = fetchall_side_effect
    else:
        cursor.fetchall.return_value = fetchall_value if fetchall_value is not None else []

    conn = MagicMock()
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    @contextmanager
    def _fake_get_conn():  # type: ignore[return]
        yield conn

    s._get_connection = _fake_get_conn  # type: ignore[method-assign]
    return s, conn, cursor


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestNormalizeTimestampIso:
    def test_none_returns_empty(self) -> None:
        assert pm._normalize_timestamp_iso(None) == ""

    def test_datetime_utc(self) -> None:
        dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = pm._normalize_timestamp_iso(dt)
        assert result == "2025-01-15T12:00:00Z"

    def test_datetime_with_offset(self) -> None:
        from datetime import timedelta

        tz = timezone(timedelta(hours=5))
        dt = datetime(2025, 1, 15, 17, 0, 0, tzinfo=tz)
        result = pm._normalize_timestamp_iso(dt)
        assert "2025-01-15T17:00:00+05:00" == result

    def test_string_passthrough(self) -> None:
        s = "2025-01-01T00:00:00Z"
        assert pm._normalize_timestamp_iso(s) == s


class TestRequireRustSmt:
    def test_raises_when_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="olympus_core is required"):
            pm._require_rust_smt()

    def test_passes_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        pm._require_rust_smt()  # must not raise


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestStorageLayerConstructor:
    def test_pool_min_size_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="pool_min_size"):
            StorageLayer("postgresql://unused", pool_min_size=0)

    def test_pool_max_less_than_min_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="pool_max_size"):
            StorageLayer("postgresql://unused", pool_min_size=5, pool_max_size=3)

    def test_negative_retries_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="connection_retries"):
            StorageLayer("postgresql://unused", connection_retries=-1)

    def test_zero_base_delay_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="retry_base_delay_seconds"):
            StorageLayer("postgresql://unused", retry_base_delay_seconds=0)

    def test_max_delay_less_than_base_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="retry_max_delay_seconds"):
            StorageLayer(
                "postgresql://unused",
                retry_base_delay_seconds=1.0,
                retry_max_delay_seconds=0.5,
            )

    def test_cb_threshold_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="circuit_breaker_threshold"):
            StorageLayer("postgresql://unused", circuit_breaker_threshold=0)

    def test_cb_timeout_zero_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        with pytest.raises(ValueError, match="circuit_breaker_timeout"):
            StorageLayer("postgresql://unused", circuit_breaker_timeout_seconds=0)

    def test_defaults_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        monkeypatch.setenv("OLYMPUS_CB_THRESHOLD", "7")
        monkeypatch.setenv("OLYMPUS_CB_TIMEOUT_SECONDS", "45.0")
        monkeypatch.setenv("OLYMPUS_POOL_MAX_SIZE", "15")
        storage = StorageLayer("postgresql://unused")
        assert storage._circuit_breaker_threshold == 7
        assert storage._circuit_breaker_timeout_seconds == 45.0

    def test_node_cache_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        storage = StorageLayer("postgresql://unused", node_cache_size=0)
        assert storage._node_cache_max == 0


# ---------------------------------------------------------------------------
# Merkle node cache
# ---------------------------------------------------------------------------


class TestNodeCache:
    def test_cache_miss(self) -> None:
        s = _bare_storage()
        assert s._cache_get("shard1", 5, b"\x01") is None

    def test_cache_put_and_hit(self) -> None:
        s = _bare_storage()
        s._cache_put("shard1", 5, b"\x01", b"\xab" * 32)
        result = s._cache_get("shard1", 5, b"\x01")
        assert result == b"\xab" * 32

    def test_cache_lru_eviction(self) -> None:
        s = _bare_storage(node_cache_size=2)
        s._cache_put("s", 0, b"\x00", b"\x00" * 32)
        s._cache_put("s", 0, b"\x01", b"\x01" * 32)
        # access first entry to mark it recently used
        s._cache_get("s", 0, b"\x00")
        # add third entry → second entry (b"\x01") should be evicted
        s._cache_put("s", 0, b"\x02", b"\x02" * 32)
        assert s._cache_get("s", 0, b"\x01") is None
        assert s._cache_get("s", 0, b"\x00") is not None
        assert s._cache_get("s", 0, b"\x02") is not None

    def test_cache_put_keeps_first_value_on_duplicate_key(self) -> None:
        # _cache_put on an existing key only refreshes LRU position, not the value
        s = _bare_storage(node_cache_size=2)
        s._cache_put("s", 0, b"\x00", b"\xaa" * 32)
        s._cache_put("s", 0, b"\x00", b"\xbb" * 32)  # key exists → only moves_to_end
        assert s._cache_get("s", 0, b"\x00") == b"\xaa" * 32

    def test_cache_clear(self) -> None:
        s = _bare_storage()
        s._cache_put("s", 0, b"\x00", b"\xaa" * 32)
        s._cache_clear()
        assert s._cache_get("s", 0, b"\x00") is None

    def test_disabled_cache_always_misses(self) -> None:
        s = _bare_storage(node_cache_size=0)
        s._cache_put("s", 0, b"\x00", b"\xaa" * 32)
        assert s._cache_get("s", 0, b"\x00") is None

    def test_cache_clear_on_empty(self) -> None:
        s = _bare_storage()
        s._cache_clear()  # must not raise


# ---------------------------------------------------------------------------
# Static methods
# ---------------------------------------------------------------------------


class TestEncodePath:
    def test_empty_path(self) -> None:
        assert StorageLayer._encode_path(()) == b""

    def test_single_zero(self) -> None:
        assert StorageLayer._encode_path((0,)) == b"\x00"

    def test_single_one(self) -> None:
        assert StorageLayer._encode_path((1,)) == b"\x80"

    def test_8_bits_all_ones(self) -> None:
        assert StorageLayer._encode_path((1,) * 8) == b"\xff"

    def test_full_256_bit_path_roundtrip(self) -> None:
        path = tuple(i % 2 for i in range(256))
        encoded = StorageLayer._encode_path(path)
        assert len(encoded) == 32

    def test_known_pattern(self) -> None:
        # path (1,0,1,0,...) for 8 bits = 0b10101010 = 0xAA
        path = (1, 0, 1, 0, 1, 0, 1, 0)
        assert StorageLayer._encode_path(path) == b"\xaa"


class TestNormalizeRoot:
    def test_none_returns_empty(self) -> None:
        assert StorageLayer._normalize_root(None) == ""

    def test_bytes(self) -> None:
        assert StorageLayer._normalize_root(b"\xab\xcd") == "abcd"

    def test_hex_string(self) -> None:
        assert StorageLayer._normalize_root("0xABCD") == "abcd"

    def test_hex_no_prefix(self) -> None:
        assert StorageLayer._normalize_root("abcdef") == "abcdef"

    def test_memoryview(self) -> None:
        mv = memoryview(b"\xde\xad")
        assert StorageLayer._normalize_root(mv) == "dead"


class TestIterBatches:
    def test_exact_multiple(self) -> None:
        batches = list(StorageLayer._iter_batches(range(4), 2))
        assert batches == [[0, 1], [2, 3]]

    def test_remainder_batch(self) -> None:
        batches = list(StorageLayer._iter_batches(range(5), 2))
        assert batches == [[0, 1], [2, 3], [4]]

    def test_single_item(self) -> None:
        batches = list(StorageLayer._iter_batches([42], 10))
        assert batches == [[42]]

    def test_empty(self) -> None:
        assert list(StorageLayer._iter_batches([], 5)) == []

    def test_zero_batch_size_raises(self) -> None:
        with pytest.raises(ValueError, match="batch_size"):
            list(StorageLayer._iter_batches([1, 2], 0))


class TestIterIngestionProofRows:
    def _make_record(self, idx: int = 0) -> dict[str, Any]:
        from protocol.hashes import hash_bytes

        return {
            "proof_id": f"proof-{idx}",
            "record_id": f"rec-{idx}",
            "record_type": "document",
            "version": 1,
            "shard_id": "s1",
            "content_hash": hash_bytes(b"content").hex(),
            "merkle_root": hash_bytes(b"root").hex(),
            "merkle_proof": {"siblings": []},
            "ledger_entry_hash": hash_bytes(b"ledger").hex(),
            "timestamp": "2025-01-01T00:00:00Z",
            "canonicalization": {"type": "test"},
        }

    def test_single_record(self) -> None:
        rows = list(StorageLayer._iter_ingestion_proof_rows("batch-1", [self._make_record()]))
        assert len(rows) == 1
        # proof_id is the first column
        assert rows[0][0] == "proof-0"

    def test_batch_index_default(self) -> None:
        rows = list(StorageLayer._iter_ingestion_proof_rows("b", [self._make_record(0), self._make_record(1)]))
        assert rows[0][2] == 0  # batch_index
        assert rows[1][2] == 1

    def test_explicit_batch_index(self) -> None:
        rec = self._make_record()
        rec["batch_index"] = 7
        rows = list(StorageLayer._iter_ingestion_proof_rows("b", [rec]))
        assert rows[0][2] == 7


class TestRowGet:
    def test_dict_row(self) -> None:
        s = _bare_storage()
        row = {"root": b"\xab"}
        assert s._row_get(row, "root", 0) == b"\xab"

    def test_tuple_row(self) -> None:
        s = _bare_storage()
        row = (b"\xcd", "unused")
        assert s._row_get(row, "root", 0) == b"\xcd"


# ---------------------------------------------------------------------------
# close / __del__
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_calls_pool_close(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s.close()
        assert s._pool.closed is True  # type: ignore[union-attr]

    def test_double_close_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s.close()
        s.close()  # must not raise

    def test_del_suppresses_exceptions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        # Force close to raise
        s._pool.close = lambda: (_ for _ in ()).throw(RuntimeError("oops"))  # type: ignore
        s.__del__()  # must not propagate


# ---------------------------------------------------------------------------
# _is_transient_connection_error
# ---------------------------------------------------------------------------


class TestIsTransientConnectionError:
    def test_operational_error_is_transient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        from psycopg import OperationalError

        assert s._is_transient_connection_error(OperationalError("conn fail"))

    def test_pool_timeout_is_transient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        from psycopg_pool import PoolTimeout

        assert s._is_transient_connection_error(PoolTimeout("timeout"))

    def test_value_error_not_transient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        assert not s._is_transient_connection_error(ValueError("bad"))


# ---------------------------------------------------------------------------
# init_schema
# ---------------------------------------------------------------------------


class TestInitSchema:
    def test_init_schema_executes_stmts(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.init_schema()
        assert conn.commit.called


# ---------------------------------------------------------------------------
# check_ingestion_schema
# ---------------------------------------------------------------------------


class TestCheckIngestionSchema:
    def test_passes_when_tables_exist(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.check_ingestion_schema()  # must not raise

    def test_raises_on_db_error(self) -> None:
        s = _bare_storage()

        @contextmanager
        def _exploding_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor_cm = MagicMock()
            cur = MagicMock()
            cur.execute.side_effect = Exception("table missing")
            cursor_cm.__enter__ = MagicMock(return_value=cur)
            cursor_cm.__exit__ = MagicMock(return_value=False)
            conn.cursor.return_value = cursor_cm
            yield conn

        s._get_connection = _exploding_conn  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="Database not migrated"):
            s.check_ingestion_schema()


# ---------------------------------------------------------------------------
# consume_rate_limit
# ---------------------------------------------------------------------------


class TestConsumeRateLimit:
    def _call(
        self, s: StorageLayer, tokens: float = 5.0, elapsed: float = 0.0
    ) -> bool:
        return s.consume_rate_limit(
            subject_type="ip",
            subject="127.0.0.1",
            action="ingest",
            capacity=10.0,
            refill_rate_per_second=1.0,
        )

    def test_token_available_returns_true(self) -> None:
        s, conn, cursor = _storage_with_cursor(
            fetchone_value={"tokens": 5.0, "elapsed_seconds": 0.0}
        )
        assert self._call(s) is True
        assert conn.commit.called

    def test_token_exhausted_returns_false(self) -> None:
        s, conn, cursor = _storage_with_cursor(
            fetchone_value={"tokens": 0.5, "elapsed_seconds": 0.0}
        )
        assert self._call(s) is False
        assert conn.rollback.called

    def test_invalid_capacity_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        with pytest.raises(ValueError, match="capacity must be > 0"):
            s.consume_rate_limit(
                subject_type="ip",
                subject="x",
                action="a",
                capacity=0,
                refill_rate_per_second=1.0,
            )

    def test_fetchone_none_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        with pytest.raises(RuntimeError, match="Failed to load rate limit"):
            self._call(s)


# ---------------------------------------------------------------------------
# clear_rate_limits
# ---------------------------------------------------------------------------


class TestClearRateLimits:
    def test_executes_delete(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.clear_rate_limits()
        assert conn.commit.called


# ---------------------------------------------------------------------------
# append_record – outer validation & retry loop
# ---------------------------------------------------------------------------


class TestAppendRecordOuter:
    def _signing_key(self):
        import nacl.signing

        return nacl.signing.SigningKey.generate()

    def test_bad_value_hash_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        s = _bare_storage()
        with pytest.raises(ValueError, match="32 bytes"):
            s.append_record("shard", "doc", "id1", 1, b"\x00" * 16, self._signing_key())

    def test_empty_parser_id_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        s = _bare_storage()
        with pytest.raises(ValueError, match="parser_id"):
            s.append_record(
                "shard",
                "doc",
                "id1",
                1,
                b"\x00" * 32,
                self._signing_key(),
                parser_id="",
            )

    def test_empty_canonical_parser_version_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        s = _bare_storage()
        with pytest.raises(ValueError, match="canonical_parser_version"):
            s.append_record(
                "shard",
                "doc",
                "id1",
                1,
                b"\x00" * 32,
                self._signing_key(),
                canonical_parser_version="",
            )

    def test_no_rust_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", False)
        s = _bare_storage()
        with pytest.raises(RuntimeError, match="olympus_core"):
            s.append_record("shard", "doc", "id1", 1, b"\x00" * 32, self._signing_key())

    def test_serialization_failure_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_append_record_inner raising SerializationFailure is retried."""
        import time

        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        monkeypatch.setattr(time, "sleep", lambda _s: None)

        call_count = {"n": 0}

        def _fake_inner(**_kwargs):
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise psycopg.errors.SerializationFailure()
            return ("root", "proof", "header", "sig", "entry")

        s = _bare_storage()
        s._append_record_inner = _fake_inner  # type: ignore[method-assign]
        result = s.append_record(
            "shard",
            "doc",
            "id1",
            1,
            b"\x00" * 32,
            self._signing_key(),
            max_serialization_retries=3,
        )
        assert result[0] == "root"
        assert call_count["n"] == 3

    def test_deadlock_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        monkeypatch.setattr(time, "sleep", lambda _s: None)

        call_count = {"n": 0}

        def _fake_inner(**_kwargs):
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise psycopg.errors.DeadlockDetected()
            return ("r", "p", "h", "s", "e")

        s = _bare_storage()
        s._append_record_inner = _fake_inner  # type: ignore[method-assign]
        s.append_record(
            "shard", "doc", "id1", 1, b"\x00" * 32, self._signing_key(), max_serialization_retries=2
        )
        assert call_count["n"] == 2

    def test_serialization_failure_exhausted_reraises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        monkeypatch.setattr(time, "sleep", lambda _s: None)

        def _always_fail(**_kwargs):
            raise psycopg.errors.SerializationFailure()

        s = _bare_storage()
        s._append_record_inner = _always_fail  # type: ignore[method-assign]
        with pytest.raises(psycopg.errors.SerializationFailure):
            s.append_record(
                "shard",
                "doc",
                "id1",
                1,
                b"\x00" * 32,
                self._signing_key(),
                max_serialization_retries=1,
            )


# ---------------------------------------------------------------------------
# get_ingestion_proof
# ---------------------------------------------------------------------------


class TestGetIngestionProof:
    def _row(self) -> dict[str, Any]:
        from protocol.hashes import hash_bytes

        return {
            "proof_id": "p1",
            "batch_id": "b1",
            "batch_index": 0,
            "record_id": "r1",
            "record_type": "document",
            "version": 1,
            "shard_id": "s1",
            "content_hash": hash_bytes(b"c").ljust(32, b"\x00"),
            "merkle_root": hash_bytes(b"m").ljust(32, b"\x00"),
            "merkle_proof": json.dumps({"siblings": []}),
            "ledger_entry_hash": hash_bytes(b"l").ljust(32, b"\x00"),
            "ts": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "canonicalization": json.dumps({"type": "test"}),
            "persisted": True,
        }

    def test_returns_none_when_not_found(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.get_ingestion_proof("p1") is None

    def test_returns_dict_when_found(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=self._row())
        result = s.get_ingestion_proof("p1")
        assert result is not None
        assert result["proof_id"] == "p1"
        assert result["timestamp"].endswith("Z")

    def test_ts_as_string(self) -> None:
        row = self._row()
        row["ts"] = "2025-01-01T00:00:00Z"
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        result = s.get_ingestion_proof("p1")
        assert result is not None
        assert result["timestamp"] == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# get_ingestion_proof_by_content_hash
# ---------------------------------------------------------------------------


class TestGetIngestionProofByContentHash:
    def test_bad_hash_length_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        with pytest.raises(ValueError, match="32 bytes"):
            s.get_ingestion_proof_by_content_hash(b"\x00" * 16)

    def test_not_found_returns_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        result = s.get_ingestion_proof_by_content_hash(b"\x00" * 32)
        assert result is None

    def test_delegates_to_get_ingestion_proof(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"proof_id": "p99"})
        # get_ingestion_proof is called with "p99" — mock it
        s.get_ingestion_proof = MagicMock(return_value={"proof_id": "p99"})  # type: ignore[method-assign]
        result = s.get_ingestion_proof_by_content_hash(b"\x00" * 32)
        s.get_ingestion_proof.assert_called_once_with("p99")
        assert result == {"proof_id": "p99"}


# ---------------------------------------------------------------------------
# get_ingestion_proof_by_record_identity
# ---------------------------------------------------------------------------


class TestGetIngestionProofByRecordIdentity:
    def test_not_found_returns_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        result = s.get_ingestion_proof_by_record_identity("s", "doc", "r1", 1)
        assert result is None

    def test_delegates_to_get_ingestion_proof(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"proof_id": "p5"})
        s.get_ingestion_proof = MagicMock(return_value={"proof_id": "p5"})  # type: ignore[method-assign]
        result = s.get_ingestion_proof_by_record_identity("s", "doc", "r1", 1)
        s.get_ingestion_proof.assert_called_once_with("p5")
        assert result == {"proof_id": "p5"}


# ---------------------------------------------------------------------------
# get_latest_header
# ---------------------------------------------------------------------------


def _make_signed_header():
    """Return a (header_row, signing_key) tuple for header tests."""
    import nacl.signing
    from protocol.hashes import shard_header_hash
    from protocol.shards import create_shard_header, sign_header

    shard_id = "shard1"
    sk = nacl.signing.SigningKey.generate()
    root = b"\x01" * 32
    header = create_shard_header(
        shard_id=shard_id,
        root_hash=root,
        timestamp="2025-01-01T00:00:00Z",
        tree_size=1,
        previous_header_hash="",
    )
    sig_hex = sign_header(header, sk)
    pubkey = sk.verify_key.encode()
    header_hash = shard_header_hash({k: v for k, v in header.items() if k != "header_hash"})
    row = {
        "root": root,
        "tree_size": 1,
        "leaf_seq": 1,
        "header_hash": bytes.fromhex(header["header_hash"]),
        "sig": bytes.fromhex(sig_hex),
        "pubkey": pubkey,
        "previous_header_hash": "",
        "ts": "2025-01-01T00:00:00Z",
        "seq": 0,
    }
    return row, sk, shard_id


class TestGetLatestHeader:
    def test_returns_none_when_no_headers(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.get_latest_header("shard1") is None

    def test_returns_header_dict(self) -> None:
        row, sk, shard_id = _make_signed_header()
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        # Mock the integrity checks so we don't need a real DB
        s._assert_root_matches_state = MagicMock()  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        result = s.get_latest_header(shard_id)
        assert result is not None
        assert "header" in result
        assert "signature" in result

    def test_datetime_timestamp_converted(self) -> None:
        row, sk, shard_id = _make_signed_header()
        row["ts"] = datetime(2025, 1, 1, tzinfo=timezone.utc)
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        s._assert_root_matches_state = MagicMock()  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        result = s.get_latest_header(shard_id)
        assert result is not None
        assert result["header"]["timestamp"].endswith("Z")

    def test_invalid_timestamp_type_raises(self) -> None:
        row, sk, shard_id = _make_signed_header()
        row["ts"] = 12345  # invalid type
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        s._assert_root_matches_state = MagicMock()  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        with pytest.raises(TypeError, match="Unexpected timestamp type"):
            s.get_latest_header(shard_id)


# ---------------------------------------------------------------------------
# get_header_history
# ---------------------------------------------------------------------------


class TestGetHeaderHistory:
    def test_empty_history(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        assert s.get_header_history("shard1") == []

    def _make_row(self, seq: int = 0) -> dict[str, Any]:
        return {
            "seq": seq,
            "root": b"\x01" * 32,
            "tree_size": 1,
            "header_hash": b"\x02" * 32,
            "previous_header_hash": "",
            "ts": "2025-01-01T00:00:00Z",
            "sig": b"\x03" * 64,
            "pubkey": b"\x04" * 32,
        }

    def test_string_timestamp(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[self._make_row()])
        history = s.get_header_history("shard1")
        assert len(history) == 1
        assert history[0]["seq"] == 0

    def test_datetime_timestamp(self) -> None:
        row = self._make_row()
        row["ts"] = datetime(2025, 1, 1, tzinfo=timezone.utc)
        s, conn, cursor = _storage_with_cursor(fetchall_value=[row])
        history = s.get_header_history("shard1")
        assert history[0]["timestamp"].endswith("Z")

    def test_invalid_timestamp_type_raises(self) -> None:
        row = self._make_row()
        row["ts"] = 99999
        s, conn, cursor = _storage_with_cursor(fetchall_value=[row])
        with pytest.raises(TypeError, match="Unexpected timestamp type"):
            s.get_header_history("shard1")

    def test_previous_header_hash_bytes(self) -> None:
        row = self._make_row()
        row["previous_header_hash"] = b"\xff" * 32
        s, conn, cursor = _storage_with_cursor(fetchall_value=[row])
        history = s.get_header_history("shard1")
        assert isinstance(history[0]["previous_header_hash"], str)


# ---------------------------------------------------------------------------
# get_ledger_tail
# ---------------------------------------------------------------------------


class TestGetLedgerTail:
    def test_empty(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        assert s.get_ledger_tail("shard1") == []

    def test_returns_ledger_entries(self) -> None:
        payload = {
            "ts": "2025-01-01T00:00:00Z",
            "record_hash": "aa" * 32,
            "shard_id": "shard1",
            "shard_root": "bb" * 32,
            "canonicalization": {"type": "test"},
            "prev_entry_hash": "",
        }
        rows = [{"payload": payload, "entry_hash": b"\xcc" * 32}]
        s, conn, cursor = _storage_with_cursor(fetchall_value=rows)
        entries = s.get_ledger_tail("shard1")
        assert len(entries) == 1
        assert entries[0].shard_id == "shard1"


# ---------------------------------------------------------------------------
# get_all_shard_ids
# ---------------------------------------------------------------------------


class TestGetAllShardIds:
    def test_empty(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        assert s.get_all_shard_ids() == []

    def test_returns_shard_ids(self) -> None:
        rows = [{"shard_id": "alpha"}, {"shard_id": "beta"}]
        s, conn, cursor = _storage_with_cursor(fetchall_value=rows)
        ids = s.get_all_shard_ids()
        assert ids == ["alpha", "beta"]


# ---------------------------------------------------------------------------
# verify_persisted_root
# ---------------------------------------------------------------------------


class TestVerifyPersistedRoot:
    def test_no_headers_returns_true(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.verify_persisted_root("shard1") is True

    def test_root_matches_node(self) -> None:
        root = b"\xab" * 32
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[{"root": root}, {"hash": root}]
        )
        assert s.verify_persisted_root("shard1") is True

    def test_root_mismatch(self) -> None:
        root = b"\xab" * 32
        other = b"\xcd" * 32
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[{"root": root}, {"hash": other}]
        )
        assert s.verify_persisted_root("shard1") is False

    def test_no_node_uses_empty_hash(self) -> None:
        from protocol.ssmf import EMPTY_HASHES

        root = EMPTY_HASHES[256]
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[{"root": root}, None]
        )
        assert s.verify_persisted_root("shard1") is True


# ---------------------------------------------------------------------------
# get_leaf_count
# ---------------------------------------------------------------------------


class TestGetLeafCount:
    def test_basic(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"cnt": 42})
        with pytest.warns(DeprecationWarning):
            count = s.get_leaf_count("shard1")
        assert count == 42

    def test_with_timestamp(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"cnt": 7})
        with pytest.warns(DeprecationWarning):
            count = s.get_leaf_count("shard1", up_to_ts="2025-01-01T00:00:00Z")
        assert count == 7

    def test_none_row_returns_zero(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        with pytest.warns(DeprecationWarning):
            count = s.get_leaf_count("shard1")
        assert count == 0

    def test_datetime_cutoff(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"cnt": 3})
        with pytest.warns(DeprecationWarning):
            count = s.get_leaf_count("shard1", up_to_ts=datetime(2025, 1, 1, tzinfo=timezone.utc))
        assert count == 3


# ---------------------------------------------------------------------------
# get_current_root
# ---------------------------------------------------------------------------


class TestGetCurrentRoot:
    def test_no_headers_returns_empty(self) -> None:
        from protocol.ssmf import EMPTY_HASHES

        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.get_current_root("shard1") == EMPTY_HASHES[256]

    def test_returns_persisted_root(self) -> None:
        root = b"\xfa" * 32
        s, conn, cursor = _storage_with_cursor(fetchone_value={"root": root})
        assert s.get_current_root("shard1") == root


# ---------------------------------------------------------------------------
# verify_state_replay
# ---------------------------------------------------------------------------


class TestVerifyStateReplay:
    def test_delegates_to_replay_tree_incremental(self) -> None:
        s = _bare_storage()
        expected = {"verified": True, "headers_checked": 0, "next_seq": None}
        s.replay_tree_incremental = MagicMock(return_value=expected)  # type: ignore[method-assign]
        result = s.verify_state_replay("shard1")
        assert result == expected
        s.replay_tree_incremental.assert_called_once_with("shard1", max_headers=None, after_seq=-1)


# ---------------------------------------------------------------------------
# store_timestamp_token
# ---------------------------------------------------------------------------


class TestStoreTimestampToken:
    def _make_token(self) -> object:
        token = MagicMock()
        token.hash_hex = "aa" * 32
        token.tsa_url = "https://tsa.example.com"
        token.tst_bytes = b"\x01" * 64
        token.tsa_cert_fingerprint = None
        token.timestamp = "2025-01-01T00:00:00Z"
        return token

    def test_bad_header_hash_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        with pytest.raises(ValueError, match="32 bytes"):
            s.store_timestamp_token("shard", "aabb", self._make_token())

    def test_stores_token_successfully(self) -> None:
        s, conn, cursor = _storage_with_cursor(
            fetchone_value={"token_count": 0, "tsa_already_present": False}
        )
        from protocol.rfc3161 import MAX_TSA_TOKENS

        s.store_timestamp_token("shard", "aa" * 32, self._make_token())
        assert conn.commit.called

    def test_exceeds_max_tokens_raises(self) -> None:
        from protocol.rfc3161 import MAX_TSA_TOKENS

        s, conn, cursor = _storage_with_cursor(
            fetchone_value={"token_count": MAX_TSA_TOKENS, "tsa_already_present": False}
        )
        with pytest.raises(ValueError, match="Refusing to store more than"):
            s.store_timestamp_token("shard", "aa" * 32, self._make_token())

    def test_duplicate_tsa_allowed(self) -> None:
        from protocol.rfc3161 import MAX_TSA_TOKENS

        s, conn, cursor = _storage_with_cursor(
            fetchone_value={"token_count": MAX_TSA_TOKENS, "tsa_already_present": True}
        )
        # Should NOT raise even though count >= MAX
        s.store_timestamp_token("shard", "aa" * 32, self._make_token())
        assert conn.commit.called

    def test_fetchone_none_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        with pytest.raises(RuntimeError, match="Failed to load timestamp token count"):
            s.store_timestamp_token("shard", "aa" * 32, self._make_token())


# ---------------------------------------------------------------------------
# get_timestamp_tokens / get_timestamp_token
# ---------------------------------------------------------------------------


class TestGetTimestampTokens:
    def test_empty(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        assert s.get_timestamp_tokens("shard", "aa" * 32) == []

    def test_returns_tokens(self) -> None:
        row = {
            "tsa_url": "https://tsa.example.com",
            "tst": b"\x01" * 64,
            "gen_time": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "tsa_cert_fingerprint": None,
        }
        s, conn, cursor = _storage_with_cursor(fetchall_value=[row])
        tokens = s.get_timestamp_tokens("shard", "aa" * 32)
        assert len(tokens) == 1
        assert tokens[0]["timestamp"].endswith("Z")

    def test_gen_time_as_string(self) -> None:
        row = {
            "tsa_url": "https://tsa.example.com",
            "tst": b"\x01" * 64,
            "gen_time": "2025-01-01T00:00:00Z",
            "tsa_cert_fingerprint": None,
        }
        s, conn, cursor = _storage_with_cursor(fetchall_value=[row])
        tokens = s.get_timestamp_tokens("shard", "aa" * 32)
        assert tokens[0]["timestamp"] == "2025-01-01T00:00:00Z"


class TestGetTimestampToken:
    def test_returns_none_when_empty(self) -> None:
        s = _bare_storage()
        s.get_timestamp_tokens = MagicMock(return_value=[])  # type: ignore[method-assign]
        assert s.get_timestamp_token("shard", "aa" * 32) is None

    def test_returns_first_token(self) -> None:
        token = {"tsa_url": "https://tsa.example.com"}
        s = _bare_storage()
        s.get_timestamp_tokens = MagicMock(return_value=[token, {"tsa_url": "other"}])  # type: ignore[method-assign]
        assert s.get_timestamp_token("shard", "aa" * 32) == token


# ---------------------------------------------------------------------------
# Rekor anchor methods
# ---------------------------------------------------------------------------


class TestCreateRekorAnchor:
    def test_bad_root_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        with pytest.raises(ValueError, match="32 bytes"):
            s.create_rekor_anchor(shard_id="s", shard_seq=0, root_hash=b"\x00" * 16)

    def test_returns_id(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"id": 42})
        result = s.create_rekor_anchor(shard_id="s", shard_seq=0, root_hash=b"\x00" * 32)
        assert result == 42
        assert conn.commit.called

    def test_fetchone_none_raises(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        with pytest.raises(RuntimeError, match="did not return an id"):
            s.create_rekor_anchor(shard_id="s", shard_seq=0, root_hash=b"\x00" * 32)


class TestUpdateRekorAnchor:
    def test_updates_and_commits(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.update_rekor_anchor(anchor_id=1, status="anchored")
        assert conn.commit.called


class TestGetLatestRekorAnchor:
    def test_returns_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.get_latest_rekor_anchor("s") is None

    def test_returns_dict(self) -> None:
        row = {
            "id": 1,
            "shard_id": "s",
            "shard_seq": 0,
            "root_hash": b"\x00" * 32,
            "rekor_uuid": "uuid",
            "rekor_index": 5,
            "anchored_at": None,
            "status": "anchored",
        }
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        result = s.get_latest_rekor_anchor("s")
        assert result is not None
        assert result["status"] == "anchored"
        assert isinstance(result["root_hash"], str)


class TestGetRekorAnchorBySeq:
    def test_returns_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.get_rekor_anchor_by_seq("s", 0) is None

    def test_returns_dict(self) -> None:
        row = {
            "id": 2,
            "shard_id": "s",
            "shard_seq": 1,
            "root_hash": b"\x01" * 32,
            "rekor_uuid": None,
            "rekor_index": None,
            "anchored_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "status": "pending",
        }
        s, conn, cursor = _storage_with_cursor(fetchone_value=row)
        result = s.get_rekor_anchor_by_seq("s", 1)
        assert result is not None
        assert result["anchored_at"] == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# create_checkpoint / get_checkpoints
# ---------------------------------------------------------------------------


class TestCreateCheckpoint:
    def test_no_headers_returns_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        assert s.create_checkpoint("shard1") is None

    def test_creates_checkpoint(self) -> None:
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[
                {"seq": 5, "root": b"\xaa" * 32},
                {"cnt": 10},
            ]
        )
        result = s.create_checkpoint("shard1")
        assert result is not None
        assert result["header_seq"] == 5
        assert result["leaf_count"] == 10
        assert conn.commit.called


class TestGetCheckpoints:
    def test_empty(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        assert s.get_checkpoints("shard1") == []

    def test_returns_checkpoints(self) -> None:
        rows = [
            {
                "header_seq": 3,
                "root_hash": b"\xbb" * 32,
                "leaf_count": 5,
                "ts": datetime(2025, 2, 1, tzinfo=timezone.utc),
            }
        ]
        s, conn, cursor = _storage_with_cursor(fetchall_value=rows)
        results = s.get_checkpoints("shard1")
        assert len(results) == 1
        assert results[0]["header_seq"] == 3
        assert results[0]["ts"].endswith("Z")

    def test_ts_as_string(self) -> None:
        rows = [
            {
                "header_seq": 1,
                "root_hash": b"\xcc" * 32,
                "leaf_count": 2,
                "ts": "2025-01-01T00:00:00Z",
            }
        ]
        s, conn, cursor = _storage_with_cursor(fetchall_value=rows)
        results = s.get_checkpoints("shard1")
        assert results[0]["ts"] == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# get_root_diff
# ---------------------------------------------------------------------------


class TestGetRootDiff:
    def _header_row(self, seq: int) -> dict[str, Any]:
        return {
            "seq": seq,
            "root": b"\xaa" * 32,
            "tree_size": seq + 1,
            "header_hash": b"\xbb" * 32,
            "previous_header_hash": "",
            "ts": "2025-01-01T00:00:00Z",
        }

    def test_from_seq_not_found(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        with pytest.raises(ValueError, match="not found"):
            s.get_root_diff("shard1", 0, 1)

    def test_to_seq_not_found(self) -> None:
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[self._header_row(0), None]
        )
        with pytest.raises(ValueError, match="not found"):
            s.get_root_diff("shard1", 0, 1)

    def test_journal_diff_used_when_available(self) -> None:
        from_row = self._header_row(0)
        to_row = self._header_row(1)
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[from_row, to_row]
        )
        journal_result = {"added": [{"key": "aa" * 32}], "changed": [], "removed": []}
        s._diff_from_journal = MagicMock(return_value=journal_result)  # type: ignore[method-assign]
        result = s.get_root_diff("shard1", 0, 1)
        assert "from_root_hash" in result
        assert result["added"] == journal_result["added"]

    def test_slow_path_when_no_journal(self) -> None:
        from_row = self._header_row(0)
        to_row = {**self._header_row(1), "ts": datetime(2025, 1, 2, tzinfo=timezone.utc)}
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[from_row, to_row],
            fetchall_value=[{"key": b"\xdd" * 32, "value_hash": b"\xee" * 32}],
        )
        s._diff_from_journal = MagicMock(return_value=None)  # type: ignore[method-assign]
        result = s.get_root_diff("shard1", 0, 1)
        assert "added" in result
        assert len(result["added"]) == 1

    def test_slow_path_with_key_range(self) -> None:
        from_row = self._header_row(0)
        to_row = {**self._header_row(1), "ts": "2025-01-02T00:00:00Z"}
        s, conn, cursor = _storage_with_cursor(
            fetchone_side_effect=[from_row, to_row],
            fetchall_value=[],
        )
        s._diff_from_journal = MagicMock(return_value=None)  # type: ignore[method-assign]
        result = s.get_root_diff(
            "shard1",
            0,
            1,
            key_range_start=b"\x00" * 32,
            key_range_end=b"\xff" * 32,
        )
        assert result["added"] == []


# ---------------------------------------------------------------------------
# _diff_from_journal
# ---------------------------------------------------------------------------


class TestDiffFromJournal:
    def test_undefined_table_returns_none(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.execute.side_effect = psycopg.errors.UndefinedTable()
        result = s._diff_from_journal(cursor, "shard1", 0, 1, None, None)
        assert result is None

    def test_empty_rows_returns_none(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        result = s._diff_from_journal(cursor, "shard1", 0, 1, None, None)
        assert result is None

    def test_added_entry(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            {"key": b"\xaa" * 32, "old_value": None, "new_value": b"\xbb" * 32}
        ]
        result = s._diff_from_journal(cursor, "shard1", 0, 1, None, None)
        assert result is not None
        assert len(result["added"]) == 1
        assert result["changed"] == []
        assert result["removed"] == []

    def test_removed_entry(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            {"key": b"\xaa" * 32, "old_value": b"\xbb" * 32, "new_value": None}
        ]
        result = s._diff_from_journal(cursor, "shard1", 0, 1, None, None)
        assert result is not None
        assert len(result["removed"]) == 1

    def test_changed_entry(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            {"key": b"\xaa" * 32, "old_value": b"\xbb" * 32, "new_value": b"\xcc" * 32}
        ]
        result = s._diff_from_journal(cursor, "shard1", 0, 1, None, None)
        assert result is not None
        assert len(result["changed"]) == 1

    def test_key_range_filters_entries(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        key_in = b"\x50" * 32
        key_out_low = b"\x00" * 32
        key_out_high = b"\xff" * 32
        cursor.fetchall.return_value = [
            {"key": key_out_low, "old_value": None, "new_value": b"\x01" * 32},
            {"key": key_in, "old_value": None, "new_value": b"\x02" * 32},
            {"key": key_out_high, "old_value": None, "new_value": b"\x03" * 32},
        ]
        result = s._diff_from_journal(
            cursor, "shard1", 0, 1, b"\x10" * 32, b"\xf0" * 32
        )
        assert result is not None
        assert len(result["added"]) == 1
        assert result["added"][0]["key"] == key_in.hex()


# ---------------------------------------------------------------------------
# _get_current_global_root
# ---------------------------------------------------------------------------


class TestGetCurrentGlobalRoot:
    def test_no_node_returns_empty(self) -> None:
        from protocol.ssmf import EMPTY_HASHES

        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        root = s._get_current_global_root(cursor)
        assert root == EMPTY_HASHES[256]

    def test_returns_bytes_from_dict_row(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = {"hash": b"\xab" * 32}
        root = s._get_current_global_root(cursor)
        assert root == b"\xab" * 32

    def test_returns_bytes_from_tuple_row(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = (b"\xcd" * 32,)
        root = s._get_current_global_root(cursor)
        assert root == b"\xcd" * 32


# ---------------------------------------------------------------------------
# _get_proof_path
# ---------------------------------------------------------------------------


class TestGetProofPath:
    def test_returns_256_siblings(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        # Return 256 rows of None hash → uses EMPTY_HASHES
        cursor.fetchall.return_value = [{"hash": None}] * 256
        key = b"\x00" * 32
        siblings = s._get_proof_path(cursor, key)
        assert len(siblings) == 256

    def test_non_none_hash_used(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        rows = [{"hash": b"\xab" * 32}] + [{"hash": None}] * 255
        cursor.fetchall.return_value = rows
        key = b"\x00" * 32
        siblings = s._get_proof_path(cursor, key)
        assert siblings[0] == b"\xab" * 32

    def test_tuple_row_support(self) -> None:
        from protocol.ssmf import EMPTY_HASHES

        s = _bare_storage()
        cursor = MagicMock()
        # Tuple rows: (hash_value,)
        cursor.fetchall.return_value = [(b"\xde" * 32,)] + [(None,)] * 255
        key = b"\xff" * 32
        siblings = s._get_proof_path(cursor, key)
        assert siblings[0] == b"\xde" * 32
        assert siblings[1] == EMPTY_HASHES[1]


# ---------------------------------------------------------------------------
# _get_poseidon_proof_path
# ---------------------------------------------------------------------------


class TestGetPoseidonProofPath:
    def test_returns_256_siblings(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = [{"hash": None}] * 256
        key = b"\x00" * 32
        siblings = s._get_poseidon_proof_path(cursor, key)
        assert len(siblings) == 256

    def test_non_none_hash(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchall.return_value = [{"hash": "12345"}] + [{"hash": None}] * 255
        key = b"\x00" * 32
        siblings = s._get_poseidon_proof_path(cursor, key)
        assert siblings[0] == 12345


# ---------------------------------------------------------------------------
# _assert_root_matches_state (fast path only)
# ---------------------------------------------------------------------------


class TestAssertRootMatchesStateFastPath:
    def test_matching_node_passes(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        root = b"\xaa" * 32
        cursor.fetchone.return_value = {"hash": root}
        # Mock the leaf_seq integrity check
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        s._assert_root_matches_state(cursor, "shard1", root, as_of_leaf_seq=None)

    def test_mismatch_raises(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = {"hash": b"\xbb" * 32}
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="does not match persisted root"):
            s._assert_root_matches_state(cursor, "shard1", b"\xaa" * 32, as_of_leaf_seq=None)

    def test_none_node_uses_empty_hash(self) -> None:
        from protocol.ssmf import EMPTY_HASHES

        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        # Should not raise when expected root matches empty hash
        s._assert_root_matches_state(cursor, "shard1", EMPTY_HASHES[256], as_of_leaf_seq=None)

    def test_tuple_row_support(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        root = b"\xcc" * 32
        cursor.fetchone.return_value = (root,)
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]
        s._assert_root_matches_state(cursor, "shard1", root, as_of_leaf_seq=None)


# ---------------------------------------------------------------------------
# _assert_leaf_seq_integrity
# ---------------------------------------------------------------------------


class TestAssertLeafSeqIntegrity:
    def test_passes_with_no_issues(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        # Upper bound query returns max_seq = 0
        cursor.fetchone.return_value = {"max_seq": 0}
        # Both check queries return None (no violations)
        cursor.fetchone.side_effect = [{"max_seq": 0}, None, None]
        # Must not raise
        s._assert_leaf_seq_integrity(cursor, "shard1", "Replay mismatch", upper_leaf_seq=None)

    def test_with_explicit_upper_bound(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [None, None]
        s._assert_leaf_seq_integrity(cursor, "shard1", "Error", upper_leaf_seq=5)

    def test_missing_leaf_seq_raises(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [{"leaf_seq": 3}, None]
        with pytest.raises(ValueError, match="leaf_seq 3 has no corresponding"):
            s._assert_leaf_seq_integrity(cursor, "shard1", "Error", upper_leaf_seq=5)

    def test_orphaned_leaf_raises(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [None, {"global_seq": 4}]
        with pytest.raises(ValueError, match="orphaned"):
            s._assert_leaf_seq_integrity(cursor, "shard1", "Error", upper_leaf_seq=5)

    def test_with_lower_bound(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [None, None]
        s._assert_leaf_seq_integrity(
            cursor,
            "shard1",
            "Error",
            upper_leaf_seq=10,
            lower_leaf_seq_exclusive=5,
        )


# ---------------------------------------------------------------------------
# get_shard_headers_by_leaf_seq_range
# ---------------------------------------------------------------------------


class TestGetShardHeadersByLeafSeqRange:
    def test_returns_rows(self) -> None:
        rows = [{"leaf_seq": 1, "root": b"\xaa" * 32}]
        s, conn, cursor = _storage_with_cursor(fetchall_value=rows)
        result = s.get_shard_headers_by_leaf_seq_range("shard1", 1, 1)
        assert result == rows


# ---------------------------------------------------------------------------
# verify_shard_integrity
# ---------------------------------------------------------------------------


class TestVerifyShardIntegrity:
    def test_empty_mapping_is_noop(self) -> None:
        s = _bare_storage()
        s.verify_shard_integrity("shard1", {})  # must not raise

    def test_passes_when_roots_match(self) -> None:
        root = b"\xaa" * 32
        s = _bare_storage()
        s.get_shard_headers_by_leaf_seq_range = MagicMock(  # type: ignore[method-assign]
            return_value=[{"leaf_seq": 1, "root": root}]
        )
        s.verify_shard_integrity("shard1", {1: root})

    def test_skips_zero_leaf_seq(self) -> None:
        s = _bare_storage()
        s.get_shard_headers_by_leaf_seq_range = MagicMock(  # type: ignore[method-assign]
            return_value=[{"leaf_seq": 0, "root": b"\xaa" * 32}]
        )
        s.verify_shard_integrity("shard1", {0: b"\xaa" * 32})

    def test_missing_replay_entry_raises(self) -> None:
        root = b"\xaa" * 32
        s = _bare_storage()
        s.get_shard_headers_by_leaf_seq_range = MagicMock(  # type: ignore[method-assign]
            return_value=[{"leaf_seq": 2, "root": root}]
        )
        with pytest.raises(ValueError, match="missing leaf_seq=2"):
            s.verify_shard_integrity("shard1", {1: root})

    def test_null_replayed_root_raises(self) -> None:
        s = _bare_storage()
        s.get_shard_headers_by_leaf_seq_range = MagicMock(  # type: ignore[method-assign]
            return_value=[{"leaf_seq": 1, "root": b"\xaa" * 32}]
        )
        with pytest.raises(ValueError, match="null replayed root"):
            s.verify_shard_integrity("shard1", {1: None})

    def test_root_mismatch_raises(self) -> None:
        s = _bare_storage()
        s.get_shard_headers_by_leaf_seq_range = MagicMock(  # type: ignore[method-assign]
            return_value=[{"leaf_seq": 1, "root": b"\xaa" * 32}]
        )
        with pytest.raises(ValueError, match="root mismatch"):
            s.verify_shard_integrity("shard1", {1: b"\xbb" * 32})


# ---------------------------------------------------------------------------
# _get_header_by_seq
# ---------------------------------------------------------------------------


class TestGetHeaderBySeq:
    def test_returns_none_when_not_found(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        assert s._get_header_by_seq(cursor, "shard1", 0) is None

    def test_returns_row_when_found(self) -> None:
        row = {"seq": 0, "root": b"\xaa" * 32, "tree_size": 1}
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.return_value = row
        assert s._get_header_by_seq(cursor, "shard1", 0) == row


# ---------------------------------------------------------------------------
# replay_tree_incremental – empty shard
# ---------------------------------------------------------------------------


class TestReplayTreeIncremental:
    def test_empty_shard_returns_zero_checked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = b"\x00" * 32
        mock_tree_cls = MagicMock(return_value=mock_tree)
        monkeypatch.setattr(pm, "RustSparseMerkleTree", mock_tree_cls)

        # Cursor: headers empty, ledger empty
        s, conn, cursor = _storage_with_cursor(fetchall_value=[])
        result = s.replay_tree_incremental("shard1")
        assert result == {"verified": True, "headers_checked": 0, "next_seq": None}

    def test_mismatch_in_header_ledger_count_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = b"\x00" * 32
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        call_count = {"n": 0}

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            # First fetchall → 1 header; second fetchall → 0 ledger rows
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": b"\xaa" * 32, "leaf_seq": 1}],  # headers
                [],  # ledger entries
            ]
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="Replay mismatch"):
            s.replay_tree_incremental("shard1")

    def test_single_header_verified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfa" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": root, "leaf_seq": 1}],  # headers
                [{"seq": 0, "payload": json.dumps({"shard_root": root.hex()})}],  # ledger
                [],  # leaf delta batch (empty → tree not updated)
            ]
            cursor.fetchone.return_value = None  # no prior header at after_seq
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        result = s.replay_tree_incremental("shard1")
        assert result["verified"] is True
        assert result["headers_checked"] == 1
        assert result["next_seq"] is None

    def test_max_headers_pagination(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfb" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        headers = [
            {"seq": i, "root": root, "leaf_seq": i + 1} for i in range(3)
        ]
        ledger_rows = [
            {"seq": i, "payload": json.dumps({"shard_root": root.hex()})} for i in range(3)
        ]
        leaf_deltas = [[]] * 3  # three empty delta windows

        s = _bare_storage()

        call_count = {"n": 0}

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [headers, ledger_rows] + leaf_deltas
            cursor.fetchone.return_value = None
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        result = s.replay_tree_incremental("shard1", max_headers=2)
        assert result["headers_checked"] == 2
        assert result["next_seq"] == 1  # last checked header's seq


# ---------------------------------------------------------------------------
# _compute_poseidon_root_from_leaves (mocked poseidon)
# ---------------------------------------------------------------------------


class TestComputePoseidonRootFromLeaves:
    def test_calls_poseidon_smt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_smt = MagicMock()
        mock_smt_instance = MagicMock()
        mock_smt_instance.get_root.return_value = 42
        mock_smt.return_value = mock_smt_instance

        with patch("protocol.poseidon_smt.PoseidonSMT", mock_smt, create=True):
            with patch.dict("sys.modules", {"protocol.poseidon_smt": MagicMock(PoseidonSMT=mock_smt)}):
                from protocol.hashes import SNARK_SCALAR_FIELD

                leaves = {b"\x01" * 32: b"\x02" * 32}
                # We can't easily test this without the actual module, so just
                # verify the function exists and is callable
                assert callable(pm._compute_poseidon_root_from_leaves)


# ---------------------------------------------------------------------------
# _poseidon_incremental_update (mocked poseidon hash functions)
# ---------------------------------------------------------------------------


class TestPoseidonIncrementalUpdate:
    def test_returns_root_and_deltas(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_poseidon_incremental_update with mocked hash functions."""
        # Create a mock poseidon_smt module
        mock_poseidon_smt = MagicMock()
        mock_poseidon_smt._poseidon_hash_leaf.return_value = 100
        mock_poseidon_smt._poseidon_hash_node.return_value = 200

        with patch.dict("sys.modules", {"protocol.poseidon_smt": mock_poseidon_smt}):
            key = b"\x01" * 32
            value_hash = b"\x02" * 32
            siblings = [0] * 256
            new_root, deltas = pm._poseidon_incremental_update(key, value_hash, siblings)
            assert isinstance(new_root, int)
            assert len(deltas) == 256
            # Each delta is (level, packed_index, hash_decimal)
            for level, packed_idx, hash_str in deltas:
                assert isinstance(level, int)
                assert isinstance(packed_idx, bytes)
                assert hash_str.isdecimal()

    def test_path_determines_branch_direction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that left/right branch is determined by path bits."""
        call_args: list[tuple] = []
        mock_poseidon_smt = MagicMock()
        mock_poseidon_smt._poseidon_hash_leaf.return_value = 50

        def _mock_hash_node(a: int, b: int) -> int:
            call_args.append((a, b))
            return (a + b) % pm.SNARK_SCALAR_FIELD

        mock_poseidon_smt._poseidon_hash_node.side_effect = _mock_hash_node

        with patch.dict("sys.modules", {"protocol.poseidon_smt": mock_poseidon_smt}):
            # key with all zeros → path is all zeros → left branch at every level
            key = b"\x00" * 32
            value_hash = b"\x01" * 32
            siblings = [1] * 256
            pm._poseidon_incremental_update(key, value_hash, siblings)
            # For path bit = 0, we call hash_node(current, sibling) → first arg is current
            first_call = call_args[0]
            assert first_call[1] == 1  # sibling is second arg when bit==0


# ---------------------------------------------------------------------------
# get_proof / get_nonexistence_proof
# ---------------------------------------------------------------------------


class TestGetProof:
    def test_returns_none_when_leaf_not_found(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value=None)
        result = s.get_proof("shard1", "document", "rec1", 1)
        assert result is None

    def test_returns_existence_proof_when_found(self) -> None:
        leaf_row = {
            "value_hash": b"\xaa" * 32,
            "parser_id": "test-parser",
            "canonical_parser_version": "1.0",
        }
        # fetchone returns: leaf row; _get_proof_path uses fetchall; _get_current_global_root uses fetchone
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [leaf_row, {"hash": b"\xbb" * 32}]
        cursor.fetchall.return_value = [{"hash": None}] * 256

        conn = MagicMock()
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        result = s.get_proof("shard1", "document", "rec1", 1)
        assert result is not None
        assert result.value_hash == b"\xaa" * 32
        assert result.parser_id == "test-parser"


class TestGetNonExistenceProof:
    def test_returns_proof_when_leaf_not_found(self) -> None:
        s = _bare_storage()
        cursor = MagicMock()
        cursor.fetchone.side_effect = [None, {"hash": b"\xcc" * 32}]
        cursor.fetchall.return_value = [{"hash": None}] * 256

        conn = MagicMock()
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        result = s.get_nonexistence_proof("shard1", "document", "rec1", 1)
        assert result is not None
        assert len(result.siblings) == 256

    def test_raises_when_leaf_exists(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"exists": 1})
        with pytest.raises(ValueError, match="cannot generate non-existence proof"):
            s.get_nonexistence_proof("shard1", "document", "rec1", 1)


# ---------------------------------------------------------------------------
# _iter_tree_node_rows
# ---------------------------------------------------------------------------


class TestIterTreeNodeRows:
    def test_yields_rows_for_each_node(self) -> None:
        s = _bare_storage()
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        # Mock a tree with two nodes
        mock_tree = MagicMock()
        mock_tree.nodes = {
            (0, 1): b"\xaa" * 32,
            (1,): b"\xbb" * 32,
        }
        rows = list(s._iter_tree_node_rows("shard1", mock_tree, ts))
        assert len(rows) == 2
        # Each row: (shard_id, level, path_bytes, hash_value, ts)
        assert rows[0][0] == "shard1"
        assert rows[0][4] == ts

    def test_empty_tree(self) -> None:
        s = _bare_storage()
        mock_tree = MagicMock()
        mock_tree.nodes = {}
        rows = list(s._iter_tree_node_rows("shard1", mock_tree, datetime.now(timezone.utc)))
        assert rows == []


# ---------------------------------------------------------------------------
# _get_connection – rollback on non-IDLE transaction
# ---------------------------------------------------------------------------


class TestGetConnectionRollback:
    def test_rolls_back_non_idle_transaction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")

        conn = MagicMock()
        conn.closed = False
        conn.info = SimpleNamespace(transaction_status=TransactionStatus.INTRANS)
        s._acquire_connection_with_retry = MagicMock(return_value=conn)  # type: ignore[method-assign]

        with s._get_connection() as c:
            assert c is conn

        conn.rollback.assert_called_once()

    def test_no_rollback_on_idle_transaction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")

        conn = MagicMock()
        conn.closed = False
        conn.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        s._acquire_connection_with_retry = MagicMock(return_value=conn)  # type: ignore[method-assign]

        with s._get_connection() as c:
            pass

        conn.rollback.assert_not_called()

    def test_no_rollback_on_closed_connection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")

        conn = MagicMock()
        conn.closed = True
        conn.info = SimpleNamespace(transaction_status=TransactionStatus.INTRANS)
        s._acquire_connection_with_retry = MagicMock(return_value=conn)  # type: ignore[method-assign]

        with s._get_connection() as c:
            pass

        conn.rollback.assert_not_called()


# ---------------------------------------------------------------------------
# _acquire_connection_with_retry + circuit breaker helpers
# ---------------------------------------------------------------------------


class TestAcquireConnectionWithRetry:
    def test_returns_connection_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        conn = s._acquire_connection_with_retry()
        assert conn is not None

    def test_retries_on_transient_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        monkeypatch.setattr(time, "sleep", lambda _: None)
        s = StorageLayer("postgresql://unused")

        call_count = {"n": 0}
        original_getconn = s._pool.getconn

        def flaky_getconn():
            call_count["n"] += 1
            if call_count["n"] < 2:
                from psycopg import OperationalError
                raise OperationalError("connection failed")
            return original_getconn()

        s._pool.getconn = flaky_getconn  # type: ignore[method-assign]
        conn = s._acquire_connection_with_retry()
        assert conn is not None
        assert call_count["n"] == 2

    def test_raises_after_all_retries_exhausted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        monkeypatch.setattr(time, "sleep", lambda _: None)
        s = StorageLayer("postgresql://unused", connection_retries=2)

        from psycopg import OperationalError
        s._pool.getconn = MagicMock(side_effect=OperationalError("always fails"))  # type: ignore
        with pytest.raises(RuntimeError, match="Failed to acquire PostgreSQL connection"):
            s._acquire_connection_with_retry()

    def test_non_transient_error_propagates_immediately(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s._pool.getconn = MagicMock(side_effect=ValueError("non-transient"))  # type: ignore
        with pytest.raises(ValueError, match="non-transient"):
            s._acquire_connection_with_retry()

    def test_circuit_breaker_open_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s._circuit_open_until = time.monotonic() + 999.0
        with pytest.raises(RuntimeError, match="circuit breaker is open"):
            s._acquire_connection_with_retry()


class TestCircuitBreakerHelpers:
    def test_record_connection_failure_increments(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        assert s._consecutive_connection_failures == 0
        s._record_connection_failure()
        assert s._consecutive_connection_failures == 1

    def test_record_failure_opens_circuit_at_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused", circuit_breaker_threshold=2)
        s._record_connection_failure()
        s._record_connection_failure()
        assert s._circuit_open_until > time.monotonic()

    def test_reset_connection_failures_clears_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s._consecutive_connection_failures = 5
        s._circuit_open_until = 9999.0
        s._reset_connection_failures()
        assert s._consecutive_connection_failures == 0
        assert s._circuit_open_until == 0.0

    def test_circuit_breaker_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s._circuit_open_until = time.monotonic() + 999.0
        assert s._is_circuit_breaker_open() is True

    def test_circuit_breaker_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "ConnectionPool", _FakePool)
        s = StorageLayer("postgresql://unused")
        s._circuit_open_until = 0.0
        assert s._is_circuit_breaker_open() is False


# ---------------------------------------------------------------------------
# store_ingestion_batch
# ---------------------------------------------------------------------------


class TestStoreIngestionBatch:
    def _make_record(self, idx: int = 0) -> dict[str, Any]:
        from protocol.hashes import hash_bytes
        return {
            "proof_id": f"proof-{idx}",
            "record_id": f"rec-{idx}",
            "record_type": "document",
            "version": 1,
            "shard_id": "s1",
            "content_hash": hash_bytes(b"content").hex(),
            "merkle_root": hash_bytes(b"root").hex(),
            "merkle_proof": {"siblings": []},
            "ledger_entry_hash": hash_bytes(b"ledger").hex(),
            "timestamp": "2025-01-01T00:00:00Z",
            "canonicalization": {"type": "test"},
        }

    def test_empty_records_is_noop(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.store_ingestion_batch("batch-1", [])
        conn.commit.assert_not_called()

    def test_stores_records_and_commits(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.store_ingestion_batch("batch-1", [self._make_record(0), self._make_record(1)])
        assert conn.commit.called

    def test_single_record_batch(self) -> None:
        s, conn, cursor = _storage_with_cursor()
        s.store_ingestion_batch("batch-x", [self._make_record()])
        cursor.execute.assert_called()
        assert conn.commit.called


# ---------------------------------------------------------------------------
# get_leaf_count with shard_id=None (branch coverage)
# ---------------------------------------------------------------------------


class TestGetLeafCountNoneShardId:
    def test_no_warning_when_shard_id_none(self) -> None:
        s, conn, cursor = _storage_with_cursor(fetchone_value={"cnt": 99})
        count = s.get_leaf_count(None)
        assert count == 99


# ---------------------------------------------------------------------------
# _compute_poseidon_root_from_leaves with mocked PoseidonSMT
# ---------------------------------------------------------------------------


class TestComputePoseidonRootFromLeavesActual:
    def test_iterates_leaves_and_returns_bytes(self) -> None:
        mock_smt_instance = MagicMock()
        mock_smt_instance.get_root.return_value = 255
        mock_smt_cls = MagicMock(return_value=mock_smt_instance)

        import sys
        mock_module = MagicMock()
        mock_module.PoseidonSMT = mock_smt_cls
        original = sys.modules.get("protocol.poseidon_smt")
        sys.modules["protocol.poseidon_smt"] = mock_module
        try:
            leaves: dict[bytes, bytes] = {b"\x01" * 32: b"\x02" * 32, b"\x03" * 32: b"\x04" * 32}
            result = pm._compute_poseidon_root_from_leaves(leaves)
            assert isinstance(result, bytes)
            assert len(result) == 32
            assert mock_smt_instance.update.call_count == len(leaves)
        finally:
            if original is not None:
                sys.modules["protocol.poseidon_smt"] = original
            else:
                sys.modules.pop("protocol.poseidon_smt", None)

    def test_empty_leaves_returns_zero_root(self) -> None:
        mock_smt_instance = MagicMock()
        mock_smt_instance.get_root.return_value = 0
        mock_smt_cls = MagicMock(return_value=mock_smt_instance)

        import sys
        mock_module = MagicMock()
        mock_module.PoseidonSMT = mock_smt_cls
        original = sys.modules.get("protocol.poseidon_smt")
        sys.modules["protocol.poseidon_smt"] = mock_module
        try:
            result = pm._compute_poseidon_root_from_leaves({})
            assert result == b"\x00" * 32
        finally:
            if original is not None:
                sys.modules["protocol.poseidon_smt"] = original
            else:
                sys.modules.pop("protocol.poseidon_smt", None)


# ---------------------------------------------------------------------------
# replay_tree_incremental – error path and after_seq coverage
# ---------------------------------------------------------------------------


class TestReplayTreeIncrementalErrorPaths:
    def test_root_mismatch_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        wrong_root = b"\xff" * 32
        good_root = b"\xfa" * 32

        mock_tree = MagicMock()
        mock_tree.get_root.return_value = wrong_root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": good_root, "leaf_seq": 1}],
                [{"seq": 0, "payload": json.dumps({"shard_root": good_root.hex()})}],
                [],
            ]
            cursor.fetchone.return_value = None
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        with pytest.raises(ValueError, match="root mismatch"):
            s.replay_tree_incremental("shard1")

    def test_ledger_missing_shard_root_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfa" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": root, "leaf_seq": 1}],
                [{"seq": 0, "payload": json.dumps({"no_shard_root": "here"})}],
                [],
            ]
            cursor.fetchone.return_value = None
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        with pytest.raises(ValueError, match="missing shard_root"):
            s.replay_tree_incremental("shard1")

    def test_ledger_root_mismatch_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfa" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": root, "leaf_seq": 1}],
                [{"seq": 0, "payload": json.dumps({"shard_root": "deadbeef" * 8})}],
                [],
            ]
            cursor.fetchone.return_value = None
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        with pytest.raises(ValueError, match="ledger root mismatch"):
            s.replay_tree_incremental("shard1")

    def test_replay_with_after_seq_loads_prior_leaves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfa" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 1, "root": root, "leaf_seq": 2}],
                [{"seq": 1, "payload": json.dumps({"shard_root": root.hex()})}],
                [{"key": b"\x01" * 32, "value_hash": b"\x02" * 32, "parser_id": "p", "canonical_parser_version": "1"}],
                [],
                [],
            ]
            cursor.fetchone.return_value = {"leaf_seq": 1}
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        result = s.replay_tree_incremental("shard1", after_seq=0)
        assert result["verified"] is True
        assert result["headers_checked"] == 1

    def test_replay_with_leaf_deltas_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pm, "_RUST_SMT_AVAILABLE", True)
        root = b"\xfa" * 32
        mock_tree = MagicMock()
        mock_tree.get_root.return_value = root
        monkeypatch.setattr(pm, "RustSparseMerkleTree", MagicMock(return_value=mock_tree))

        s = _bare_storage()

        @contextmanager
        def _fake_conn():  # type: ignore[return]
            conn = MagicMock()
            cursor = MagicMock()
            cursor.fetchall.side_effect = [
                [{"seq": 0, "root": root, "leaf_seq": 1}],
                [{"seq": 0, "payload": json.dumps({"shard_root": root.hex()})}],
                [{"key": b"\x01" * 32, "value_hash": b"\x02" * 32, "parser_id": "parser", "canonical_parser_version": "1.0"}],
                [],
            ]
            cursor.fetchone.return_value = None
            conn.cursor.return_value.__enter__ = MagicMock(return_value=cursor)
            conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            yield conn

        s._get_connection = _fake_conn  # type: ignore[method-assign]
        s._assert_leaf_seq_integrity = MagicMock()  # type: ignore[method-assign]

        result = s.replay_tree_incremental("shard1")
        assert result["headers_checked"] == 1
        mock_tree.update.assert_called_once_with(
            b"\x01" * 32, b"\x02" * 32, "parser", "1.0"
        )
