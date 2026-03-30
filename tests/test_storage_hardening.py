"""Unit tests for storage hardening behavior without requiring PostgreSQL."""

from types import SimpleNamespace

import pytest
from psycopg import OperationalError
from psycopg.pq import TransactionStatus

import storage.postgres as postgres_module
from storage.postgres import StorageLayer


class _FakeConnection:
    def __init__(self, status: TransactionStatus = TransactionStatus.IDLE) -> None:
        self.closed = False
        self.info = SimpleNamespace(transaction_status=status)
        self.rollback_calls = 0

    def rollback(self) -> None:
        self.rollback_calls += 1
        self.info.transaction_status = TransactionStatus.IDLE


class _RetryPool:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.getconn_calls = 0
        self.putconn_calls = 0
        self.connection = _FakeConnection()

    def getconn(self) -> _FakeConnection:
        self.getconn_calls += 1
        if self.getconn_calls < 3:
            raise OperationalError("transient outage")
        return self.connection

    def putconn(self, _connection: _FakeConnection) -> None:
        self.putconn_calls += 1

    def close(self) -> None:
        return None


class _AlwaysFailingPool:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.getconn_calls = 0

    def getconn(self) -> _FakeConnection:
        self.getconn_calls += 1
        raise OperationalError("database unavailable")

    def putconn(self, _connection: _FakeConnection) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeCursor:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, sql: str, _params: object) -> None:
        self.statements.append(" ".join(sql.split()))

    def executemany(self, sql: str, _params: object) -> None:
        self.statements.append(" ".join(sql.split()))


class _FakeTree:
    def __init__(self) -> None:
        self.nodes = {(0,): b"\x01" * 32, (1, 0): b"\x02" * 32}


def test_get_connection_retries_transient_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Transient pool failures are retried with backoff before succeeding."""
    monkeypatch.setattr(postgres_module, "ConnectionPool", _RetryPool)
    monkeypatch.setattr(postgres_module.time, "sleep", lambda _seconds: None)
    storage = StorageLayer("postgresql://unused")

    with storage._get_connection() as conn:
        assert conn is storage._pool.connection

    assert storage._pool.getconn_calls == 3
    assert storage._pool.putconn_calls == 1
    assert storage._consecutive_connection_failures == 0


def test_circuit_breaker_opens_after_sustained_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sustained transient failures open the circuit breaker and fail fast."""
    monkeypatch.setattr(postgres_module, "ConnectionPool", _AlwaysFailingPool)
    monkeypatch.setattr(postgres_module.time, "sleep", lambda _seconds: None)
    storage = StorageLayer(
        "postgresql://unused",
        connection_retries=0,
        circuit_breaker_threshold=2,
        circuit_breaker_timeout_seconds=60.0,
    )

    with pytest.raises(RuntimeError, match="Failed to acquire PostgreSQL connection"):
        with storage._get_connection():
            pass

    with pytest.raises(RuntimeError, match="Failed to acquire PostgreSQL connection"):
        with storage._get_connection():
            pass

    with pytest.raises(RuntimeError, match="Database circuit breaker is open"):
        with storage._get_connection():
            pass


def test_get_connection_rolls_back_before_returning_to_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any uncommitted transaction is rolled back before returning connection to pool."""

    class _InTransactionPool(_RetryPool):
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            super().__init__()
            self.connection = _FakeConnection(TransactionStatus.INTRANS)

        def getconn(self) -> _FakeConnection:
            self.getconn_calls += 1
            return self.connection

    monkeypatch.setattr(postgres_module, "ConnectionPool", _InTransactionPool)
    storage = StorageLayer("postgresql://unused")

    with storage._get_connection():
        pass

    assert storage._pool.connection.rollback_calls == 1
    assert storage._pool.putconn_calls == 1


def test_persist_tree_nodes_uses_upsert_without_precheck(monkeypatch: pytest.MonkeyPatch) -> None:
    """SMT node persistence uses ON CONFLICT DO UPDATE to keep smt_nodes current.

    ADR-0001: smt_nodes must reflect the latest tree state so that proof
    generation can read siblings directly (O(256)) instead of rebuilding
    the entire tree from leaves (O(N)).

    The global CD-HS-ST table has no shard_id column (nodes are keyed by
    level+index in the single global tree), so the conflict target is
    ``(level, index)`` — not the old per-shard ``(shard_id, level, index)``.
    """
    monkeypatch.setattr(postgres_module, "ConnectionPool", _RetryPool)
    storage = StorageLayer("postgresql://unused")
    cursor = _FakeCursor()

    storage._persist_tree_nodes(cursor, "shard", _FakeTree())

    assert all("SELECT 1 FROM smt_nodes" not in sql for sql in cursor.statements)
    assert all(
        "ON CONFLICT (level, index)" in sql
        and "DO UPDATE SET hash = EXCLUDED.hash" in sql
        for sql in cursor.statements
    )


def test_fake_cursor_executemany_records_normalized_sql() -> None:
    """Fake cursor tracks batched statements for persistence-path assertions."""
    cursor = _FakeCursor()
    cursor.executemany("INSERT INTO foo  (a)\nVALUES (%s)", [(1,), (2,)])

    assert cursor.statements == ["INSERT INTO foo (a) VALUES (%s)"]
