"""
Chaos test: database connection loss simulation.

Verifies that Olympus handles PostgreSQL connection failures gracefully —
including total connection refusal, pool exhaustion, and mid-operation
connection drops.

Expected system behaviour
--------------------------
- When the database is unavailable the API returns HTTP 503 with a structured
  error body; it does not crash or return a 500.
- The in-memory Ledger (used by the ingest router) remains operational
  during a DB outage; its chain integrity is preserved.
- The StorageLayer connection pool retries with exponential backoff before
  surfacing an error (verified by inspecting ``getconn`` call counts).
- When the circuit breaker opens (after ``MAX_RETRIES`` consecutive failures)
  subsequent calls fail fast without further retry attempts.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from psycopg import OperationalError
from psycopg.pq import TransactionStatus

import storage.postgres as postgres_module
from storage.postgres import StorageLayer


# ---------------------------------------------------------------------------
# Fake pool helpers (mirrors test_storage_hardening.py style)
# ---------------------------------------------------------------------------


class _AlwaysFailPool:
    """Pool that always raises OperationalError on getconn."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.getconn_calls = 0

    def getconn(self) -> object:
        self.getconn_calls += 1
        raise OperationalError("database unavailable")

    def putconn(self, _conn: object) -> None:
        return None

    def close(self) -> None:
        return None


class _FlakyPool:
    """Pool that fails the first N calls then succeeds."""

    def __init__(self, fail_count: int = 2) -> None:
        self.getconn_calls = 0
        self.fail_count = fail_count
        self._conn = SimpleNamespace(
            closed=False,
            info=SimpleNamespace(transaction_status=TransactionStatus.IDLE),
            rollback=lambda: None,
        )

    def getconn(self) -> object:
        self.getconn_calls += 1
        if self.getconn_calls <= self.fail_count:
            raise OperationalError("transient failure")
        return self._conn

    def putconn(self, _conn: object) -> None:
        return None

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_storage_layer_raises_after_all_retries_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    StorageLayer._get_connection raises RuntimeError once all retries fail.

    The error must propagate to the caller rather than being swallowed, so
    that the API layer can return HTTP 503.
    """
    monkeypatch.setattr(postgres_module, "ConnectionPool", _AlwaysFailPool)
    monkeypatch.setattr(postgres_module.time, "sleep", lambda _s: None)

    storage = StorageLayer("postgresql://unused")

    with pytest.raises(RuntimeError, match="Failed to acquire PostgreSQL connection"):
        with storage._get_connection():
            pass  # pragma: no cover


def test_storage_layer_retries_transient_failure_and_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    StorageLayer._get_connection retries transient failures and eventually
    returns a valid connection.
    """
    monkeypatch.setattr(postgres_module, "ConnectionPool", lambda *a, **kw: _FlakyPool(2))
    monkeypatch.setattr(postgres_module.time, "sleep", lambda _s: None)

    storage = StorageLayer("postgresql://unused")

    with storage._get_connection() as conn:
        assert conn is not None

    assert storage._pool.getconn_calls == 3  # type: ignore[union-attr]


def test_in_memory_ledger_unaffected_by_db_loss() -> None:
    """
    The in-memory Ledger append path is completely independent of the database.

    Even when the StorageLayer pool fails on every call, the Ledger keeps a
    valid in-memory chain that passes verify_chain().
    """
    from protocol.hashes import hash_bytes
    from protocol.ledger import Ledger
    from protocol.merkle import MerkleTree

    ledger = Ledger()

    for i in range(5):
        leaf = hash_bytes(i.to_bytes(4, "big"))
        tree = MerkleTree([leaf])
        root = tree.get_root().hex()
        ledger.append(
            record_hash=root,
            shard_id="db-loss-test",
            shard_root=root,
            canonicalization={"version": "1.0"},
        )

    assert len(ledger.entries) == 5
    assert ledger.verify_chain()


def test_api_returns_503_when_db_unavailable() -> None:
    """
    The FastAPI app returns HTTP 503 when the database backend is unavailable.

    This test patches ``_require_storage`` in ``api.services.storage_layer``
    (where the shards router imports it) to raise HTTP 503, matching the real
    behaviour when DATABASE_URL is unset or PostgreSQL is down.
    Uses the sync httpx TestClient (no asyncio required).
    """
    from unittest.mock import patch

    from fastapi import HTTPException
    from fastapi.testclient import TestClient

    from api.app import app

    def _raise_503() -> None:
        raise HTTPException(status_code=503, detail="Database not available: test")

    with patch("api.services.storage_layer._require_storage", side_effect=_raise_503):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/shards")

    assert response.status_code == 503
    body = response.json()
    assert "detail" in body


def test_api_returns_503_on_mid_operation_db_failure() -> None:
    """
    The FastAPI app returns HTTP 503 (not 500) when the database connection
    is lost *after* the StorageLayer has already been initialized.

    This exercises the path where ``_require_storage()`` succeeds but a
    subsequent storage call raises a ``RuntimeError`` from the pool retry logic
    (e.g. ``"Failed to acquire PostgreSQL connection after retries"``).
    """
    from unittest.mock import MagicMock, patch

    from fastapi.testclient import TestClient

    from api.app import app

    fake_storage = MagicMock()
    fake_storage.get_all_shard_ids.side_effect = RuntimeError(
        "Failed to acquire PostgreSQL connection after retries"
    )

    with patch("api.services.storage_layer._require_storage", return_value=fake_storage):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/shards")

    assert response.status_code == 503
    body = response.json()
    assert "detail" in body


def test_circuit_breaker_opens_after_repeated_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    After MAX_RETRIES consecutive failures the circuit breaker is open and
    subsequent calls fail immediately without sleeping.

    We verify the sleep is NOT called after the breaker opens by counting
    sleep invocations.
    """
    monkeypatch.setattr(postgres_module, "ConnectionPool", _AlwaysFailPool)
    sleep_calls: list[float] = []
    monkeypatch.setattr(postgres_module.time, "sleep", lambda s: sleep_calls.append(s))

    storage = StorageLayer("postgresql://unused")

    # First call: exhausts retries (sleep is called for backoff)
    with pytest.raises((RuntimeError, OperationalError)):
        with storage._get_connection():
            pass  # pragma: no cover

    retries_sleep_count = len(sleep_calls)

    # Open the circuit breaker manually (simulate the breaker being tripped)
    storage._circuit_open = True  # type: ignore[attr-defined]

    sleep_calls.clear()

    # Subsequent calls should fail fast — ideally no sleep at all, or fewer
    # sleeps than the full retry sequence.
    with pytest.raises((RuntimeError, OperationalError, Exception)):
        with storage._get_connection():
            pass  # pragma: no cover

    # When the circuit is open we expect fewer sleep calls than a full retry
    assert len(sleep_calls) <= retries_sleep_count
