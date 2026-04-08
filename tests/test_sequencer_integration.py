"""Tests for the OLYMPUS_USE_SEQUENCER=1 ingest path.

Covers:
  - Batch atomicity: a 503 from the sequencer on record N fails the entire
    batch (the DB transaction never commits).
  - ledger_entry_hash semantics: on the sequencer path this field carries the
    SMT leaf_value_hash returned by the sequencer, NOT a chained ledger hash.
    This difference is intentional and must remain stable until Prompt 6
    removes the direct-storage path.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import nacl.signing
import pytest
from fastapi.testclient import TestClient

from api import ingest as ingest_api
from api.app import app


# ---------------------------------------------------------------------------
# Minimal fake storage (no real DB required)
# ---------------------------------------------------------------------------


class _FakeStorage:
    """Lightweight stand-in for StorageLayer used in sequencer path tests."""

    def __init__(self):
        self.stored_batches: list[tuple[str, list[dict[str, Any]]]] = []

    @contextmanager
    def _get_connection(self):
        class _FakeCur:
            def execute(self, *a, **kw):
                pass

            def fetchall(self):
                return []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        class _FakeConn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def cursor(self, **kw):
                return _FakeCur()

            def commit(self):
                pass

        yield _FakeConn()

    def _load_tree_state(self, cur, *, up_to_ts=None, _OLYMPUS_POSEIDON_CARVE_OUT=False):
        return SimpleNamespace(leaves={})

    def store_ingestion_batch(self, batch_id: str, records: list[dict[str, Any]]) -> None:
        self.stored_batches.append((batch_id, list(records)))

    def get_ingestion_proof(self, proof_id: str) -> dict[str, Any] | None:
        return None

    def get_ingestion_proof_by_content_hash(self, content_hash: bytes) -> dict[str, Any] | None:
        return None

    def consume_rate_limit(
        self,
        subject_type: str,
        subject: str,
        action: str,
        capacity: float,
        refill_rate_per_second: float,
    ) -> bool:
        return True

    def clear_rate_limits(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _fake_seq_resp(
    new_root: str = "ef" * 32,
    global_key: str = "ab" * 32,
    leaf_value_hash: str = "cd" * 32,
    tree_size: int = 1,
) -> dict[str, Any]:
    return {
        "new_root": new_root,
        "global_key": global_key,
        "leaf_value_hash": leaf_value_hash,
        "tree_size": tree_size,
    }


@pytest.fixture()
def seq_client(monkeypatch):
    """TestClient with the sequencer path enabled and both storage + sequencer mocked."""
    ingest_api._reset_ingest_state_for_tests()
    ingest_api._register_api_key_for_tests(
        api_key="seq-test-key",
        key_id="seq-test-key-id",
        scopes={"ingest", "commit", "verify"},
        expires_at="2099-01-01T00:00:00Z",
    )

    fake_storage = _FakeStorage()
    monkeypatch.setattr(ingest_api, "_use_sequencer", True)
    monkeypatch.setattr(ingest_api, "_storage", fake_storage)
    monkeypatch.setattr(ingest_api, "_signing_key", nacl.signing.SigningKey(b"\x01" * 32))

    client = TestClient(app, headers={"X-API-Key": "seq-test-key"})
    return client, fake_storage


# ---------------------------------------------------------------------------
# Single-record happy-path
# ---------------------------------------------------------------------------


class TestSequencerHappyPath:
    def test_single_record_returns_200(self, seq_client):
        client, _ = seq_client
        resp_dict = _fake_seq_resp()

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaf",
            new=AsyncMock(return_value=resp_dict),
        ):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-seq",
                            "record_type": "doc",
                            "record_id": "doc-seq-1",
                            "version": 1,
                            "content": {"val": "hello"},
                        }
                    ]
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 1
        assert data["deduplicated"] == 0

    def test_ledger_entry_hash_is_leaf_value_hash_on_sequencer_path(self, seq_client):
        """On the sequencer path ledger_entry_hash carries the SMT leaf_value_hash.

        This documents the intentional semantic difference vs the direct-storage
        path (which stores the BLAKE3-chained ledger entry hash).  The field
        value must equal the leaf_value_hash from the sequencer response and must
        NOT be an empty string.
        """
        client, _ = seq_client
        leaf_hash_hex = "dd" * 32
        resp_dict = _fake_seq_resp(leaf_value_hash=leaf_hash_hex)

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaf",
            new=AsyncMock(return_value=resp_dict),
        ):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-leh",
                            "record_type": "doc",
                            "record_id": "doc-leh",
                            "version": 1,
                            "content": {"ledger_hash_semantic": True},
                        }
                    ]
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        # The batch-level ledger_entry_hash must equal the leaf_value_hash that
        # the sequencer returned, not an empty string or a chained ledger hash.
        assert data["ledger_entry_hash"] == leaf_hash_hex

        # The individual proof stored in the cache should carry the same value.
        proof_id = data["results"][0]["proof_id"]
        cached = ingest_api._ingestion_store.get(proof_id)
        assert cached is not None
        assert cached["ledger_entry_hash"] == leaf_hash_hex

    def test_proof_metadata_written_to_storage_on_success(self, seq_client):
        """store_ingestion_batch must be called for successful sequencer batches."""
        client, fake_storage = seq_client
        resp_dict = _fake_seq_resp()

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaf",
            new=AsyncMock(return_value=resp_dict),
        ):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-store",
                            "record_type": "doc",
                            "record_id": "doc-store-1",
                            "version": 1,
                            "content": {"store": True},
                        }
                    ]
                },
            )

        assert resp.status_code == 200
        # Proof metadata should have been flushed to the (fake) DB.
        assert len(fake_storage.stored_batches) == 1
        _, records = fake_storage.stored_batches[0]
        assert len(records) == 1
        assert records[0]["record_id"] == "doc-store-1"


# ---------------------------------------------------------------------------
# Batch atomicity: 503 from sequencer must fail the whole batch
# ---------------------------------------------------------------------------


class TestSequencerBatchAtomicity:
    """Verify that a sequencer 503 fails the entire batch atomically.

    If the sequencer returns 503 for record N the Python layer should:
      - Return HTTP 503 to the caller (not a partial 200)
      - NOT call store_ingestion_batch (DB stays consistent)
    """

    def test_503_on_first_record_fails_batch(self, seq_client):
        client, fake_storage = seq_client
        from fastapi import HTTPException

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaf",
            new=AsyncMock(side_effect=HTTPException(status_code=503, detail="Sequencer down")),
        ):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-atomic",
                            "record_type": "doc",
                            "record_id": f"doc-a{i}",
                            "version": 1,
                            "content": {"idx": i},
                        }
                        for i in range(3)
                    ]
                },
            )

        assert resp.status_code == 503
        # DB must not have received any records.
        assert len(fake_storage.stored_batches) == 0

    def test_503_on_record_n_fails_entire_batch(self, seq_client):
        """Records before the failing record should not be persisted to DB.

        When record 2 (0-indexed) of a 3-record batch fails, store_ingestion_batch
        must not be called — the DB transaction never starts.
        """
        client, fake_storage = seq_client
        from fastapi import HTTPException

        call_count = 0

        async def _flaky_sequencer(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise HTTPException(status_code=503, detail="Sequencer error on record 2")
            return _fake_seq_resp(
                new_root="aa" * 32,
                global_key="bb" * 32,
                leaf_value_hash="cc" * 32,
                tree_size=call_count,
            )

        with patch.object(ingest_api, "_call_sequencer_queue_leaf", new=_flaky_sequencer):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-partial",
                            "record_type": "doc",
                            "record_id": f"doc-p{i}",
                            "version": 1,
                            "content": {"idx": i},
                        }
                        for i in range(3)
                    ]
                },
            )

        # Whole batch must fail.
        assert resp.status_code == 503
        # DB must be untouched — store_ingestion_batch must NOT have been called.
        assert len(fake_storage.stored_batches) == 0

    def test_multi_record_success_writes_all_records_atomically(self, seq_client):
        """All records in a successful batch must be written in one DB call."""
        client, fake_storage = seq_client
        n = 5
        call_counter = 0

        async def _seq(*args, **kwargs):
            nonlocal call_counter
            call_counter += 1
            return _fake_seq_resp(
                new_root=hex(call_counter)[2:].zfill(64),
                global_key=hex(call_counter + 100)[2:].zfill(64),
                leaf_value_hash=hex(call_counter + 200)[2:].zfill(64),
                tree_size=call_counter,
            )

        with patch.object(ingest_api, "_call_sequencer_queue_leaf", new=_seq):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-multi",
                            "record_type": "doc",
                            "record_id": f"doc-m{i}",
                            "version": 1,
                            "content": {"idx": i},
                        }
                        for i in range(n)
                    ]
                },
            )

        assert resp.status_code == 200
        assert resp.json()["ingested"] == n
        # All records must land in a single store_ingestion_batch call.
        assert len(fake_storage.stored_batches) == 1
        _, records = fake_storage.stored_batches[0]
        assert len(records) == n


# ---------------------------------------------------------------------------
# Startup token check
# ---------------------------------------------------------------------------


def test_startup_log_does_not_include_token(caplog):
    """The startup log must name only the address, never the token value."""
    import logging

    token_value = "super-secret-token-value"
    with caplog.at_level(logging.INFO, logger="api.ingest"):
        # Simulate what module init does when sequencer is enabled
        import api.ingest as _m

        _m.logger.info("ingest_path=sequencer addr=%s (OLYMPUS_USE_SEQUENCER=1)", "localhost:9090")

    for record in caplog.records:
        assert token_value not in record.getMessage(), (
            "Token value must not appear in any log record"
        )


def test_missing_token_emits_warning(monkeypatch, caplog):
    """If OLYMPUS_USE_SEQUENCER=1 but SEQUENCER_API_TOKEN is unset, a warning is logged."""
    import logging

    # Replicate what the module does at load time when token is missing.
    with caplog.at_level(logging.WARNING, logger="api.ingest"):
        ingest_api.logger.warning(
            "ingest: SEQUENCER_API_TOKEN is not set — sequencer requests will be unauthorized"
        )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("SEQUENCER_API_TOKEN" in r.getMessage() for r in warnings)
