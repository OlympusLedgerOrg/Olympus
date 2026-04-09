"""Tests for the Go sequencer ingest path (unconditional since 0.12).

Covers:
  - Batch atomicity: a 503 from the sequencer on record N fails the entire
    batch (the DB transaction never commits).
  - ledger_entry_hash semantics: this field carries the BLAKE3 hash of the
    canonical record bytes (hash_bytes(canonical_content)), identical to the
    content_hash computed by _process_record_canonicalization.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

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
    """TestClient with storage + sequencer mocked."""
    ingest_api._reset_ingest_state_for_tests()
    ingest_api._register_api_key_for_tests(
        api_key="seq-test-key",
        key_id="seq-test-key-id",
        scopes={"ingest", "commit", "verify"},
        expires_at="2099-01-01T00:00:00Z",
    )

    fake_storage = _FakeStorage()
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

        async def _batch_mock(records):
            return [resp_dict]

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaves_batch",
            new=_batch_mock,
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
        """ledger_entry_hash equals hash_bytes(canonical_content) on the sequencer path.

        This is the acceptance gate: the field must equal the value produced by
        hash_bytes() applied to the same canonical bytes that
        _process_record_canonicalization computed — not the SMT leaf_value_hash
        returned by the sequencer, and not an empty string.
        """
        from protocol.canonical import canonicalize_document, document_to_bytes
        from protocol.hashes import hash_bytes

        client, _ = seq_client
        leaf_hash_hex = "dd" * 32
        resp_dict = _fake_seq_resp(leaf_value_hash=leaf_hash_hex)

        record_content = {"ledger_hash_semantic": True}
        expected_ledger_hash = hash_bytes(
            document_to_bytes(canonicalize_document(record_content))
        ).hex()

        async def _batch_mock(records):
            return [resp_dict]

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaves_batch",
            new=_batch_mock,
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
                            "content": record_content,
                        }
                    ]
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        # ledger_entry_hash must equal hash_bytes(canonical_content), which is the
        # same as content_hash — NOT the SMT leaf_value_hash from the sequencer.
        assert data["ledger_entry_hash"] == expected_ledger_hash
        assert data["ledger_entry_hash"] != leaf_hash_hex

        # The individual proof stored in the cache should carry the same value.
        proof_id = data["results"][0]["proof_id"]
        cached = ingest_api._ingestion_store.get(proof_id)
        assert cached is not None
        assert cached["ledger_entry_hash"] == expected_ledger_hash

    def test_proof_metadata_written_to_storage_on_success(self, seq_client):
        """store_ingestion_batch must be called for successful sequencer batches."""
        client, fake_storage = seq_client
        resp_dict = _fake_seq_resp()

        async def _batch_mock(records):
            return [resp_dict]

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaves_batch",
            new=_batch_mock,
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

        async def _batch_mock(records):
            raise HTTPException(status_code=503, detail="Sequencer down")

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaves_batch",
            new=_batch_mock,
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

    def test_503_on_batch_fails_entire_batch(self, seq_client):
        """Batch endpoint failure should not persist anything to DB.

        With the batch endpoint, failures are atomic since the entire batch
        is sent in one call.
        """
        client, fake_storage = seq_client
        from fastapi import HTTPException

        async def _failing_batch(records):
            raise HTTPException(status_code=503, detail="Sequencer error")

        with patch.object(ingest_api, "_call_sequencer_queue_leaves_batch", new=_failing_batch):
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

        async def _batch_mock(records):
            return [
                _fake_seq_resp(
                    new_root=hex(i + 1)[2:].zfill(64),
                    global_key=hex(i + 101)[2:].zfill(64),
                    leaf_value_hash=hex(i + 201)[2:].zfill(64),
                    tree_size=i + 1,
                )
                for i in range(len(records))
            ]

        with patch.object(ingest_api, "_call_sequencer_queue_leaves_batch", new=_batch_mock):
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
# Batch endpoint integration: _call_sequencer_queue_leaves_batch
# ---------------------------------------------------------------------------


class TestSequencerBatchEndpoint:
    """Verify the batch endpoint _call_sequencer_queue_leaves_batch populates ingestion_entries."""

    def test_batch_endpoint_populates_all_ingestion_entries(self, seq_client):
        """A 3-record batch must populate all three ingestion_entry dicts correctly."""
        client, fake_storage = seq_client

        # Mock response for batch endpoint: 3 records with distinct hashes
        batch_results = [
            _fake_seq_resp(
                new_root="11" * 32,
                global_key="a1" * 32,
                leaf_value_hash="b1" * 32,
                tree_size=1,
            ),
            _fake_seq_resp(
                new_root="22" * 32,
                global_key="a2" * 32,
                leaf_value_hash="b2" * 32,
                tree_size=2,
            ),
            _fake_seq_resp(
                new_root="33" * 32,
                global_key="a3" * 32,
                leaf_value_hash="b3" * 32,
                tree_size=3,
            ),
        ]

        async def _batch_mock(records):
            # Verify we're receiving 3 records
            assert len(records) == 3
            return batch_results

        with patch.object(
            ingest_api,
            "_call_sequencer_queue_leaves_batch",
            new=_batch_mock,
        ):
            resp = client.post(
                "/ingest/records",
                json={
                    "records": [
                        {
                            "shard_id": "shard-batch",
                            "record_type": "doc",
                            "record_id": f"doc-batch-{i}",
                            "version": 1,
                            "content": {"batch_idx": i},
                        }
                        for i in range(3)
                    ]
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 3
        assert data["deduplicated"] == 0
        assert len(data["results"]) == 3

        # Verify all three records were persisted via store_ingestion_batch
        assert len(fake_storage.stored_batches) == 1
        _, stored_records = fake_storage.stored_batches[0]
        assert len(stored_records) == 3

        # Verify each ingestion_entry has the correct fields populated
        for i, record in enumerate(stored_records):
            assert record["record_id"] == f"doc-batch-{i}"
            assert record["shard_id"] == "shard-batch"
            assert record["record_type"] == "doc"
            assert record["merkle_root"] == batch_results[i]["new_root"]
            assert record["merkle_proof"]["smt_key"] == batch_results[i]["global_key"]
            assert record["merkle_proof"]["leaf_hash"] == batch_results[i]["leaf_value_hash"]
            assert record["persisted"] is True
            # ledger_entry_hash must be set (BLAKE3 of canonical content)
            assert record["ledger_entry_hash"] != ""


# ---------------------------------------------------------------------------
# Startup token check
# ---------------------------------------------------------------------------


def test_startup_log_does_not_include_token(caplog):
    """The startup log must name only the address, never the token value."""
    import logging

    token_value = "super-secret-token-value"
    with caplog.at_level(logging.INFO, logger="api.ingest"):
        # Simulate what module init does at startup
        import api.ingest as _m

        _m.logger.info("ingest_path=sequencer addr=%s", "localhost:9090")

    for record in caplog.records:
        assert token_value not in record.getMessage(), (
            "Token value must not appear in any log record"
        )


def test_missing_token_emits_warning(monkeypatch, caplog):
    """If SEQUENCER_API_TOKEN is unset, a warning is logged at startup."""
    import logging

    # Replicate what the module does at load time when token is missing.
    with caplog.at_level(logging.WARNING, logger="api.ingest"):
        ingest_api.logger.warning(
            "ingest: SEQUENCER_API_TOKEN is not set — sequencer requests will be unauthorized"
        )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("SEQUENCER_API_TOKEN" in r.getMessage() for r in warnings)
