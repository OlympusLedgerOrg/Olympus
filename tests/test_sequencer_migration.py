"""Parity tests for the sequencer migration (0.12).

Verifies that for the same input records, the new unconditional sequencer
path produces a ``ledger_entry_hash`` that equals ``hash_bytes(canonical_content)``
— the same value the retired direct-storage path would have produced when
applying the same hash function to the same canonical bytes.

The parametrized test runs multiple record datasets through the sequencer
path and checks:
  - ``ledger_entry_hash`` == ``hash_bytes(canonical_bytes)`` (content hash)
  - ``new_root``, ``global_key``, ``tree_size`` match the mocked sequencer
    response unchanged
  - results are stable across both a "direct-storage mock" baseline (which
    computes the expected hash inline) and the actual code path
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
from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.hashes import hash_bytes


# ---------------------------------------------------------------------------
# Fake storage (no real DB needed)
# ---------------------------------------------------------------------------


class _FakeStorage:
    def __init__(self):
        self.stored_batches: list[tuple[str, list[dict[str, Any]]]] = []

    @contextmanager
    def _get_connection(self):
        class _Cur:
            def execute(self, *a, **kw):
                pass

            def fetchall(self):
                return []

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        class _Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def cursor(self, **kw):
                return _Cur()

            def commit(self):
                pass

        yield _Conn()

    def _load_tree_state(self, cur, *, up_to_ts=None, _OLYMPUS_POSEIDON_CARVE_OUT=False):
        return SimpleNamespace(leaves={})

    def store_ingestion_batch(self, batch_id: str, records: list[dict[str, Any]]) -> None:
        self.stored_batches.append((batch_id, list(records)))

    def get_ingestion_proof(self, proof_id: str) -> dict[str, Any] | None:
        return None

    def get_ingestion_proof_by_content_hash(self, content_hash: bytes) -> dict[str, Any] | None:
        return None

    def consume_rate_limit(self, subject_type, subject, action, capacity, refill_rate) -> bool:
        return True

    def clear_rate_limits(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _content_hash(content: dict[str, Any]) -> str:
    """Compute the expected ledger_entry_hash for a given record content dict."""
    return hash_bytes(document_to_bytes(canonicalize_document(content))).hex()


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
def parity_client(monkeypatch):
    ingest_api._reset_ingest_state_for_tests()
    ingest_api._register_api_key_for_tests(
        api_key="parity-key",
        key_id="parity-key-id",
        scopes={"ingest", "commit", "verify"},
        expires_at="2099-01-01T00:00:00Z",
    )
    fake_storage = _FakeStorage()
    monkeypatch.setattr(ingest_api, "_storage", fake_storage)
    monkeypatch.setattr(ingest_api, "_signing_key", nacl.signing.SigningKey(b"\x02" * 32))
    return TestClient(app, headers={"X-API-Key": "parity-key"}), fake_storage


# ---------------------------------------------------------------------------
# Parametrized datasets
# ---------------------------------------------------------------------------

# Each entry: (record_content, seq_resp_overrides)
# The parity assertion is that ledger_entry_hash == content_hash(record_content)
# regardless of what leaf_value_hash the sequencer returns.
_DATASETS = [
    pytest.param(
        {
            "shard_id": "s1",
            "record_type": "doc",
            "record_id": "r1",
            "version": 1,
            "content": {"title": "Budget Report", "year": 2024},
        },
        _fake_seq_resp(
            new_root="aa" * 32, global_key="bb" * 32, leaf_value_hash="cc" * 32, tree_size=10
        ),
        id="budget-report",
    ),
    pytest.param(
        {
            "shard_id": "s2",
            "record_type": "ordinance",
            "record_id": "ord-42",
            "version": 3,
            "content": {"text": "amend section 5", "category": "zoning"},
        },
        _fake_seq_resp(
            new_root="11" * 32, global_key="22" * 32, leaf_value_hash="33" * 32, tree_size=99
        ),
        id="ordinance",
    ),
    pytest.param(
        {
            "shard_id": "s3",
            "record_type": "permit",
            "record_id": "p-007",
            "version": 1,
            "content": {"applicant": "Acme Corp", "approved": True, "value": 1234567},
        },
        _fake_seq_resp(
            new_root="ff" * 32, global_key="ee" * 32, leaf_value_hash="dd" * 32, tree_size=1
        ),
        id="permit",
    ),
]


@pytest.mark.parametrize("record_input,seq_resp", _DATASETS)
def test_ledger_entry_hash_parity(parity_client, record_input, seq_resp):
    """Parity: ledger_entry_hash == hash_bytes(canonical_bytes) on the sequencer path.

    This test serves as the migration acceptance gate.  It confirms that:
      1. The new unconditional sequencer path computes ledger_entry_hash as
         hash_bytes(canonical_content) — identical to what the direct-storage
         path would have produced using the same hash function.
      2. new_root, global_key, and tree_size are taken unchanged from the
         sequencer response (no re-computation on the Python side).
      3. ledger_entry_hash does NOT equal leaf_value_hash from the sequencer
         (which is the SMT leaf hash, a different value).

    The "old response shape" baseline is the inline computation of
    hash_bytes(canonical_content), which the retired direct-storage path
    also used (applying hash_bytes to the same canonical bytes).
    """
    client, _ = parity_client
    content = record_input["content"]

    # Baseline: what the direct-storage path computed for ledger_entry_hash
    expected_ledger_hash = _content_hash(content)

    with patch.object(
        ingest_api,
        "_call_sequencer_queue_leaves_batch",
        new=AsyncMock(return_value=[seq_resp]),
    ):
        resp = client.post("/ingest/records", json={"records": [record_input]})

    assert resp.status_code == 200
    data = resp.json()
    assert data["ingested"] == 1

    # --- parity assertion: ledger_entry_hash == content hash ---
    assert data["ledger_entry_hash"] == expected_ledger_hash, (
        f"ledger_entry_hash mismatch: got {data['ledger_entry_hash']!r}, "
        f"expected {expected_ledger_hash!r}"
    )

    # ledger_entry_hash must NOT equal the SMT leaf_value_hash from the sequencer
    assert data["ledger_entry_hash"] != seq_resp["leaf_value_hash"]

    # new_root, global_key, tree_size must flow through from the sequencer response
    proof_id = data["results"][0]["proof_id"]
    cached = ingest_api._ingestion_store.get(proof_id)
    assert cached is not None
    assert cached["merkle_root"] == seq_resp["new_root"]
    assert cached["merkle_proof"]["smt_key"] == seq_resp["global_key"]
    assert cached["merkle_proof"]["tree_size"] == str(seq_resp["tree_size"])
