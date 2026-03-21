"""Tests for the witness protocol router (api/routers/witness.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api.routers.witness as witness_module
from api.main import create_app

app = create_app()
client = TestClient(app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def clear_store() -> None:
    """Reset the in-process observation store before every test."""
    witness_module.clear_observations()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _announcement_payload(origin: str, sequence: int, checkpoint_hash: str = "ab" * 32) -> dict:
    return {
        "origin": origin,
        "checkpoint": {
            "sequence": sequence,
            "checkpoint_hash": checkpoint_hash,
        },
    }


# ---------------------------------------------------------------------------
# POST /witness/observations
# ---------------------------------------------------------------------------

def test_submit_observation_returns_201() -> None:
    payload = _announcement_payload("node-alpha", 1)
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["origin"] == "node-alpha"
    assert body["sequence"] == 1
    assert body["status"] == "recorded"


def test_submit_observation_stores_entry() -> None:
    payload = _announcement_payload("node-beta", 5, "cd" * 32)
    client.post("/witness/observations", json=payload)
    key = "node-beta:5"
    assert key in witness_module._observations
    stored = witness_module._observations[key]
    assert stored.origin == "node-beta"
    assert stored.checkpoint.sequence == 5
    assert stored.checkpoint.checkpoint_hash == "cd" * 32


def test_submit_observation_duplicate_returns_409() -> None:
    payload = _announcement_payload("node-gamma", 3)
    first = client.post("/witness/observations", json=payload)
    assert first.status_code == 201
    second = client.post("/witness/observations", json=payload)
    assert second.status_code == 409


def test_submit_observation_same_origin_different_sequence_allowed() -> None:
    client.post("/witness/observations", json=_announcement_payload("node-delta", 1))
    resp = client.post("/witness/observations", json=_announcement_payload("node-delta", 2))
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# GET /witness/checkpoints/latest
# ---------------------------------------------------------------------------

def test_latest_checkpoint_404_when_empty() -> None:
    resp = client.get("/witness/checkpoints/latest")
    assert resp.status_code == 404


def test_latest_checkpoint_returns_highest_sequence() -> None:
    for seq in (3, 1, 7, 5):
        client.post("/witness/observations", json=_announcement_payload(f"node-{seq}", seq))
    resp = client.get("/witness/checkpoints/latest")
    assert resp.status_code == 200
    assert resp.json()["checkpoint"]["sequence"] == 7


# ---------------------------------------------------------------------------
# GET /witness/checkpoints/{sequence}
# ---------------------------------------------------------------------------

def test_checkpoint_by_sequence_found() -> None:
    client.post("/witness/observations", json=_announcement_payload("node-x", 42))
    resp = client.get("/witness/checkpoints/42")
    assert resp.status_code == 200
    assert resp.json()["checkpoint"]["sequence"] == 42


def test_checkpoint_by_sequence_404() -> None:
    resp = client.get("/witness/checkpoints/99")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /witness/checkpoints
# ---------------------------------------------------------------------------

def test_list_checkpoints_sorted_descending() -> None:
    for seq in (1, 3, 2):
        client.post("/witness/observations", json=_announcement_payload(f"node-{seq}", seq))
    resp = client.get("/witness/checkpoints")
    assert resp.status_code == 200
    sequences = [item["checkpoint"]["sequence"] for item in resp.json()]
    assert sequences == sorted(sequences, reverse=True)


def test_list_checkpoints_pagination() -> None:
    for seq in range(1, 6):
        client.post("/witness/observations", json=_announcement_payload(f"node-{seq}", seq))
    resp = client.get("/witness/checkpoints?limit=2&offset=1")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    # offset=1 skips the highest (seq 5); next two are 4 and 3
    assert items[0]["checkpoint"]["sequence"] == 4
    assert items[1]["checkpoint"]["sequence"] == 3


def test_list_checkpoints_default_limit_is_20() -> None:
    for seq in range(1, 26):
        client.post("/witness/observations", json=_announcement_payload(f"n{seq}", seq))
    resp = client.get("/witness/checkpoints")
    assert resp.status_code == 200
    assert len(resp.json()) == 20


# ---------------------------------------------------------------------------
# GET /witness/gossip
# ---------------------------------------------------------------------------

def test_gossip_empty_when_no_observations() -> None:
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


def test_gossip_empty_when_no_conflicts() -> None:
    # Two origins, same sequence, same hash → no conflict
    hash_val = "aa" * 32
    client.post("/witness/observations", json=_announcement_payload("origin-a", 1, hash_val))
    client.post("/witness/observations", json=_announcement_payload("origin-b", 1, hash_val))
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


def test_gossip_detects_differing_hashes_at_same_sequence() -> None:
    client.post(
        "/witness/observations",
        json=_announcement_payload("origin-a", 10, "aa" * 32),
    )
    client.post(
        "/witness/observations",
        json=_announcement_payload("origin-b", 10, "bb" * 32),
    )
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["sequence"] == 10
    assert set(conflict["conflicting_origins"]) == {"origin-a", "origin-b"}
    assert conflict["hashes"]["origin-a"] == "aa" * 32
    assert conflict["hashes"]["origin-b"] == "bb" * 32


def test_gossip_ignores_single_origin_at_sequence() -> None:
    # Only one origin at a given sequence → cannot determine split view
    client.post("/witness/observations", json=_announcement_payload("only-origin", 7))
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


def test_gossip_multiple_sequences_only_flags_conflicts() -> None:
    hash_a = "aa" * 32
    hash_b = "bb" * 32
    # Sequence 1: conflict
    client.post("/witness/observations", json=_announcement_payload("o1", 1, hash_a))
    client.post("/witness/observations", json=_announcement_payload("o2", 1, hash_b))
    # Sequence 2: no conflict (same hash)
    client.post("/witness/observations", json=_announcement_payload("o1", 2, hash_a))
    client.post("/witness/observations", json=_announcement_payload("o2", 2, hash_a))
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    assert conflicts[0]["sequence"] == 1


# ---------------------------------------------------------------------------
# GET /witness/health
# ---------------------------------------------------------------------------

def test_health_ok_when_empty() -> None:
    resp = client.get("/witness/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["observation_count"] == 0


def test_health_count_reflects_observations() -> None:
    for seq in range(1, 4):
        client.post("/witness/observations", json=_announcement_payload(f"n{seq}", seq))
    resp = client.get("/witness/health")
    assert resp.status_code == 200
    assert resp.json()["observation_count"] == 3
