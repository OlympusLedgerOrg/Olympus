"""Tests for the witness protocol router (api/routers/witness.py)."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

import api.routers.witness as witness_module
from api.main import create_app
from protocol.timestamps import current_timestamp


app = create_app()
client = TestClient(app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def clear_store() -> None:
    """Reset the in-process observation store before every test."""
    witness_module.clear_observations()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nonce() -> str:
    """Generate a unique nonce for replay-resistance."""
    return uuid.uuid4().hex


def _announcement_payload(
    origin: str,
    sequence: int,
    checkpoint_hash: str = "ab" * 32,
    *,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict:
    return {
        "origin": origin,
        "checkpoint": {
            "sequence": sequence,
            "checkpoint_hash": checkpoint_hash,
            "timestamp": timestamp or current_timestamp(),
        },
        "nonce": nonce or _nonce(),
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
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 201
    # Verify via the public API rather than the internal store
    get_resp = client.get("/witness/checkpoints/5")
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["origin"] == "node-beta"
    assert body["checkpoint"]["sequence"] == 5
    assert body["checkpoint"]["checkpoint_hash"] == "cd" * 32


def test_submit_observation_duplicate_returns_409() -> None:
    nonce1 = _nonce()
    nonce2 = _nonce()
    payload1 = _announcement_payload("node-gamma", 3, nonce=nonce1)
    payload2 = _announcement_payload("node-gamma", 3, nonce=nonce2)
    first = client.post("/witness/observations", json=payload1)
    assert first.status_code == 201
    second = client.post("/witness/observations", json=payload2)
    assert second.status_code == 409


def test_submit_observation_same_origin_different_sequence_allowed() -> None:
    client.post("/witness/observations", json=_announcement_payload("node-delta", 1))
    resp = client.post("/witness/observations", json=_announcement_payload("node-delta", 2))
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# checkpoint_hash validation
# ---------------------------------------------------------------------------


def test_submit_observation_rejects_too_short_hash() -> None:
    payload = _announcement_payload("node-short", 1, "ab" * 10)  # only 20 hex chars
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


def test_submit_observation_rejects_empty_hash() -> None:
    payload = _announcement_payload("node-empty", 1, "")
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


def test_submit_observation_rejects_non_hex_hash() -> None:
    payload = _announcement_payload("node-invalid", 1, "zz" * 32)  # non-hex chars
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


def test_submit_observation_accepts_128_char_hash() -> None:
    # 128 hex chars (512-bit hash) should be accepted
    long_hash = "a1" * 64
    payload = _announcement_payload("node-long", 1, long_hash)
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 201


def test_submit_observation_rejects_too_long_hash() -> None:
    payload = _announcement_payload("node-toolong", 1, "ab" * 65)  # 130 hex chars
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


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


def test_checkpoint_by_sequence_uses_secondary_index(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /witness/checkpoints/{sequence} does not need to scan _observations."""
    announcement = witness_module.WitnessAnnouncement.model_validate(
        {
            "origin": "node-index",
            "checkpoint": {
                "sequence": 42,
                "checkpoint_hash": "ab" * 32,
                "timestamp": current_timestamp(),
            },
            "received_at": current_timestamp(),
        }
    )
    witness_module._observations_by_seq[42] = announcement

    class _ForbiddenObservations(dict):
        def values(self):  # pragma: no cover - should never be reached
            raise AssertionError("get_checkpoint_by_sequence scanned _observations")

    monkeypatch.setattr(witness_module, "_observations", _ForbiddenObservations())

    resp = client.get("/witness/checkpoints/42")
    assert resp.status_code == 200
    assert resp.json()["origin"] == "node-index"


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


def test_gossip_conflict_with_128_char_hash() -> None:
    # 128 hex chars (max boundary) — conflict detection must still fire correctly.
    hash_x = "a1" * 64  # 128-char lowercase hex
    hash_y = "b2" * 64  # 128-char lowercase hex, different value
    client.post("/witness/observations", json=_announcement_payload("origin-x", 20, hash_x))
    client.post("/witness/observations", json=_announcement_payload("origin-y", 20, hash_y))
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    assert conflicts[0]["sequence"] == 20
    assert set(conflicts[0]["conflicting_origins"]) == {"origin-x", "origin-y"}
    assert conflicts[0]["hashes"]["origin-x"] == hash_x
    assert conflicts[0]["hashes"]["origin-y"] == hash_y


def test_gossip_no_conflict_when_128_char_hashes_match() -> None:
    # Two origins at same sequence with identical 128-char hashes → no conflict.
    hash_val = "c3" * 64
    client.post("/witness/observations", json=_announcement_payload("origin-p", 30, hash_val))
    client.post("/witness/observations", json=_announcement_payload("origin-q", 30, hash_val))
    resp = client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []

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


# ---------------------------------------------------------------------------
# Auth gate — POST /witness/observations requires authentication
# ---------------------------------------------------------------------------


def test_submit_observation_requires_auth_when_keys_configured() -> None:
    """POST /witness/observations returns 401 when API keys are configured
    but the request has no key."""
    import api.auth as auth_module

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()

        from protocol.hashes import hash_bytes

        test_key_hash = hash_bytes(b"witness-test-key").hex()
        import json
        import os

        os.environ["OLYMPUS_FOIA_API_KEYS"] = json.dumps(
            [{"key_hash": test_key_hash, "key_id": "witness-test"}]
        )

        # Client with NO auth header should be rejected
        no_auth_client = TestClient(app, raise_server_exceptions=False)
        payload = _announcement_payload("no-auth-node", 1)
        resp = no_auth_client.post("/witness/observations", json=payload)
        assert resp.status_code == 401
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)


# ---------------------------------------------------------------------------
# Replay-resistance: timestamp freshness
# ---------------------------------------------------------------------------


def test_submit_observation_rejects_stale_timestamp() -> None:
    """Checkpoint timestamp older than _MAX_ANNOUNCE_SKEW_SECONDS is rejected."""
    stale_ts = "2020-01-01T00:00:00Z"
    payload = _announcement_payload("stale-node", 1, timestamp=stale_ts)
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422
    assert "Stale" in resp.json()["detail"]


def test_submit_observation_rejects_future_timestamp() -> None:
    """Checkpoint timestamp far in the future is rejected."""
    future_ts = "2099-01-01T00:00:00Z"
    payload = _announcement_payload("future-node", 1, timestamp=future_ts)
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422
    assert "future" in resp.json()["detail"]


def test_submit_observation_accepts_fresh_timestamp() -> None:
    """Checkpoint with a current timestamp is accepted."""
    payload = _announcement_payload("fresh-node", 1, timestamp=current_timestamp())
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Replay-resistance: nonce deduplication
# ---------------------------------------------------------------------------


def test_submit_observation_rejects_duplicate_nonce() -> None:
    """Re-using a nonce returns 409 even if origin/sequence differ."""
    shared_nonce = "a" * 32
    payload1 = _announcement_payload("nonce-node-a", 1, nonce=shared_nonce)
    payload2 = _announcement_payload("nonce-node-b", 2, nonce=shared_nonce)
    first = client.post("/witness/observations", json=payload1)
    assert first.status_code == 201
    second = client.post("/witness/observations", json=payload2)
    assert second.status_code == 409
    assert "nonce" in second.json()["detail"].lower()


def test_submit_observation_rejects_short_nonce() -> None:
    """Nonces shorter than 16 characters are rejected by schema validation."""
    payload = _announcement_payload("short-nonce-node", 1, nonce="tooshort")
    resp = client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# received_at field on stored announcements
# ---------------------------------------------------------------------------


def test_stored_announcement_has_received_at() -> None:
    """WitnessAnnouncement returned by GET includes a server-assigned received_at."""
    payload = _announcement_payload("ts-node", 50)
    client.post("/witness/observations", json=payload)
    resp = client.get("/witness/checkpoints/50")
    assert resp.status_code == 200
    body = resp.json()
    assert "received_at" in body
    assert body["received_at"].endswith("Z")
