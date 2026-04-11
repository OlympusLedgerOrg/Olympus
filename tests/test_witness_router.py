"""Tests for the witness protocol router (api/routers/witness.py)."""

from __future__ import annotations

import hashlib
import uuid

import nacl.signing
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import api.routers.witness as witness_module
from api.db import get_db
from api.main import create_app
from api.models import Base
from protocol.timestamps import current_timestamp


# -- Ed25519 test key pair used to sign all test announcements ----------------
_TEST_SIGNING_KEY = nacl.signing.SigningKey.generate()
_TEST_VERIFY_KEY = _TEST_SIGNING_KEY.verify_key
_TEST_PUBKEY_HEX = _TEST_VERIFY_KEY.encode().hex()


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def session_factory(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture()
async def client(session_factory, monkeypatch):
    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    monkeypatch.setattr(
        witness_module,
        "_resolve_node_pubkey",
        lambda origin: _TEST_PUBKEY_HEX,
    )

    # Clear tables before each test
    async with session_factory() as session:
        await witness_module.clear_observations(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nonce() -> str:
    """Generate a unique nonce for replay-resistance."""
    return uuid.uuid4().hex


def _sign_checkpoint(origin: str, sequence: int, checkpoint_hash: str) -> str:
    """Create an Ed25519 signature over the canonical checkpoint payload."""
    payload = hashlib.sha256(f"{origin}:{sequence}:{checkpoint_hash}".encode()).digest()
    return _TEST_SIGNING_KEY.sign(payload).signature.hex()


def _announcement_payload(
    origin: str,
    sequence: int,
    checkpoint_hash: str = "ab" * 32,
    *,
    timestamp: str | None = None,
    nonce: str | None = None,
    node_signature: str | None = None,
) -> dict:
    ts = timestamp or current_timestamp()
    sig = node_signature or _sign_checkpoint(origin, sequence, checkpoint_hash)
    return {
        "origin": origin,
        "checkpoint": {
            "sequence": sequence,
            "checkpoint_hash": checkpoint_hash,
            "timestamp": ts,
        },
        "nonce": nonce or _nonce(),
        "node_signature": sig,
    }


# ---------------------------------------------------------------------------
# POST /witness/observations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_observation_returns_201(client) -> None:
    payload = _announcement_payload("node-alpha", 1)
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["origin"] == "node-alpha"
    assert body["sequence"] == 1
    assert body["status"] == "recorded"


@pytest.mark.asyncio
async def test_submit_observation_stores_entry(client) -> None:
    payload = _announcement_payload("node-beta", 5, "cd" * 32)
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 201
    # Verify via the public API rather than the internal store
    get_resp = await client.get("/witness/checkpoints/5")
    assert get_resp.status_code == 200
    body = get_resp.json()
    assert body["origin"] == "node-beta"
    assert body["checkpoint"]["sequence"] == 5
    assert body["checkpoint"]["checkpoint_hash"] == "cd" * 32


@pytest.mark.asyncio
async def test_submit_observation_duplicate_returns_409(client) -> None:
    nonce1 = _nonce()
    nonce2 = _nonce()
    payload1 = _announcement_payload("node-gamma", 3, nonce=nonce1)
    payload2 = _announcement_payload("node-gamma", 3, nonce=nonce2)
    first = await client.post("/witness/observations", json=payload1)
    assert first.status_code == 201
    second = await client.post("/witness/observations", json=payload2)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_submit_observation_same_origin_different_sequence_allowed(
    client,
) -> None:
    await client.post(
        "/witness/observations",
        json=_announcement_payload("node-delta", 1),
    )
    resp = await client.post(
        "/witness/observations",
        json=_announcement_payload("node-delta", 2),
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# checkpoint_hash validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_observation_rejects_too_short_hash(client) -> None:
    payload = _announcement_payload("node-short", 1, "ab" * 10)  # only 20 hex chars
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_observation_rejects_empty_hash(client) -> None:
    payload = _announcement_payload("node-empty", 1, "")
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_observation_rejects_non_hex_hash(client) -> None:
    payload = _announcement_payload("node-invalid", 1, "zz" * 32)  # non-hex chars
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_observation_accepts_128_char_hash(client) -> None:
    # 128 hex chars (512-bit hash) should be accepted
    long_hash = "a1" * 64
    payload = _announcement_payload("node-long", 1, long_hash)
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_submit_observation_rejects_too_long_hash(client) -> None:
    payload = _announcement_payload("node-toolong", 1, "ab" * 65)  # 130 hex chars
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /witness/checkpoints/latest
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_latest_checkpoint_404_when_empty(client) -> None:
    resp = await client.get("/witness/checkpoints/latest")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_latest_checkpoint_returns_highest_sequence(client) -> None:
    for seq in (3, 1, 7, 5):
        await client.post(
            "/witness/observations",
            json=_announcement_payload(f"node-{seq}", seq),
        )
    resp = await client.get("/witness/checkpoints/latest")
    assert resp.status_code == 200
    assert resp.json()["checkpoint"]["sequence"] == 7


# ---------------------------------------------------------------------------
# GET /witness/checkpoints/{sequence}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkpoint_by_sequence_found(client) -> None:
    await client.post(
        "/witness/observations",
        json=_announcement_payload("node-x", 42),
    )
    resp = await client.get("/witness/checkpoints/42")
    assert resp.status_code == 200
    assert resp.json()["checkpoint"]["sequence"] == 42


@pytest.mark.asyncio
async def test_checkpoint_by_sequence_404(client) -> None:
    resp = await client.get("/witness/checkpoints/99")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /witness/checkpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_checkpoints_sorted_descending(client) -> None:
    for seq in (1, 3, 2):
        await client.post(
            "/witness/observations",
            json=_announcement_payload(f"node-{seq}", seq),
        )
    resp = await client.get("/witness/checkpoints")
    assert resp.status_code == 200
    sequences = [item["checkpoint"]["sequence"] for item in resp.json()]
    assert sequences == sorted(sequences, reverse=True)


@pytest.mark.asyncio
async def test_list_checkpoints_pagination(client) -> None:
    for seq in range(1, 6):
        await client.post(
            "/witness/observations",
            json=_announcement_payload(f"node-{seq}", seq),
        )
    resp = await client.get("/witness/checkpoints?limit=2&offset=1")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    # offset=1 skips the highest (seq 5); next two are 4 and 3
    assert items[0]["checkpoint"]["sequence"] == 4
    assert items[1]["checkpoint"]["sequence"] == 3


@pytest.mark.asyncio
async def test_list_checkpoints_default_limit_is_20(client) -> None:
    for seq in range(1, 26):
        await client.post(
            "/witness/observations",
            json=_announcement_payload(f"n{seq}", seq),
        )
    resp = await client.get("/witness/checkpoints")
    assert resp.status_code == 200
    assert len(resp.json()) == 20


# ---------------------------------------------------------------------------
# GET /witness/gossip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gossip_empty_when_no_observations(client) -> None:
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_gossip_empty_when_no_conflicts(client) -> None:
    # Two origins, same sequence, same hash → no conflict
    hash_val = "aa" * 32
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-a", 1, hash_val),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-b", 1, hash_val),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_gossip_detects_differing_hashes_at_same_sequence(
    client,
) -> None:
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-a", 10, "aa" * 32),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-b", 10, "bb" * 32),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["sequence"] == 10
    assert set(conflict["conflicting_origins"]) == {"origin-a", "origin-b"}
    assert conflict["hashes"]["origin-a"] == "aa" * 32
    assert conflict["hashes"]["origin-b"] == "bb" * 32


@pytest.mark.asyncio
async def test_gossip_ignores_single_origin_at_sequence(client) -> None:
    # Only one origin at a given sequence → cannot determine split view
    await client.post(
        "/witness/observations",
        json=_announcement_payload("only-origin", 7),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_gossip_conflict_with_128_char_hash(client) -> None:
    # 128 hex chars (max boundary) — conflict detection must still fire.
    hash_x = "a1" * 64
    hash_y = "b2" * 64
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-x", 20, hash_x),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-y", 20, hash_y),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    assert conflicts[0]["sequence"] == 20
    assert set(conflicts[0]["conflicting_origins"]) == {"origin-x", "origin-y"}
    assert conflicts[0]["hashes"]["origin-x"] == hash_x
    assert conflicts[0]["hashes"]["origin-y"] == hash_y


@pytest.mark.asyncio
async def test_gossip_no_conflict_when_128_char_hashes_match(client) -> None:
    # Two origins at same sequence with identical 128-char hashes → no conflict.
    hash_val = "c3" * 64
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-p", 30, hash_val),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("origin-q", 30, hash_val),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []

    hash_a = "aa" * 32
    hash_b = "bb" * 32
    # Sequence 1: conflict
    await client.post(
        "/witness/observations",
        json=_announcement_payload("o1", 1, hash_a),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("o2", 1, hash_b),
    )
    # Sequence 2: no conflict (same hash)
    await client.post(
        "/witness/observations",
        json=_announcement_payload("o1", 2, hash_a),
    )
    await client.post(
        "/witness/observations",
        json=_announcement_payload("o2", 2, hash_a),
    )
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    conflicts = resp.json()
    assert len(conflicts) == 1
    assert conflicts[0]["sequence"] == 1


# ---------------------------------------------------------------------------
# GET /witness/health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_ok_when_empty(client) -> None:
    resp = await client.get("/witness/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["observation_count"] == 0


@pytest.mark.asyncio
async def test_health_count_reflects_observations(client) -> None:
    for seq in range(1, 4):
        await client.post(
            "/witness/observations",
            json=_announcement_payload(f"n{seq}", seq),
        )
    resp = await client.get("/witness/health")
    assert resp.status_code == 200
    assert resp.json()["observation_count"] == 3


# ---------------------------------------------------------------------------
# Auth gate — POST /witness/observations requires authentication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_observation_requires_auth_when_keys_configured(
    session_factory, monkeypatch
) -> None:
    """POST /witness/observations returns 401 when API keys are configured
    but the request has no key."""
    import json
    import os

    import api.auth as auth_module
    from protocol.hashes import hash_bytes

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    monkeypatch.setattr(
        witness_module,
        "_resolve_node_pubkey",
        lambda origin: _TEST_PUBKEY_HEX,
    )

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()

        test_key_hash = hash_bytes(b"witness-test-key").hex()

        os.environ["OLYMPUS_FOIA_API_KEYS"] = json.dumps(
            [{"key_hash": test_key_hash, "key_id": "witness-test"}]
        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as no_auth_client:
            payload = _announcement_payload("no-auth-node", 1)
            resp = await no_auth_client.post("/witness/observations", json=payload)
            assert resp.status_code == 401
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)


# ---------------------------------------------------------------------------
# Replay-resistance: timestamp freshness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_observation_rejects_stale_timestamp(client) -> None:
    """Checkpoint timestamp older than _MAX_ANNOUNCE_SKEW_SECONDS is rejected."""
    stale_ts = "2020-01-01T00:00:00Z"
    payload = _announcement_payload("stale-node", 1, timestamp=stale_ts)
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422
    assert "Stale" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_submit_observation_rejects_future_timestamp(client) -> None:
    """Checkpoint timestamp far in the future is rejected."""
    future_ts = "2099-01-01T00:00:00Z"
    payload = _announcement_payload("future-node", 1, timestamp=future_ts)
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422
    assert "future" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_submit_observation_accepts_fresh_timestamp(client) -> None:
    """Checkpoint with a current timestamp is accepted."""
    payload = _announcement_payload("fresh-node", 1, timestamp=current_timestamp())
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Replay-resistance: nonce deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_observation_rejects_duplicate_nonce(client) -> None:
    """Re-using a nonce returns 409 even if origin/sequence differ."""
    shared_nonce = "a" * 32
    payload1 = _announcement_payload("nonce-node-a", 1, nonce=shared_nonce)
    payload2 = _announcement_payload("nonce-node-b", 2, nonce=shared_nonce)
    first = await client.post("/witness/observations", json=payload1)
    assert first.status_code == 201
    second = await client.post("/witness/observations", json=payload2)
    assert second.status_code == 409
    assert "nonce" in second.json()["detail"].lower()


@pytest.mark.asyncio
async def test_submit_observation_rejects_short_nonce(client) -> None:
    """Nonces shorter than 16 characters are rejected by schema validation."""
    payload = _announcement_payload("short-nonce-node", 1, nonce="tooshort")
    resp = await client.post("/witness/observations", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# received_at field on stored announcements
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stored_announcement_has_received_at(client) -> None:
    """WitnessAnnouncement returned by GET includes a server-assigned received_at."""
    payload = _announcement_payload("ts-node", 50)
    await client.post("/witness/observations", json=payload)
    resp = await client.get("/witness/checkpoints/50")
    assert resp.status_code == 200
    body = resp.json()
    assert "received_at" in body
    assert body["received_at"].endswith("Z")
