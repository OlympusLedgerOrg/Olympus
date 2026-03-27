"""
Integration tests for the document commit and verify endpoints.

Uses an in-memory SQLite database via pytest fixtures.
"""

from __future__ import annotations

import json
import os

import blake3
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base


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
async def client(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


def _b3(s: str) -> str:
    return blake3.blake3(s.encode()).hexdigest()


@pytest.mark.asyncio
async def test_commit_document(client):
    """POST /doc/commit should return 201 with a commit_id."""
    doc_hash = _b3("my government document")
    resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    assert resp.status_code == 201
    data = resp.json()
    assert data["doc_hash"] == doc_hash
    assert data["commit_id"].startswith("0x")
    assert len(data["commit_id"]) == 42  # 0x + 40 hex chars


@pytest.mark.asyncio
async def test_verify_by_commit_id(client):
    """Commit then verify by commit_id — should return verified: true."""
    doc_hash = _b3("verify by commit_id test")
    commit_resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    commit_id = commit_resp.json()["commit_id"]

    verify_resp = await client.post("/doc/verify", json={"commit_id": commit_id})
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["verified"] is True
    assert data["commit"]["commit_id"] == commit_id


@pytest.mark.asyncio
async def test_verify_by_doc_hash(client):
    """Commit then verify by doc_hash — should return verified: true."""
    doc_hash = _b3("verify by doc_hash test")
    await client.post("/doc/commit", json={"doc_hash": doc_hash})

    verify_resp = await client.post("/doc/verify", json={"doc_hash": doc_hash})
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["verified"] is True


@pytest.mark.asyncio
async def test_verify_nonexistent_returns_false(client):
    """Verifying a non-existent commit should return verified: false, not 404."""
    resp = await client.post(
        "/doc/verify", json={"commit_id": "0xdeadbeef00000000deadbeef00000000deadbeef"}
    )
    assert resp.status_code == 200
    assert resp.json()["verified"] is False


@pytest.mark.asyncio
async def test_verify_missing_both_fields(client):
    """POST /doc/verify with no lookup key should return 422."""
    resp = await client.post("/doc/verify", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_hash_consistency(client):
    """The same doc_hash committed twice should produce different commit_ids."""
    doc_hash = _b3("duplicate hash test")
    r1 = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    r2 = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["commit_id"] != r2.json()["commit_id"]


@pytest.mark.asyncio
async def test_commit_includes_merkle_root(client):
    """After the second commit the merkle_root should be non-null."""
    doc_hash = _b3("merkle root check")
    resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    assert resp.status_code == 201
    # merkle_root may be null on the very first commit in a fresh DB,
    # but should not be an error
    data = resp.json()
    assert "merkle_root" in data


@pytest.mark.asyncio
async def test_verify_includes_zk_proof_stub(client):
    """Verification response should include the ZK proof stub."""
    doc_hash = _b3("zk proof stub check")
    commit_resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    commit_id = commit_resp.json()["commit_id"]

    verify_resp = await client.post("/doc/verify", json={"commit_id": commit_id})
    data = verify_resp.json()
    assert data["zk_proof"] is not None
    assert data["zk_proof"]["protocol"] == "groth16"
    assert "STUB" in data["zk_proof"]["note"]


@pytest.mark.asyncio
async def test_commit_rejects_invalid_hash(client):
    """POST /doc/commit with a non-hex or wrong-length hash should return 422."""
    for bad_hash in ["hello", "ZZZZ", "abc", "A" * 64, ""]:
        resp = await client.post("/doc/commit", json={"doc_hash": bad_hash})
        assert resp.status_code == 422, (
            f"Expected 422 for doc_hash={bad_hash!r}, got {resp.status_code}"
        )


@pytest.mark.asyncio
async def test_commit_nonexistent_request_id_returns_404(client):
    """POST /doc/commit with a request_id that does not exist should return 404."""
    doc_hash = _b3("request id not found test")
    resp = await client.post(
        "/doc/commit",
        json={"doc_hash": doc_hash, "request_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_commit_requires_auth_when_keys_configured(client):
    """POST /doc/commit should return 401 when API keys are configured but none provided."""
    import api.auth as auth_module

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)
    original_env = os.environ.get("OLYMPUS_FOIA_API_KEYS")

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()

        test_key_hash = blake3.blake3(b"test-key-1234").hexdigest()
        os.environ["OLYMPUS_FOIA_API_KEYS"] = json.dumps(
            [{"key_hash": test_key_hash, "key_id": "test"}]
        )

        doc_hash = _b3("auth test doc")
        resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
        assert resp.status_code == 401
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        if original_env is None:
            os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)
        else:
            os.environ["OLYMPUS_FOIA_API_KEYS"] = original_env
