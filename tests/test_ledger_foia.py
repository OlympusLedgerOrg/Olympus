"""
Tests for document commit/verify round-trip via the ledger endpoints.

Covers: commit → ledger state, per-shard state, and proof retrieval.
"""

from __future__ import annotations

import hashlib
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
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


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@pytest.mark.asyncio
async def test_ledger_state_empty(client):
    """GET /ledger/state on a fresh DB returns total_commits = 0."""
    resp = await client.get("/ledger/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_commits"] == 0
    assert data["global_state_root"] == "0" * 64


@pytest.mark.asyncio
async def test_ledger_state_after_commit(client):
    """State root changes after a commit is added."""
    await client.post("/doc/commit", json={"doc_hash": _h("ledger state test")})
    resp = await client.get("/ledger/state")
    data = resp.json()
    assert data["total_commits"] >= 1
    assert data["global_state_root"] != "0" * 64


@pytest.mark.asyncio
async def test_shard_state(client):
    """GET /ledger/shard/{shard_id} returns the state for the default shard."""
    await client.post("/doc/commit", json={"doc_hash": _h("shard state test")})
    resp = await client.get("/ledger/shard/0x4F3A")
    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == "0x4F3A"
    assert data["commit_count"] >= 1
    assert isinstance(data["latest_commits"], list)


@pytest.mark.asyncio
async def test_proof_endpoint(client):
    """GET /ledger/proof/{commit_id} returns a proof for an existing commit."""
    doc_hash = _h("proof endpoint test")
    commit_resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    commit_id = commit_resp.json()["commit_id"]

    proof_resp = await client.get(f"/ledger/proof/{commit_id}")
    assert proof_resp.status_code == 200
    data = proof_resp.json()
    assert data["commit_id"] == commit_id
    assert data["zk_proof"]["protocol"] == "groth16"


@pytest.mark.asyncio
async def test_proof_not_found(client):
    """GET /ledger/proof/{bad_id} should return 404."""
    resp = await client.get("/ledger/proof/0xdeadbeefdeadbeefdeaddead")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_empty_shard_state_root():
    """compute_state_root returns 64 zeros for an empty shard."""
    from unittest.mock import AsyncMock, MagicMock

    from sqlalchemy import select
    from api.services.shard import compute_state_root
    from api.models.document import DocCommit

    # Mock a DB session that returns no results
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_result

    root = await compute_state_root("0xEMPTY", mock_db)
    assert root == "0" * 64
