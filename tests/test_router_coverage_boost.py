"""
Integration tests for ledger, requests, and documents routers.
Covers error paths and missing branches to push coverage past 90%.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.models.document import DocCommit
from api.models.ledger_activity import LedgerActivity
from api.models.request import PublicRecordsRequest, RequestStatus


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture()
async def fresh_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def client(fresh_engine):
    sf = async_sessionmaker(fresh_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with sf() as session:
            yield session

    with patch.dict(os.environ, {
        "OLYMPUS_ENV": "development",
        "OLYMPUS_ALLOW_DEV_AUTH": "1",
        "OLYMPUS_FOIA_API_KEYS": "[]",
    }):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


@pytest_asyncio.fixture()
async def seeded_client(fresh_engine):
    """Client with pre-seeded data (a request, a commit, and an activity)."""
    sf = async_sessionmaker(fresh_engine, expire_on_commit=False, class_=AsyncSession)

    async with sf() as session:
        req = PublicRecordsRequest(
            id="req-001", display_id="OLY-0001", subject="Budget records",
            description="All budget records for 2025", status=RequestStatus.PENDING.value,
            filed_at=datetime.now(timezone.utc), commit_hash="a" * 64,
            shard_id="0x4F3A",
        )
        session.add(req)
        commit = DocCommit(
            id="commit-001", request_id="req-001", doc_hash="b" * 64,
            commit_id="0x" + "c" * 64, shard_id="0x4F3A",
            epoch_timestamp=datetime.now(timezone.utc), merkle_root="d" * 64,
        )
        session.add(commit)
        activity = LedgerActivity(
            id="act-001", activity_type="DOCUMENT_SUBMITTED",
            title="Document Added", description="Budget doc submitted",
            related_commit_id="0x" + "c" * 64,
            user_friendly_status="✓ Complete",
        )
        session.add(activity)
        await session.commit()

    async def override_get_db():
        async with sf() as session:
            yield session

    with patch.dict(os.environ, {
        "OLYMPUS_ENV": "development",
        "OLYMPUS_ALLOW_DEV_AUTH": "1",
        "OLYMPUS_FOIA_API_KEYS": "[]",
    }):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


# ═══════════════════════════════════════════════════════════════════════════════
# A) api/routers/requests.py
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_create_request(client: AsyncClient):
    """POST /requests — file a new request (lines 132-153)."""
    resp = await client.post("/requests", json={
        "subject": "Budget transparency report",
        "description": "All line-item budgets for fiscal year 2025",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["display_id"].startswith("OLY-")
    assert len(data["commit_hash"]) == 64
    assert all(c in "0123456789abcdef" for c in data["commit_hash"])
    assert data["status"] == "PENDING"
    assert data["shard_id"] == "0x4F3A"


@pytest.mark.asyncio
async def test_list_requests(client: AsyncClient):
    """GET /requests — paginated list (lines 189-196)."""
    # Create two requests first
    await client.post("/requests", json={
        "subject": "List test A", "description": "desc A",
    })
    await client.post("/requests", json={
        "subject": "List test B", "description": "desc B",
    })
    resp = await client.get("/requests")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2
    assert all("display_id" in r for r in data)


@pytest.mark.asyncio
async def test_get_request_found(client: AsyncClient):
    """GET /requests/{display_id} — found (lines 216-227)."""
    create_resp = await client.post("/requests", json={
        "subject": "Get test", "description": "Verify get by display_id",
    })
    display_id = create_resp.json()["display_id"]
    resp = await client.get(f"/requests/{display_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["display_id"] == display_id
    assert data["subject"] == "Get test"


@pytest.mark.asyncio
async def test_get_request_not_found(client: AsyncClient):
    """GET /requests/{display_id} — 404 (lines 217-221)."""
    resp = await client.get("/requests/OLY-9999")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_update_status_valid_transition(client: AsyncClient):
    """PATCH /requests/{id}/status — PENDING→ACKNOWLEDGED (lines 258-295)."""
    create_resp = await client.post("/requests", json={
        "subject": "Status test", "description": "transition test",
    })
    display_id = create_resp.json()["display_id"]
    resp = await client.patch(f"/requests/{display_id}/status", json={
        "status": "ACKNOWLEDGED",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_update_status_invalid_transition(client: AsyncClient):
    """PATCH /requests/{id}/status — invalid transition 409 (lines 268-278)."""
    create_resp = await client.post("/requests", json={
        "subject": "Invalid transition", "description": "desc",
    })
    display_id = create_resp.json()["display_id"]
    resp = await client.patch(f"/requests/{display_id}/status", json={
        "status": "OVERDUE",
    })
    assert resp.status_code == 409
    body = resp.json()
    assert body["detail"]["code"] == "INVALID_STATUS_TRANSITION"
    assert body["detail"]["current_status"] == "PENDING"


@pytest.mark.asyncio
async def test_update_status_not_found(client: AsyncClient):
    """PATCH /requests/{id}/status — 404 (lines 259-263)."""
    resp = await client.patch("/requests/OLY-0000/status", json={
        "status": "ACKNOWLEDGED",
    })
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_fulfilled_sets_fulfilled_at(client: AsyncClient):
    """PATCH — PENDING→ACKNOWLEDGED→FULFILLED sets fulfilled_at (lines 282-283)."""
    create_resp = await client.post("/requests", json={
        "subject": "Fulfillment test", "description": "desc",
    })
    did = create_resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "ACKNOWLEDGED"})
    resp = await client.patch(f"/requests/{did}/status", json={"status": "FULFILLED"})
    assert resp.status_code == 200
    assert resp.json()["fulfilled_at"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# B) api/routers/ledger.py
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_ledger_state_empty(client: AsyncClient):
    """GET /ledger/state — empty DB (lines 129-152)."""
    resp = await client.get("/ledger/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["global_state_root"] == "0" * 64
    assert data["shard_count"] >= 1
    assert data["total_commits"] == 0


@pytest.mark.asyncio
async def test_ledger_state_with_commits(seeded_client: AsyncClient):
    """GET /ledger/state — with seeded commits."""
    resp = await seeded_client.get("/ledger/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_commits"] >= 1
    assert data["shard_count"] >= 1
    assert len(data["global_state_root"]) == 64


@pytest.mark.asyncio
async def test_shard_state_with_data(seeded_client: AsyncClient):
    """GET /ledger/shard/{shard_id} — with data (lines 177-183)."""
    resp = await seeded_client.get("/ledger/shard/0x4F3A")
    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == "0x4F3A"
    assert data["commit_count"] >= 1
    assert len(data["state_root"]) == 64
    assert len(data["latest_commits"]) >= 1


@pytest.mark.asyncio
async def test_shard_state_empty(client: AsyncClient):
    """GET /ledger/shard/{shard_id} — unused shard."""
    resp = await client.get("/ledger/shard/0xDEAD")
    assert resp.status_code == 200
    data = resp.json()
    assert data["commit_count"] == 0


@pytest.mark.asyncio
async def test_proof_not_found(client: AsyncClient):
    """GET /ledger/proof/{commit_id} — 404 (lines 226-231)."""
    resp = await client.get("/ledger/proof/0x" + "f" * 64)
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "COMMIT_NOT_FOUND"


@pytest.mark.asyncio
async def test_proof_found_dev(seeded_client: AsyncClient):
    """GET /ledger/proof/{commit_id} — development mode (lines 244-277)."""
    commit_id = "0x" + "c" * 64
    resp = await seeded_client.get(f"/ledger/proof/{commit_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["commit_id"] == commit_id
    assert "merkle_proof" in data
    assert "zk_proof" in data


@pytest.mark.asyncio
async def test_activity_empty(client: AsyncClient):
    """GET /ledger/activity — empty feed (lines 321-326)."""
    resp = await client.get("/ledger/activity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_activity_with_data(seeded_client: AsyncClient):
    """GET /ledger/activity — with seeded data."""
    resp = await seeded_client.get("/ledger/activity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1
    item = data["items"][0]
    assert "activity_type" in item
    assert "title" in item


@pytest.mark.asyncio
async def test_activity_filter_by_type(seeded_client: AsyncClient):
    """GET /ledger/activity?activity_type=... — filter."""
    resp = await seeded_client.get("/ledger/activity", params={"activity_type": "DOCUMENT_SUBMITTED"})
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["activity_type"] == "DOCUMENT_SUBMITTED" for i in data["items"])

    resp2 = await seeded_client.get("/ledger/activity", params={"activity_type": "NONEXISTENT"})
    assert resp2.status_code == 200
    assert resp2.json()["items"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# C) api/routers/documents.py
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_doc_commit_request_not_found(client: AsyncClient):
    """POST /doc/commit — request_id not found 404 (lines 71-72)."""
    resp = await client.post("/doc/commit", json={
        "doc_hash": "a" * 64,
        "request_id": str(uuid.uuid4()),
    })
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_doc_commit_success(client: AsyncClient):
    """POST /doc/commit — success (lines 94-121)."""
    resp = await client.post("/doc/commit", json={
        "doc_hash": "ab" * 32,
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["doc_hash"] == "ab" * 32
    assert data["commit_id"].startswith("0x")
    assert data["shard_id"] == "0x4F3A"
    assert data["merkle_root"] is not None


@pytest.mark.asyncio
async def test_doc_verify_not_found(client: AsyncClient):
    """POST /doc/verify — commit not found returns verified=False (line 158)."""
    resp = await client.post("/doc/verify", json={
        "commit_id": "0x" + "f" * 64,
    })
    assert resp.status_code == 200
    assert resp.json()["verified"] is False


@pytest.mark.asyncio
async def test_doc_verify_success(client: AsyncClient):
    """POST /doc/verify — success (lines 174-187)."""
    commit_resp = await client.post("/doc/commit", json={
        "doc_hash": "cd" * 32,
    })
    commit_id = commit_resp.json()["commit_id"]
    resp = await client.post("/doc/verify", json={
        "commit_id": commit_id,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True
    assert data["commit"]["commit_id"] == commit_id
    assert data["merkle_proof"] is not None
    assert data["zk_proof"] is not None


@pytest.mark.asyncio
async def test_doc_verify_embargoed(fresh_engine):
    """POST /doc/verify — embargoed commit returns 403 (lines 161-165)."""
    sf = async_sessionmaker(fresh_engine, expire_on_commit=False, class_=AsyncSession)

    # Use a far-future aware datetime for embargo; patch datetime.now in the
    # router module so the comparison uses the same type SQLite returns.
    future_aware = datetime.now(timezone.utc) + timedelta(days=30)
    commit_id = "0x" + "e" * 64
    async with sf() as session:
        commit = DocCommit(
            id=str(uuid.uuid4()), doc_hash="ee" * 32,
            commit_id=commit_id, shard_id="0x4F3A",
            epoch_timestamp=datetime.now(timezone.utc),
            merkle_root="dd" * 32, embargo_until=future_aware,
        )
        session.add(commit)
        await session.commit()

    async def override_get_db():
        async with sf() as session:
            yield session

    # SQLite returns naive datetimes; the router compares with
    # datetime.now(timezone.utc) which is aware.  Patch so both sides are naive.
    _real_dt = datetime

    class _NaiveDatetime(_real_dt):
        @classmethod
        def now(cls, tz=None):
            return _real_dt.now()

    with patch.dict(os.environ, {
        "OLYMPUS_ENV": "development",
        "OLYMPUS_ALLOW_DEV_AUTH": "1",
        "OLYMPUS_FOIA_API_KEYS": "[]",
    }):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        with patch("api.routers.documents.datetime", _NaiveDatetime):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post("/doc/verify", json={"commit_id": commit_id})
    assert resp.status_code == 403
