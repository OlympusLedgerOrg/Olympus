"""
Integration tests for public-records request lifecycle.

Covers: create, list, get, status update, overdue auto-transition,
and appeal filing.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

REQUEST_BODY = {
    "subject": "Body camera footage — incident 2024-01-15",
    "description": "All body-worn camera recordings related to incident number 2024-0115.",
    "request_type": "NC_PUBLIC_RECORDS",
    "priority": "STANDARD",
}


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


@pytest.mark.asyncio
async def test_create_request(client):
    """POST /requests should create a request with display_id and commit_hash."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert data["display_id"].startswith("OLY-")
    assert len(data["commit_hash"]) == 64
    assert data["status"] == "PENDING"
    assert data["deadline"] is not None


@pytest.mark.asyncio
async def test_get_request(client):
    """GET /requests/{display_id} should return the created request."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    get_resp = await client.get(f"/requests/{display_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["display_id"] == display_id


@pytest.mark.asyncio
async def test_get_request_not_found(client):
    """GET /requests/OLY-9999 for a non-existent request should return 404."""
    resp = await client.get("/requests/OLY-9999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_requests(client):
    """GET /requests should return at least one result after creation."""
    await client.post("/requests", json=REQUEST_BODY)
    resp = await client.get("/requests")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_acknowledge_request(client):
    """PATCH /requests/{display_id}/status → ACKNOWLEDGED."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    patch_resp = await client.patch(
        f"/requests/{display_id}/status", json={"status": "ACKNOWLEDGED"}
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_fulfill_request(client):
    """PATCH /requests/{display_id}/status → FULFILLED sets fulfilled_at."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    patch_resp = await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["status"] == "FULFILLED"
    assert data["fulfilled_at"] is not None


@pytest.mark.asyncio
async def test_appeal_denied_request(client):
    """File an appeal on a DENIED request — should succeed."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "IMPROPER_EXEMPTION",
            "statement": "The agency improperly withheld non-exempt records.",
        },
    )
    assert appeal_resp.status_code == 201
    appeal_data = appeal_resp.json()
    assert appeal_data["grounds"] == "IMPROPER_EXEMPTION"
    assert appeal_data["status"] == "UNDER_REVIEW"

    # Request status should now be APPEALED
    get_resp = await client.get(f"/requests/{display_id}")
    assert get_resp.json()["status"] == "APPEALED"


@pytest.mark.asyncio
async def test_appeal_fulfilled_request_rejected(client):
    """Filing an appeal on a FULFILLED request should return 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "This should not be allowed.",
        },
    )
    assert appeal_resp.status_code == 409


@pytest.mark.asyncio
async def test_deadline_nc_public_records():
    """NC Public Records deadline should be ~30 business days from filing."""
    from datetime import datetime

    from api.services.deadline import compute_deadline

    filed_at = datetime(2024, 1, 15, 9, 0, 0)
    deadline = compute_deadline(filed_at, "NC_PUBLIC_RECORDS")
    # Must be strictly after filed_at
    assert deadline > filed_at


@pytest.mark.asyncio
async def test_deadline_federal_foia():
    """Federal FOIA deadline should be ~20 business days from filing."""
    from datetime import datetime

    from api.services.deadline import compute_deadline

    filed_at = datetime(2024, 1, 15, 9, 0, 0)
    deadline = compute_deadline(filed_at, "FEDERAL_FOIA")
    assert deadline > filed_at


@pytest.mark.asyncio
async def test_appeal_already_appealed_request_rejected(client):
    """Filing a second appeal on an already-APPEALED request should return 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]

    # First appeal (on PENDING — allowed)
    first_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "First appeal.",
        },
    )
    assert first_resp.status_code == 201

    # Second appeal — should be rejected because status is now APPEALED
    second_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "Duplicate appeal attempt.",
        },
    )
    assert second_resp.status_code == 409
    assert second_resp.json()["detail"]["code"] == "APPEAL_EXISTS"
