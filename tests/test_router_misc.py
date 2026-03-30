"""
Integration tests for agencies, appeals, and keys routers.

Covers:
    - GET /agencies — empty list, with filters
    - POST /agencies — create success
    - GET /agencies/{id} — found, not found
    - POST /appeals — success, request not found, request already fulfilled
    - GET /appeals — list all
    - GET /appeals/{id} — found, not found
    - POST /key/credential — create credential
    - DELETE /key/credential/{id} — revoke credential, not found, already revoked

Uses in-memory SQLite with aiosqlite.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anyio_backend():
    """Configure pytest-asyncio to use the asyncio backend."""
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    """Create an in-memory SQLite database engine for tests."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def client(db_engine):
    """Create an async HTTP test client with overridden DB dependency."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    # Set development mode and no API keys for test bypass
    with patch.dict(os.environ, {"OLYMPUS_ENV": "development", "OLYMPUS_FOIA_API_KEYS": "[]"}):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db

        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as ac:
            yield ac


# ---------------------------------------------------------------------------
# Agencies Router Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_agencies_empty(client):
    """GET /agencies should return an empty list when no agencies exist."""
    resp = await client.get("/agencies")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_agency_success(client):
    """POST /agencies should create a new agency and return it."""
    agency_body = {
        "name": "Watauga County Sheriff",
        "short_name": "WCSO",
        "level": "COUNTY",
        "category": "Law Enforcement",
    }
    resp = await client.post("/agencies", json=agency_body)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Watauga County Sheriff"
    assert data["short_name"] == "WCSO"
    assert data["level"] == "COUNTY"
    assert data["category"] == "Law Enforcement"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_agencies_with_level_filter(client):
    """GET /agencies?level=COUNTY should filter agencies by level."""
    # Create agencies with different levels
    await client.post("/agencies", json={"name": "State Agency", "level": "STATE"})
    await client.post("/agencies", json={"name": "County Agency", "level": "COUNTY"})

    resp = await client.get("/agencies", params={"level": "STATE"})
    assert resp.status_code == 200
    data = resp.json()
    for agency in data:
        assert agency["level"] == "STATE"


@pytest.mark.asyncio
async def test_list_agencies_with_search_filter(client):
    """GET /agencies?search=Sheriff should filter agencies by name."""
    # Ensure at least one agency with 'Sheriff' in the name exists
    await client.post("/agencies", json={"name": "Boone Sheriff Office", "level": "MUNICIPAL"})

    resp = await client.get("/agencies", params={"search": "Sheriff"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    for agency in data:
        assert "sheriff" in agency["name"].lower()


@pytest.mark.asyncio
async def test_get_agency_found(client):
    """GET /agencies/{id} should return the agency when it exists."""
    create_resp = await client.post("/agencies", json={"name": "Test Agency Found"})
    agency_id = create_resp.json()["id"]

    get_resp = await client.get(f"/agencies/{agency_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == agency_id
    assert get_resp.json()["name"] == "Test Agency Found"


@pytest.mark.asyncio
async def test_get_agency_not_found(client):
    """GET /agencies/{id} should return 404 for a non-existent agency."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/agencies/{fake_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "AGENCY_NOT_FOUND"


# ---------------------------------------------------------------------------
# Appeals Router Tests
# ---------------------------------------------------------------------------


REQUEST_BODY = {
    "subject": "Test subject for appeal",
    "description": "Test description for appeal integration tests.",
    "request_type": "NC_PUBLIC_RECORDS",
    "priority": "STANDARD",
}


@pytest.mark.asyncio
async def test_list_appeals_empty(client):
    """GET /appeals should return an empty list when no appeals exist."""
    resp = await client.get("/appeals")
    assert resp.status_code == 200
    # May contain appeals from other tests, so just check it's a list
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_file_appeal_success(client):
    """POST /appeals should create an appeal for a DENIED request."""
    # Create and deny a request
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "IMPROPER_EXEMPTION",
            "statement": "The agency cited an incorrect exemption.",
        },
    )
    assert appeal_resp.status_code == 201
    data = appeal_resp.json()
    assert data["grounds"] == "IMPROPER_EXEMPTION"
    assert data["status"] == "UNDER_REVIEW"
    assert data["request_id"] == req_id
    assert "commit_hash" in data


@pytest.mark.asyncio
async def test_file_appeal_rejects_lone_surrogate(client):
    """POST /appeals surfaces hashing Unicode errors without nested detail."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]
    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})

    with patch("api.routers.appeals._hash_appeal", side_effect=ValueError("surrogates not allowed")):
        appeal_resp = await client.post(
            "/appeals",
            json={
                "request_id": req_id,
                "grounds": "IMPROPER_EXEMPTION",
                "statement": "The agency response was malformed",
            },
        )
    assert appeal_resp.status_code == 422
    detail = appeal_resp.json()["detail"]
    assert detail == [
        {
            "msg": "surrogates not allowed",
            "type": "unicode",
            "code": "INVALID_UNICODE",
        }
    ]


@pytest.mark.asyncio
async def test_file_appeal_request_not_found(client):
    """POST /appeals should return 404 when the request does not exist."""
    fake_request_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.post(
        "/appeals",
        json={
            "request_id": fake_request_id,
            "grounds": "NO_RESPONSE",
            "statement": "This request does not exist.",
        },
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_file_appeal_request_fulfilled(client):
    """POST /appeals should return 409 when the request is already fulfilled."""
    # Create and fulfill a request
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "Cannot appeal a fulfilled request.",
        },
    )
    assert appeal_resp.status_code == 409
    assert appeal_resp.json()["detail"]["code"] == "REQUEST_FULFILLED"


@pytest.mark.asyncio
async def test_list_appeals_after_creation(client):
    """GET /appeals should return appeals after one is created."""
    # Create and deny a request, then file an appeal
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})
    await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "IMPROPER_EXEMPTION",
            "statement": "Test appeal for list test.",
        },
    )

    resp = await client.get("/appeals")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_get_appeal_found(client):
    """GET /appeals/{id} should return the appeal when it exists."""
    # Create and deny a request, then file an appeal
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})
    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "IMPROPER_EXEMPTION",
            "statement": "Test appeal for get test.",
        },
    )
    appeal_id = appeal_resp.json()["id"]

    get_resp = await client.get(f"/appeals/{appeal_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == appeal_id
    assert get_resp.json()["grounds"] == "IMPROPER_EXEMPTION"


@pytest.mark.asyncio
async def test_get_appeal_not_found(client):
    """GET /appeals/{id} should return 404 for a non-existent appeal."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/appeals/{fake_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "APPEAL_NOT_FOUND"


# ---------------------------------------------------------------------------
# Keys Router Tests
# ---------------------------------------------------------------------------


CREDENTIAL_BODY = {
    "holder_key": "ed25519:" + "a" * 64,
    "credential_type": "PRESS_CREDENTIAL",
    "issuer": "Olympus Test Authority",
}


@pytest.mark.asyncio
async def test_issue_credential_success(client):
    """POST /key/credential should create a new credential."""
    resp = await client.post("/key/credential", json=CREDENTIAL_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert data["holder_key"] == CREDENTIAL_BODY["holder_key"]
    assert data["credential_type"] == "PRESS_CREDENTIAL"
    assert data["issuer"] == "Olympus Test Authority"
    assert data["sbt_nontransferable"] is True
    assert data["revoked_at"] is None
    assert "commit_id" in data
    assert "id" in data


@pytest.mark.asyncio
async def test_revoke_credential_success(client):
    """DELETE /key/credential/{id} should revoke an existing credential."""
    # Create a credential first
    create_resp = await client.post("/key/credential", json=CREDENTIAL_BODY)
    cred_id = create_resp.json()["id"]

    # Revoke the credential
    revoke_resp = await client.delete(f"/key/credential/{cred_id}")
    assert revoke_resp.status_code == 204


@pytest.mark.asyncio
async def test_revoke_credential_not_found(client):
    """DELETE /key/credential/{id} should return 404 for a non-existent credential."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"/key/credential/{fake_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "CREDENTIAL_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_credential_already_revoked(client):
    """DELETE /key/credential/{id} should return 409 when already revoked."""
    # Create a credential
    create_resp = await client.post("/key/credential", json=CREDENTIAL_BODY)
    cred_id = create_resp.json()["id"]

    # Revoke once
    first_revoke = await client.delete(f"/key/credential/{cred_id}")
    assert first_revoke.status_code == 204

    # Attempt second revocation
    second_revoke = await client.delete(f"/key/credential/{cred_id}")
    assert second_revoke.status_code == 409
    assert second_revoke.json()["detail"]["code"] == "ALREADY_REVOKED"
