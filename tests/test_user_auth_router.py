"""
Tests for the DB-backed user auth endpoints introduced in PR #768.

Covers:
    - POST /auth/register — happy path, duplicate email, weak password,
      privileged-scope rejection.
    - POST /auth/login — happy path, invalid credentials.
    - POST /auth/keys, GET /auth/keys, DELETE /auth/keys/{id} — auth flow,
      subset-of-caller-scopes enforcement, listing, revocation, 401.
    - POST /key/admin/generate — missing admin key (503), wrong admin key
      (401), success path with response shape.
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


@pytest_asyncio.fixture()
async def fresh_db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def auth_client(fresh_db_engine):
    """HTTP client with the user_auth and keys routers wired to a fresh DB."""
    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )

    async def override_get_db():
        async with session_factory() as session:
            yield session

    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_ALLOW_DEV_AUTH": "1",
            "OLYMPUS_FOIA_API_KEYS": "[]",
            "OLYMPUS_ADMIN_KEY": "test-admin-secret",
        },
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


REG_BODY = {
    "email": "alice@example.com",
    "password": "supersecretpw1234",
    "name": "alice-key",
    "scopes": ["ingest", "verify"],
    "expires_at": "2099-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# /auth/register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_success(auth_client):
    resp = await auth_client.post("/auth/register", json=REG_BODY)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["email"] == REG_BODY["email"]
    assert data["scopes"] == ["ingest", "verify"]
    assert len(data["api_key"]) == 64  # 32 bytes hex
    assert data["user_id"]
    assert data["key_id"]


@pytest.mark.asyncio
async def test_register_duplicate_email_conflict(auth_client):
    first = await auth_client.post("/auth/register", json=REG_BODY)
    assert first.status_code == 201
    second = await auth_client.post("/auth/register", json=REG_BODY)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password_rejected(auth_client):
    body = {**REG_BODY, "password": "short"}
    resp = await auth_client.post("/auth/register", json=body)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_rejects_privileged_scope(auth_client):
    """Self-service registration must not allow callers to mint admin/write keys."""
    for bad_scope in ("admin", "write"):
        body = {**REG_BODY, "email": f"{bad_scope}@example.com", "scopes": ["ingest", bad_scope]}
        resp = await auth_client.post("/auth/register", json=body)
        assert resp.status_code == 403, resp.text
        assert bad_scope in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_rejects_unknown_scope(auth_client):
    body = {**REG_BODY, "scopes": ["ingest", "bogus"]}
    resp = await auth_client.post("/auth/register", json=body)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /auth/login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    resp = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": REG_BODY["password"]},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["email"] == REG_BODY["email"]
    assert len(data["keys"]) == 1
    assert data["keys"][0]["scopes"] == ["ingest", "verify"]


@pytest.mark.asyncio
async def test_login_wrong_password(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)
    resp = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": "wrong-password-xx"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_email(auth_client):
    resp = await auth_client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "anything12345"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /auth/keys (CRUD)
# ---------------------------------------------------------------------------


async def _register_and_get_key(client: AsyncClient, **overrides) -> str:
    body = {**REG_BODY, **overrides}
    resp = await client.post("/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["api_key"]


@pytest.mark.asyncio
async def test_create_key_requires_auth(auth_client):
    resp = await auth_client.post("/auth/keys", json={"name": "k2"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_list_revoke_key_flow(auth_client):
    api_key = await _register_and_get_key(auth_client)
    headers = {"X-API-Key": api_key}

    create = await auth_client.post(
        "/auth/keys",
        headers=headers,
        json={"name": "second-key", "scopes": ["verify"], "expires_at": "2099-01-01T00:00:00Z"},
    )
    assert create.status_code == 201, create.text
    new_key_id = create.json()["key_id"]
    assert create.json()["scopes"] == ["verify"]

    listing = await auth_client.get("/auth/keys", headers=headers)
    assert listing.status_code == 200
    ids = {k["id"] for k in listing.json()}
    assert new_key_id in ids
    assert len(ids) == 2  # original + new

    revoke = await auth_client.delete(f"/auth/keys/{new_key_id}", headers=headers)
    assert revoke.status_code == 204

    listing2 = await auth_client.get("/auth/keys", headers=headers)
    remaining = {k["id"] for k in listing2.json()}
    assert new_key_id not in remaining


@pytest.mark.asyncio
async def test_create_key_rejects_scope_escalation(auth_client):
    """A key with scopes=[ingest,verify] must not be able to mint an admin key."""
    api_key = await _register_and_get_key(auth_client)
    headers = {"X-API-Key": api_key}

    resp = await auth_client.post(
        "/auth/keys",
        headers=headers,
        json={"name": "escalated", "scopes": ["ingest", "admin"]},
    )
    assert resp.status_code == 403, resp.text
    assert "admin" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_key_subset_allowed(auth_client):
    """Creating a key with a strict subset of caller's scopes is allowed."""
    api_key = await _register_and_get_key(auth_client, scopes=["ingest", "verify"])
    headers = {"X-API-Key": api_key}
    resp = await auth_client.post(
        "/auth/keys", headers=headers, json={"name": "narrow", "scopes": ["verify"]}
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["verify"]


@pytest.mark.asyncio
async def test_revoke_key_not_found(auth_client):
    api_key = await _register_and_get_key(auth_client)
    resp = await auth_client.delete(
        "/auth/keys/00000000-0000-0000-0000-000000000000",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /key/admin/generate
# ---------------------------------------------------------------------------


GEN_BODY = {
    "name": "ops-key",
    "scopes": ["ingest", "verify"],
    "expires_at": "2099-01-01T00:00:00Z",
}


@pytest.mark.asyncio
async def test_admin_generate_no_admin_key():
    """503 when OLYMPUS_ADMIN_KEY is not configured."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_ALLOW_DEV_AUTH": "1",
            "OLYMPUS_FOIA_API_KEYS": "[]",
        },
        clear=False,
    ):
        os.environ.pop("OLYMPUS_ADMIN_KEY", None)
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/key/admin/generate", json=GEN_BODY)
            assert resp.status_code == 503

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_generate_wrong_key(auth_client):
    """401 when the X-Admin-Key header is wrong."""
    resp = await auth_client.post(
        "/key/admin/generate",
        headers={"x-admin-key": "wrong"},
        json=GEN_BODY,
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_generate_success(auth_client):
    """200/201 with full response shape when admin key is correct."""
    resp = await auth_client.post(
        "/key/admin/generate",
        headers={"x-admin-key": "test-admin-secret"},
        json=GEN_BODY,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert len(data["raw_key"]) == 64
    assert len(data["key_hash"]) == 64
    assert data["key_id"] == "ops-key"
    assert data["scopes"] == ["ingest", "verify"]
    assert data["expires_at"] == "2099-01-01T00:00:00Z"
    # env_entry must be valid JSON containing the key_hash
    import json as _json
    entry = _json.loads(data["env_entry"])
    assert entry["key_hash"] == data["key_hash"]
    assert entry["key_id"] == "ops-key"
