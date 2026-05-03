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
from api.routers import user_auth


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture()
async def client():
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
            "OLYMPUS_ADMIN_KEY": "A" * 32,
            "OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION": "",
        },
        clear=False,
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac

    await engine.dispose()


@pytest.mark.asyncio
async def test_public_register_defaults_to_read_verify(client):
    payload = {"email": "default@example.com", "password": "averystrongpassword123"}
    resp = await client.post("/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["read", "verify"]


@pytest.mark.asyncio
async def test_public_register_ingest_scope_rejected_without_approval(client):
    payload = {
        "email": "ingest-blocked@example.com",
        "password": "averystrongpassword123",
        "scopes": ["ingest", "verify"],
    }
    resp = await client.post("/auth/register", json=payload)
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_public_register_ingest_scope_allowed_with_admin_approval(client):
    payload = {
        "email": "ingest-approved@example.com",
        "password": "averystrongpassword123",
        "scopes": ["ingest", "verify"],
        "expires_at": "2099-01-01T00:00:00Z",
    }
    signature = user_auth._registration_approval_signature(payload_to_request(payload), "A" * 32)
    resp = await client.post(
        "/auth/register",
        json=payload,
        headers={"x-admin-registration-approval": signature},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["ingest", "verify"]


def payload_to_request(payload: dict[str, object]) -> user_auth.RegisterRequest:
    return user_auth.RegisterRequest.model_validate(payload)
