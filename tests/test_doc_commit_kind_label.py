from __future__ import annotations

import json

import blake3
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.models.ledger_activity import LedgerActivity


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture()
async def client_and_sessionmaker():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac, session_factory

    await engine.dispose()


@pytest.mark.asyncio
async def test_doc_commit_response_and_ledger_row_include_client_asserted_kind(client_and_sessionmaker):
    client, session_factory = client_and_sessionmaker
    doc_hash = blake3.blake3(b"client-asserted-kind").hexdigest()

    resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    assert payload["kind"] == "client_asserted_hash"

    async with session_factory() as session:
        result = await session.execute(
            select(LedgerActivity)
            .where(LedgerActivity.related_commit_id == payload["commit_id"])
            .where(LedgerActivity.activity_type == "DOCUMENT_SUBMITTED")
            .limit(1)
        )
        activity = result.scalars().first()

    assert activity is not None
    assert activity.details_json is not None
    assert json.loads(activity.details_json)["kind"] == "client_asserted_hash"
