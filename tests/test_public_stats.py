from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from api.routers import public_stats


@pytest.fixture
def stats_app() -> FastAPI:
    app = FastAPI()
    app.include_router(public_stats.router)
    app.include_router(public_stats.router, prefix="/v1")
    return app


@pytest.fixture(autouse=True)
def clear_public_stats_cache():
    public_stats._cached_stats = None
    yield
    public_stats._cached_stats = None


@pytest_asyncio.fixture
async def sqlite_engine(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    monkeypatch.setattr(public_stats, "engine", engine)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_public_stats_handles_sqlite_without_schema_tables(
    stats_app: FastAPI, sqlite_engine
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=stats_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/v1/public/stats")

    assert response.status_code == 200
    data = response.json()
    assert data["copies"] == 0
    assert data["shards"] == 0
    assert data["proofs"] == 0
    assert isinstance(data["uptime"], str)
    assert isinstance(data["uptime_seconds"], int)


@pytest.mark.asyncio
async def test_public_stats_counts_existing_tables_for_both_routes(
    stats_app: FastAPI, sqlite_engine
) -> None:
    async with sqlite_engine.begin() as conn:
        await conn.execute(text("CREATE TABLE ledger_entries (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))
        await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))
        await conn.execute(text("CREATE TABLE shard_headers (shard_id TEXT NOT NULL)"))
        await conn.execute(text("INSERT INTO shard_headers (shard_id) VALUES ('a'), ('a'), ('b')"))
        await conn.execute(text("CREATE TABLE proof_requests (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO proof_requests DEFAULT VALUES"))

    async with AsyncClient(
        transport=ASGITransport(app=stats_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        public_response = await client.get("/public/stats")
        versioned_response = await client.get("/v1/public/stats")

    assert public_response.status_code == 200
    assert versioned_response.status_code == 200
    assert public_response.json()["copies"] == 2
    assert public_response.json()["shards"] == 2
    assert public_response.json()["proofs"] == 1
    assert versioned_response.json()["copies"] == 2
    assert versioned_response.json()["shards"] == 2
    assert versioned_response.json()["proofs"] == 1
