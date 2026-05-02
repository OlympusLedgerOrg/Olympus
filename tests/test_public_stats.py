"""Tests for api/routers/public_stats.py.

Covers zero-count behaviour when schema tables are absent, live count
aggregation across both route prefixes (/public/stats and /v1/public/stats),
and the 10-second response-cache contract.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

from api.routers import public_stats


@pytest.fixture
def stats_app() -> FastAPI:
    """Build a minimal FastAPI application that only mounts the public-stats router.

    Returns:
        FastAPI: Application instance with the router at both ``/public`` and
            ``/v1/public`` prefixes.
    """
    app = FastAPI()
    app.include_router(public_stats.router)
    app.include_router(public_stats.router, prefix="/v1")
    return app


@pytest.fixture(autouse=True)
def clear_public_stats_cache() -> None:
    """Clear the module-level stats cache before and after every test.

    Ensures that a cached result from one test cannot bleed into another.
    """
    public_stats._stats_cache.clear()
    yield
    public_stats._stats_cache.clear()


@pytest_asyncio.fixture
async def sqlite_engine(monkeypatch) -> AsyncEngine:
    """Create an in-memory async SQLite engine and patch it into the router.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace ``public_stats.engine``.

    Returns:
        AsyncEngine: The in-memory engine; disposed after the test finishes.
    """
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
        await conn.execute(text("CREATE TABLE ingestion_proofs (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO ingestion_proofs DEFAULT VALUES"))

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


@pytest.mark.asyncio
async def test_public_stats_cache_behavior(
    stats_app: FastAPI, sqlite_engine: AsyncEngine
) -> None:
    """Verify the 10-second response-cache contract for both route prefixes.

    The test covers three phases without any real wall-clock sleeping:
    1. First request populates the cache from the DB.
    2. A second request within the TTL window returns the stale cached value
       even after new rows are inserted.
    3. After the cache entry's timestamp is back-dated to simulate TTL expiry,
       a third request re-queries the DB and returns the updated count.

    Args:
        stats_app: Minimal FastAPI app with the public-stats router.
        sqlite_engine: In-memory async SQLite engine patched into the router.
    """
    # Seed one row so the first response has copies == 1.
    async with sqlite_engine.begin() as conn:
        await conn.execute(text("CREATE TABLE ledger_entries (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))

    async with AsyncClient(
        transport=ASGITransport(app=stats_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        # Phase 1 – populate the cache.
        first = await client.get("/public/stats")
        assert first.status_code == 200
        assert first.json()["copies"] == 1

        # Insert another row while still inside the TTL window.
        async with sqlite_engine.begin() as conn:
            await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))

        # Phase 2 – within-TTL request must return the stale cached count.
        second = await client.get("/public/stats")
        assert second.status_code == 200
        assert second.json()["copies"] == 1, "cache hit: new row must not be visible yet"

        # Also verify the /v1 prefix serves from the same cache.
        second_v1 = await client.get("/v1/public/stats")
        assert second_v1.status_code == 200
        assert second_v1.json()["copies"] == 1, "v1 cache hit: new row must not be visible yet"

        # Phase 3 – simulate TTL expiry by back-dating the cached timestamp.
        cached_at, cached_stats = public_stats._stats_cache["latest"]
        public_stats._stats_cache["latest"] = (
            cached_at - public_stats._CACHE_TTL_SECONDS - 1,
            cached_stats,
        )

        # After simulated expiry the endpoint must re-query and reflect the new row.
        third = await client.get("/public/stats")
        assert third.status_code == 200
        assert third.json()["copies"] == 2, "cache miss: updated count must be returned"
