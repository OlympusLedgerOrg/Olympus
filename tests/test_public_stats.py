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
    public_stats._stats_cache.clear()
    yield
    public_stats._stats_cache.clear()


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
    assert data["nodes"] == 0
    assert data["copies"] == 0
    assert data["shards"] == 0
    assert data["proofs"] == 0
    assert data["sbts_issued"] == 0
    assert isinstance(data["uptime"], str)
    assert isinstance(data["uptime_seconds"], int)


@pytest.mark.asyncio
async def test_public_stats_counts_public_tables_for_both_routes(
    stats_app: FastAPI, sqlite_engine
) -> None:
    async with sqlite_engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE operators (
                    id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    revoked_at TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO operators (id, role, revoked_at)
                VALUES
                  ('node-a', 'node_operator', NULL),
                  ('admin-a', 'admin', NULL),
                  ('node-b', 'node_operator', '2026-01-01')
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE witness_observations (
                    id TEXT PRIMARY KEY,
                    origin TEXT NOT NULL
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO witness_observations (id, origin)
                VALUES ('w1', 'origin-a'), ('w2', 'origin-a'), ('w3', 'origin-b')
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE doc_commits (
                    id TEXT PRIMARY KEY,
                    shard_id TEXT NOT NULL,
                    zk_proof TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO doc_commits (id, shard_id, zk_proof)
                VALUES ('d1', 'a', 'proof-a'), ('d2', 'a', NULL), ('d3', 'b', '')
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE dataset_artifacts (
                    id TEXT PRIMARY KEY,
                    shard_id TEXT NOT NULL,
                    zk_proof TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO dataset_artifacts (id, shard_id, zk_proof)
                VALUES ('ds1', 'b', 'proof-b')
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE key_credentials (
                    id TEXT PRIMARY KEY,
                    sbt_nontransferable BOOLEAN NOT NULL,
                    revoked_at TEXT
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO key_credentials (id, sbt_nontransferable, revoked_at)
                VALUES
                  ('sbt-a', TRUE, NULL),
                  ('sbt-b', TRUE, NULL),
                  ('sbt-c', TRUE, '2026-01-01'),
                  ('legacy-a', FALSE, NULL)
                """
            )
        )

    async with AsyncClient(
        transport=ASGITransport(app=stats_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        public_response = await client.get("/public/stats")
        versioned_response = await client.get("/v1/public/stats")

    assert public_response.status_code == 200
    assert versioned_response.status_code == 200
    assert public_response.json()["nodes"] == 3
    assert public_response.json()["copies"] == 3
    assert public_response.json()["shards"] == 2
    assert public_response.json()["proofs"] == 2
    assert public_response.json()["sbts_issued"] == 2
    assert versioned_response.json()["nodes"] == 3
    assert versioned_response.json()["copies"] == 3
    assert versioned_response.json()["shards"] == 2
    assert versioned_response.json()["proofs"] == 2
    assert versioned_response.json()["sbts_issued"] == 2


@pytest.mark.asyncio
async def test_public_stats_ignores_internal_tree_and_legacy_count_tables(
    stats_app: FastAPI, sqlite_engine
) -> None:
    async with sqlite_engine.begin() as conn:
        await conn.execute(text("CREATE TABLE ledger_entries (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))
        await conn.execute(text("INSERT INTO ledger_entries DEFAULT VALUES"))
        await conn.execute(text("CREATE TABLE cdhs_smf_leaves (id INTEGER PRIMARY KEY)"))
        await conn.execute(text("INSERT INTO cdhs_smf_leaves DEFAULT VALUES"))
        await conn.execute(text("INSERT INTO cdhs_smf_leaves DEFAULT VALUES"))
        await conn.execute(text("CREATE TABLE shard_headers (shard_id TEXT NOT NULL)"))
        await conn.execute(text("INSERT INTO shard_headers (shard_id) VALUES ('a'), ('b')"))
        await conn.execute(
            text(
                """
                CREATE TABLE ingestion_proofs (
                    proof_id TEXT PRIMARY KEY,
                    shard_id TEXT NOT NULL
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                INSERT INTO ingestion_proofs (proof_id, shard_id)
                VALUES ('p1', 'demo'), ('p2', 'demo'), ('p3', 'archive')
                """
            )
        )

    async with AsyncClient(
        transport=ASGITransport(app=stats_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/v1/public/stats")

    assert response.status_code == 200
    data = response.json()
    assert data["nodes"] == 0
    assert data["copies"] == 0
    assert data["shards"] == 0
    assert data["proofs"] == 0
    assert data["sbts_issued"] == 0
