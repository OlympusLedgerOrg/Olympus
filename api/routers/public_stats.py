from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import and_, column, func, inspect, select, table
from sqlalchemy.sql.elements import quoted_name

from api.db import engine


router = APIRouter(prefix="/public", tags=["public-stats"])

_STARTED_AT = time.time()
_CACHE_TTL_SECONDS = 10
_stats_cache: dict[str, tuple[float, PublicStats]] = {}


class PublicStats(BaseModel):
    nodes: int
    shards: int
    proofs: int
    sbts_issued: int
    uptime: str
    uptime_seconds: int
    copies: int = 0


def _quoted_table(table_name: str):
    return table(quoted_name(table_name, quote=True))


async def _count_query(conn: Any, stmt: Any) -> int:
    result = await conn.execute(stmt)
    value = result.scalar()
    return int(value or 0)


async def _table_exists(conn: Any, table_name: str) -> bool:
    def _has_table(sync_conn: Any) -> bool:
        schema = None if sync_conn.dialect.name == "sqlite" else "public"
        return bool(inspect(sync_conn).has_table(table_name, schema=schema))

    return bool(await conn.run_sync(_has_table))


async def _column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    if not await _table_exists(conn, table_name):
        return False

    def _has_column(sync_conn: Any) -> bool:
        schema = None if sync_conn.dialect.name == "sqlite" else "public"
        columns = inspect(sync_conn).get_columns(table_name, schema=schema)
        return any(col["name"] == column_name for col in columns)

    return bool(await conn.run_sync(_has_column))


async def _count_table_if_exists(conn: Any, table_name: str) -> int:
    if not await _table_exists(conn, table_name):
        return 0

    stmt = select(func.count()).select_from(_quoted_table(table_name))
    return await _count_query(conn, stmt)


async def _count_node_operators(conn: Any) -> int:
    if not await _column_exists(conn, "operators", "role"):
        return 0

    filters = [column("role") == "node_operator"]
    if await _column_exists(conn, "operators", "revoked_at"):
        filters.append(column("revoked_at").is_(None))

    stmt = select(func.count()).select_from(_quoted_table("operators")).where(and_(*filters))
    return await _count_query(conn, stmt)


async def _count_issued_sbts(conn: Any) -> int:
    if not await _table_exists(conn, "key_credentials"):
        return 0

    filters = []
    if await _column_exists(conn, "key_credentials", "revoked_at"):
        filters.append(column("revoked_at").is_(None))
    if await _column_exists(conn, "key_credentials", "sbt_nontransferable"):
        filters.append(column("sbt_nontransferable").is_(True))

    stmt: Any = select(func.count()).select_from(_quoted_table("key_credentials"))
    if filters:
        stmt = stmt.where(and_(*filters))
    return await _count_query(conn, stmt)


async def _distinct_column_values_if_exists(
    conn: Any, table_name: str, column_name: str
) -> set[str]:
    if not await _column_exists(conn, table_name, column_name):
        return set()

    stmt: Any = select(column(column_name)).select_from(_quoted_table(table_name)).distinct()
    result = await conn.execute(stmt)
    return {str(value) for value in result.scalars().all() if value is not None}


async def _count_non_empty_column_if_exists(conn: Any, table_name: str, column_name: str) -> int:
    if not await _column_exists(conn, table_name, column_name):
        return 0

    target: Any = column(column_name)
    stmt = (
        select(func.count())
        .select_from(_quoted_table(table_name))
        .where(and_(target.is_not(None), target != ""))
    )
    return await _count_query(conn, stmt)


def _format_uptime(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


@router.get("/stats", response_model=PublicStats)
async def get_public_stats() -> PublicStats:
    """Return aggregated public ledger statistics from an async GET endpoint.

    Args:
        None.

    Returns:
        PublicStats: Counts for nodes, shards, proofs, and process uptime.
    """
    now = time.time()
    cached = _stats_cache.get("latest")
    if cached is not None:
        cached_at, stats = cached
        if now - cached_at < _CACHE_TTL_SECONDS:
            return stats

    async with engine.connect() as conn:
        # Public stats should describe system-facing ledger entities, not
        # internal SMT rows. Counting internal tree tables makes a small local
        # database look like it has thousands of public records.
        witness_origins = await _distinct_column_values_if_exists(
            conn, "witness_observations", "origin"
        )
        nodes = await _count_node_operators(conn) + len(witness_origins)
        sbts_issued = await _count_issued_sbts(conn)

        shard_ids: set[str] = set()
        for table_name in (
            "doc_commits",
            "dataset_artifacts",
            "dataset_lineage_events",
        ):
            shard_ids.update(await _distinct_column_values_if_exists(conn, table_name, "shard_id"))
        shards = len(shard_ids)

        proofs = 0
        for table_name, column_name in (
            ("doc_commits", "zk_proof"),
            ("dataset_artifacts", "zk_proof"),
            ("credential_ledger_events", "inclusion_proof"),
        ):
            proofs += await _count_non_empty_column_if_exists(conn, table_name, column_name)

    uptime_seconds = int(now - _STARTED_AT)

    stats = PublicStats(
        nodes=nodes,
        shards=shards,
        proofs=proofs,
        sbts_issued=sbts_issued,
        uptime=_format_uptime(uptime_seconds),
        uptime_seconds=uptime_seconds,
        copies=nodes,
    )
    _stats_cache["latest"] = (now, stats)
    return stats
