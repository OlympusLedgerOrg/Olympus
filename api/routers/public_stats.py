from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import column, func, inspect, select, table
from sqlalchemy.sql.elements import quoted_name

from api.db import engine


router = APIRouter(prefix="/public", tags=["public-stats"])

_STARTED_AT = time.time()
_CACHE_TTL_SECONDS = 10
_stats_cache: dict[str, tuple[float, PublicStats]] = {}


class PublicStats(BaseModel):
    copies: int
    shards: int
    proofs: int
    uptime: str
    uptime_seconds: int


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


async def _count_table_if_exists(conn: Any, table_name: str) -> int:
    if not await _table_exists(conn, table_name):
        return 0

    stmt = select(func.count()).select_from(_quoted_table(table_name))
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
        PublicStats: Counts for copies, shards, proofs, and process uptime.
    """
    now = time.time()
    cached = _stats_cache.get("latest")
    if cached is not None:
        cached_at, stats = cached
        if now - cached_at < _CACHE_TTL_SECONDS:
            return stats

    async with engine.connect() as conn:
        copies = 0
        for table_name in (
            "ledger_entries",
            "documents",
            "ingest_records",
            "records",
        ):
            copies = await _count_table_if_exists(conn, table_name)
            if copies:
                break

        shards = 0
        if await _table_exists(conn, "shard_headers"):
            shards = await _count_query(
                conn,
                select(func.count(func.distinct(column("shard_id")))).select_from(
                    _quoted_table("shard_headers")
                ),
            )

        proofs = 0
        for table_name in (
            "proof_requests",
            "proof_audit_log",
            "proof_audits",
            "verification_events",
            "ingest_proofs",
        ):
            proofs = await _count_table_if_exists(conn, table_name)
            if proofs:
                break

    uptime_seconds = int(now - _STARTED_AT)

    stats = PublicStats(
        copies=copies,
        shards=shards,
        proofs=proofs,
        uptime=_format_uptime(uptime_seconds),
        uptime_seconds=uptime_seconds,
    )
    _stats_cache["latest"] = (now, stats)
    return stats
