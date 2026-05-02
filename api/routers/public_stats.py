from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from api.db import engine


router = APIRouter(prefix="/public", tags=["public-stats"])

_STARTED_AT = time.time()


class PublicStats(BaseModel):
    copies: int
    shards: int
    proofs: int
    uptime: str
    uptime_seconds: int


async def _count_query(conn: Any, sql: str) -> int:
    result = await conn.execute(text(sql))
    value = result.scalar()
    return int(value or 0)


async def _table_exists(conn: Any, table_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = :table_name
            )
            """
        ),
        {"table_name": table_name},
    )
    return bool(result.scalar())


async def _count_table_if_exists(conn: Any, table_name: str) -> int:
    if not await _table_exists(conn, table_name):
        return 0

    result = await conn.execute(text(f'SELECT COUNT(*) FROM "{table_name}"'))
    value = result.scalar()
    return int(value or 0)


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
                'SELECT COUNT(DISTINCT shard_id) FROM "shard_headers"',
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

    uptime_seconds = int(time.time() - _STARTED_AT)

    return PublicStats(
        copies=copies,
        shards=shards,
        proofs=proofs,
        uptime=_format_uptime(uptime_seconds),
        uptime_seconds=uptime_seconds,
    )