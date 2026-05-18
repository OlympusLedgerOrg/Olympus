"""
Schema initialisation mixin.

Internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

import logging

from psycopg.rows import dict_row

from storage._pg_utils import _NODE_REHASH_GATE
from storage.postgres_schema import schema_statements


logger = logging.getLogger(__name__)


class _SchemaMixin:
    """DDL initialisation and schema-readiness checks."""

    # 0x4F4C5953 = ASCII "OLYS" — avoids collision with other advisory lock users.
    _INIT_SCHEMA_ADVISORY_LOCK_KEY = 0x4F4C5953  # 1330661715

    def init_schema(self) -> None:
        """Initialize database schema idempotently.

        Creates all required tables, indexes, functions, and triggers using
        CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS DDL so the call is
        safe on both fresh and existing databases.  Concurrent callers are
        serialized via a PostgreSQL transaction-level advisory lock.
        """
        stmts = schema_statements(_NODE_REHASH_GATE)

        with self._get_connection() as conn:  # type: ignore[attr-defined]
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (self._INIT_SCHEMA_ADVISORY_LOCK_KEY,),
                )
                for stmt in stmts:
                    cur.execute(stmt)
            conn.commit()

    def check_ingestion_schema(self) -> None:
        """Verify ingestion tables exist before persisting ingestion batches.

        Raises:
            RuntimeError: When required ingestion tables are missing.
        """
        try:
            with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
                cur.execute("SELECT 1 FROM ingestion_batches LIMIT 1")
                cur.execute("SELECT 1 FROM api_rate_limits LIMIT 1")
        except Exception as exc:  # pragma: no cover - defensive guardrail
            logger.error("Migration not applied: required ingestion tables missing")
            raise RuntimeError("Database not migrated - run migrations first") from exc
