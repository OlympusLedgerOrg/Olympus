"""
Lazy-initializing StorageLayer for protocol-layer endpoints.

Provides _get_storage() and _require_storage() for endpoints that need
the PostgreSQL-backed StorageLayer. Returns HTTP 503 if the database
is not available.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi import HTTPException

if TYPE_CHECKING:
    from storage.postgres import StorageLayer

logger = logging.getLogger(__name__)

_storage: "StorageLayer | None" = None
_db_error: str | None = None


def _get_storage() -> "StorageLayer":
    """
    Get the storage layer, initializing lazily on first use.

    Each call retries initialization if a previous attempt failed, so that
    transient failures (e.g. Postgres not yet ready) do not permanently
    block the application.

    Returns:
        StorageLayer instance

    Raises:
        HTTPException: 503 if database is not available
    """
    global _storage, _db_error

    if _storage is not None:
        return _storage

    # Reset previous error so we retry the connection
    _db_error = None

    # Try to initialize the storage layer
    try:
        from storage.postgres import StorageLayer

        # Get database connection string from environment
        DATABASE_URL = os.environ.get("DATABASE_URL")
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is required.")

        # Validate DATABASE_URL format
        parsed_url = urlparse(DATABASE_URL)
        if not parsed_url.username:
            raise RuntimeError(f"DATABASE_URL missing username/password: {DATABASE_URL}")

        logger.info(
            f"Connecting to database: scheme={parsed_url.scheme}, "
            f"user={parsed_url.username}, "
            f"host={parsed_url.hostname or 'unknown'}, "
            f"db={parsed_url.path.lstrip('/') if parsed_url.path else 'unknown'}"
        )

        psycopg_database_url = (
            "postgresql://" + DATABASE_URL[len("postgresql+asyncpg://") :]
            if DATABASE_URL.startswith("postgresql+asyncpg://")
            else DATABASE_URL
        )
        storage = StorageLayer(psycopg_database_url)
        storage.init_schema()
        logger.info("Database schema initialized successfully")

        # Quick connectivity check (uses the pool, not a raw connection)
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
            if result is not None:
                logger.info("Database connectivity verified: SELECT 1 succeeded")
            else:
                raise RuntimeError(
                    f"Database connectivity check failed: unexpected result {result}"
                )

        _storage = storage

        # Inject storage into STH router (lazy import to avoid circular imports)
        from api.sth import set_storage as set_sth_storage

        set_sth_storage(storage)

        return _storage

    except Exception as e:
        _db_error = str(e)
        logger.warning(f"Database initialization deferred: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Database not available: {_db_error}",
        ) from e


def _require_storage() -> "StorageLayer":
    """
    Get storage layer, raising 503 if not available.

    This wrapper provides a clear semantic interface for endpoints that require
    the database. It may be extended in the future for additional checks.
    """
    storage = _get_storage()
    if storage is None:
        raise HTTPException(
            status_code=503,
            detail="Database not available: storage not initialized",
        )
    return storage


def get_storage_status() -> tuple[str, bool]:
    """Return (db_status_string, db_check_bool) for the health endpoint."""
    global _storage, _db_error

    db_status = (
        "connected" if _storage is not None
        else ("error" if _db_error else "not_initialized")
    )

    db_check = False
    if _storage is not None:
        try:
            with _storage._get_connection() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
                result = cur.fetchone()
                db_check = result is not None
        except Exception:
            db_check = False
            db_status = "degraded"

    return db_status, db_check
