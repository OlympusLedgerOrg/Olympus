"""
Lazy-initializing StorageLayer for protocol-layer endpoints.

Provides _get_storage() and _require_storage() for endpoints that need
the PostgreSQL-backed StorageLayer. Returns HTTP 503 if the database
is not available.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from fastapi import HTTPException


if TYPE_CHECKING:
    from collections.abc import Generator

    import nacl.signing

    from protocol.ssmf import ExistenceProof
    from storage.postgres import StorageLayer

logger = logging.getLogger(__name__)

_storage: StorageLayer | None = None
_db_error: str | None = None
_VERIFYING_SSLMODES = {"verify-full", "verify-ca"}


def _extract_sslmode(database_url: str) -> str:
    """Extract sslmode from URL or libpq keyword=value DSN strings.

    Handles all postgres URL schemes (postgres://, postgresql://,
    postgresql+asyncpg://, postgresql+psycopg://, etc.) and libpq
    keyword=value DSN strings.
    """
    trimmed = database_url.strip()
    scheme_sep = trimmed.find("://")
    if scheme_sep != -1 and trimmed[:scheme_sep].lower().startswith("postgres"):
        parsed = urlparse(trimmed)
        return parse_qs(parsed.query).get("sslmode", [""])[0].strip().lower()
    for field in trimmed.split():
        key, _, value = field.partition("=")
        if key.lower() == "sslmode":
            return value.strip("'\"").strip().lower()
    return ""


@functools.lru_cache(maxsize=1)
def _log_non_verifying_tls_dev_warning_once() -> None:
    """Log a development-only TLS warning once per process."""
    logger.warning(
        "Non-verifying Postgres sslmode is allowed only in development. "
        "Use sslmode=verify-full in production."
    )


def _enforce_postgres_tls_mode(database_url: str) -> None:
    """Require certificate-verifying Postgres TLS outside development."""
    env = os.environ.get("OLYMPUS_ENV", "production")
    sslmode = _extract_sslmode(database_url)

    if env == "development":
        if sslmode not in _VERIFYING_SSLMODES:
            _log_non_verifying_tls_dev_warning_once()
        return

    if sslmode in _VERIFYING_SSLMODES:
        return

    raise SystemExit(
        "Refusing startup: DATABASE_URL must set sslmode=verify-full or sslmode=verify-ca "
        "when OLYMPUS_ENV != 'development'."
    )


def _get_storage() -> StorageLayer:
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
    global _storage

    if _storage is not None:
        return _storage

    # Try to initialize the storage layer
    try:
        # Get database connection string from environment
        DATABASE_URL = os.environ.get("DATABASE_URL")
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is required.")
        _enforce_postgres_tls_mode(DATABASE_URL)

        from storage.postgres import StorageLayer

        parsed_url = urlparse(DATABASE_URL)
        if parsed_url.scheme in {"postgres", "postgresql", "postgresql+asyncpg"}:
            if not parsed_url.username:
                raise RuntimeError("DATABASE_URL missing username/password")
            logger.info(
                f"Connecting to database: scheme={parsed_url.scheme}, "
                f"user={parsed_url.username}, "
                f"host={parsed_url.hostname or 'unknown'}, "
                f"db={parsed_url.path.lstrip('/') if parsed_url.path else 'unknown'}"
            )
        else:
            # Defensive fallback for libpq keyword=value DSNs (e.g.
            # "host=... dbname=... user=... sslmode=verify-full"), where
            # urlparse() will not expose postgres URL components.
            logger.info("Connecting to database via DSN form (scheme not embedded).")

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
        logger.error("Database initialization failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Database temporarily unavailable. Please try again later.",
        ) from e


def _require_storage() -> StorageLayer:
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


# Error message fragments emitted by StorageLayer._acquire_connection_with_retry.
# Defined as module-level constants so that _is_db_unavailable_error stays in
# sync if the underlying messages ever change.
_RETRIES_EXHAUSTED_MSG = "failed to acquire postgresql connection"
_CIRCUIT_BREAKER_MSG = "circuit breaker"


def _is_db_unavailable_error(exc: BaseException) -> bool:
    """Return True when *exc* indicates a PostgreSQL connection or availability failure.

    Used by endpoint handlers to distinguish transient DB-down conditions
    (which should surface as HTTP 503) from genuine application bugs (HTTP 500).

    Args:
        exc: The exception to inspect.

    Returns:
        True if the exception is a DB connectivity failure, False otherwise.
    """
    try:
        from psycopg import OperationalError
        from psycopg_pool import PoolTimeout

        if isinstance(exc, (OperationalError, PoolTimeout)):
            return True
    except ImportError:
        return False

    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        return _RETRIES_EXHAUSTED_MSG in msg or _CIRCUIT_BREAKER_MSG in msg

    return False


@contextmanager
def db_op(description: str) -> Generator[None, None, None]:
    """Context manager that converts DB-connection errors to HTTP 503.

    Wrap storage operations inside this context manager so that a mid-operation
    connection loss (pool exhaustion, circuit breaker, psycopg OperationalError)
    is reported as HTTP 503 rather than an unhandled HTTP 500.

    ``HTTPException`` instances are always re-raised unchanged so that the 503
    raised by ``_require_storage()`` is not accidentally double-wrapped.

    Args:
        description: Short human-readable label used in the 503 detail message
            (e.g. ``"list shards"``).

    Yields:
        Nothing — the context manager only provides error translation.

    Raises:
        HTTPException: 503 when a DB connection/availability failure is detected;
            re-raised unchanged for any other ``HTTPException``.
    """
    try:
        yield
    except HTTPException:
        raise
    except Exception as exc:
        if _is_db_unavailable_error(exc):
            logger.error("Storage layer error (%s): %s", description, exc, exc_info=True)
            raise HTTPException(
                status_code=503,
                detail="Database temporarily unavailable. Please try again later.",
            ) from exc
        raise


def get_storage_status() -> tuple[str, bool]:
    """Return (db_status_string, db_check_bool) for the health endpoint."""
    db_status = (
        "connected" if _storage is not None else ("error" if _db_error else "not_initialized")
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


# ---------------------------------------------------------------------------
# Unified append adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AppendRecordResult:
    """Result from a StorageLayer.append_record operation."""

    root_hash: bytes
    ledger_entry_hash: str
    ts: str
    poseidon_root: str | None
    storage_proof: ExistenceProof | None


async def append_via_backend(
    *,
    shard_id: str,
    record_type: str,
    record_id: str,
    version: int,
    value_hash: bytes,
    signing_key: nacl.signing.SigningKey,
    canonicalization: dict[str, Any] | None = None,
    poseidon_root: bytes | None = None,
    parser_id: str = "fallback@1.0.0",
    canonical_parser_version: str = "v1",
) -> AppendRecordResult:
    """Append a record via the StorageLayer (direct PostgreSQL path)."""
    storage = _get_storage()

    def _do_append() -> tuple[bytes, ExistenceProof, dict[str, Any], str, Any]:
        return storage.append_record(
            shard_id=shard_id,
            record_type=record_type,
            record_id=record_id,
            version=version,
            value_hash=value_hash,
            signing_key=signing_key,
            canonicalization=canonicalization,
            poseidon_root=poseidon_root,
            parser_id=parser_id,
            canonical_parser_version=canonical_parser_version,
        )

    root_hash, proof, _header, _signature, ledger_entry = await asyncio.to_thread(_do_append)

    return AppendRecordResult(
        root_hash=root_hash,
        ledger_entry_hash=ledger_entry.entry_hash,
        ts=ledger_entry.ts,
        poseidon_root=ledger_entry.poseidon_root,
        storage_proof=proof,
    )
