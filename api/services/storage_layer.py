"""
Lazy-initializing StorageLayer for protocol-layer endpoints.

Provides _get_storage() and _require_storage() for endpoints that need
the PostgreSQL-backed StorageLayer. Returns HTTP 503 if the database
is not available.

Also provides feature-flag routing for the Go sequencer write path via
_get_write_backend() and get_sequencer_status().

Environment Variables:
    OLYMPUS_USE_GO_SEQUENCER: When "true", route writes through Go sequencer.
        Defaults to "false" (direct PostgreSQL writes via storage/postgres.py).
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from fastapi import HTTPException

from protocol.log_sanitization import sanitize_for_log


if TYPE_CHECKING:
    from collections.abc import Generator

    import nacl.signing

    from api.services.sequencer_client import (
        GoSequencerClient,
        SequencerInclusionProof,
    )
    from protocol.ssmf import ExistenceProof
    from storage.postgres import StorageLayer

    # Type alias for write backend -- used by _get_write_backend() return type
    # annotation and for type hints in calling code that needs to handle both
    # the StorageLayer (direct PostgreSQL) and GoSequencerClient (via Go sequencer).
    WriteBackend = StorageLayer | GoSequencerClient

logger = logging.getLogger(__name__)

_storage: StorageLayer | None = None
_db_error: str | None = None


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
            raise RuntimeError("DATABASE_URL missing username/password")

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
    global _storage, _db_error

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
# Go Sequencer Feature Flag Routing
# ---------------------------------------------------------------------------


def _use_go_sequencer() -> bool:
    """Return True when the Go sequencer write path is enabled.

    Controlled by OLYMPUS_USE_GO_SEQUENCER environment variable.
    Default is False (direct PostgreSQL writes via storage/postgres.py).

    EXPERIMENTAL: When enabled, logs a one-time CRITICAL warning at startup.
    The warning is emitted at most once per process (function-attribute gate).
    """
    enabled = os.environ.get("OLYMPUS_USE_GO_SEQUENCER", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if enabled and not getattr(_use_go_sequencer, "_warned", False):
        setattr(_use_go_sequencer, "_warned", True)
        logger.critical(
            "Go sequencer path (Path B) is EXPERIMENTAL. "
            "Known limitations tracked in ARCHITECTURE.md. "
            "For production journalist workloads use OLYMPUS_USE_GO_SEQUENCER=false."
        )
    return enabled


def _get_sequencer_client() -> GoSequencerClient:
    """Get the Go sequencer client singleton.

    Raises:
        HTTPException: 503 if the sequencer client cannot be initialized.
    """
    try:
        from api.services.sequencer_client import get_sequencer_client

        return get_sequencer_client()
    except Exception as e:
        logger.error("Failed to initialize sequencer client: %s", e, exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Sequencer client initialization failed.",
        ) from e


def _get_write_backend() -> WriteBackend:
    """Get the appropriate write backend based on feature flags.

    When OLYMPUS_USE_GO_SEQUENCER=true, returns the GoSequencerClient.
    Otherwise, returns the StorageLayer for direct PostgreSQL writes.

    Returns:
        Either a GoSequencerClient or StorageLayer instance.

    Raises:
        HTTPException: 503 if the selected backend is unavailable.
    """
    if _use_go_sequencer():
        return _get_sequencer_client()
    return _get_storage()


async def get_sequencer_status() -> tuple[str, bool]:
    """Return (sequencer_status_string, is_healthy) for the health endpoint.

    Returns:
        Tuple of (status, healthy) where status is one of:
        - "ok": Sequencer is reachable and responding
        - "degraded": Sequencer returned an error
        - "unavailable": Sequencer is unreachable
        - "disabled": Go sequencer routing is disabled (OLYMPUS_USE_GO_SEQUENCER=false)
    """
    if not _use_go_sequencer():
        return ("disabled", True)

    try:
        from api.services.sequencer_client import get_sequencer_health_status

        return await get_sequencer_health_status()
    except Exception as e:
        logger.error("Sequencer health check failed: %s", e)
        return ("unavailable", False)


# ---------------------------------------------------------------------------
# Unified append adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AppendRecordResult:
    """Normalized result from an append-record operation across both backends.

    The fields cover what the Python ingest path needs in order to populate
    `_ingestion_store` and `ArtifactCommitResponse` regardless of whether the
    write went through `StorageLayer.append_record` or the Go sequencer's
    `/v1/queue-leaf` endpoint.

    Attributes:
        root_hash: 32-byte SMT root after the append.
        ledger_entry_hash: Hex string identifying the ledger commitment. For
            the StorageLayer backend this is `LedgerEntry.entry_hash`; for the
            sequencer backend it is the sequencer-returned `leaf_value_hash`,
            which is the per-leaf commitment the Go log signs.
        ts: ISO-8601 timestamp of the commitment.
        poseidon_root: Decimal Poseidon root, when available. The Go sequencer
            does not currently compute Poseidon roots, so this is `None` on
            the sequencer path.
        storage_proof: The raw `ExistenceProof` returned by the storage layer
            (or `None` when using the sequencer backend).
        sequencer_proof: The raw `SequencerInclusionProof` returned by the
            sequencer (or `None` when using the storage backend).
        backend: Either `"storage"` or `"sequencer"`.
        persisted: True when the record was written through the durable
            PostgreSQL-backed storage layer; False when it went through the
            Go sequencer (whose own persistence is opaque to Python).
    """

    root_hash: bytes
    ledger_entry_hash: str
    ts: str
    poseidon_root: str | None
    storage_proof: ExistenceProof | None
    sequencer_proof: SequencerInclusionProof | None
    backend: str
    persisted: bool


async def append_via_backend(
    *,
    shard_id: str,
    record_type: str,
    record_id: str,
    version: int,
    value_hash: bytes,
    signing_key: nacl.signing.SigningKey | None = None,
    canonicalization: dict[str, Any] | None = None,
    poseidon_root: bytes | None = None,
    parser_id: str = "fallback@1.0.0",
    canonical_parser_version: str = "v1",
    want_proof: bool = True,
    backend: WriteBackend | None = None,
) -> AppendRecordResult:
    """Append a record via the configured write backend.

    Routes to either `StorageLayer.append_record` (default) or the Go
    sequencer's HTTP API (when `OLYMPUS_USE_GO_SEQUENCER` is enabled). The
    return value is normalized so that route handlers do not need to branch
    on which backend produced the result.

    Sequencer error mapping:
        - `SequencerUnavailableError` → `HTTPException(503)`
        - `SequencerResponseError`    → `HTTPException(502)`

    Args:
        shard_id: Logical shard identifier (e.g. `"watauga:2025:budget"`).
        record_type: Record type string (e.g. `"artifact"`, `"document"`).
        record_id: Caller-supplied record identifier within the shard.
        version: Integer record version (mapped to a string on the sequencer).
        value_hash: 32-byte canonical value hash. The sequencer treats this as
            the leaf content; the storage layer treats it as the leaf value.
        signing_key: Ed25519 signing key used by the storage layer to sign
            shard headers. Ignored on the sequencer path (the Go service signs
            with its own key). Required for the storage path.
        canonicalization: Canonicalization provenance dict for the storage
            layer. Ignored on the sequencer path (canonicalization happens in
            Rust before the leaf is committed).
        poseidon_root: Optional pre-computed Poseidon root or compute sentinel
            for the storage layer. Ignored on the sequencer path.
        parser_id: ADR-0003 parser identifier bound into the leaf hash domain.
        canonical_parser_version: ADR-0003 canonical parser version bound into
            the leaf hash domain.
        want_proof: When True, fetch an inclusion proof on the sequencer path.
            Inclusion proofs are always returned by the storage layer.
        backend: Optional pre-resolved write backend. When supplied, the
            adapter does **not** call `_get_write_backend()`; callers that
            already hold a `StorageLayer` (or that need to inject a stub for
            tests) can pass it directly. This is also how callers can force
            the storage path while leaving the global feature flag alone.

            Sequencer dispatch uses `isinstance(backend, GoSequencerClient)`,
            so any sequencer test stub passed via this argument must be a
            real `GoSequencerClient` instance or subclass — duck-typed stubs
            will fall through to the StorageLayer path.

    Returns:
        An `AppendRecordResult` with backend-agnostic fields.

    Raises:
        HTTPException: 503/502 on sequencer transport / response errors;
            propagates whatever the storage layer raises (typically
            `ValueError` for dedup conflicts) on the storage path.
    """
    if backend is None:
        backend = _get_write_backend()

    # Lazy import to keep the storage_layer module free of unconditional
    # dependencies on httpx and the sequencer client at import time.
    from api.services.sequencer_client import (
        GoSequencerClient,
        SequencerResponseError,
        SequencerUnavailableError,
    )

    if isinstance(backend, GoSequencerClient):
        # Sequencer path: hand the pre-computed value_hash to Go via the
        # /v1/queue-leaf-hash endpoint, which bypasses Rust canonicalization.
        # Previously this called /v1/queue-leaf with content_type=
        # "application/octet-stream", which the Rust canonicalizer rejects
        # (H-3). The hash-specific endpoint is the correct path when the
        # Python layer already holds a canonical content hash.
        version_str = str(version) if version is not None else ""
        try:
            append_result = await backend.append_record_hash(
                shard_id=shard_id,
                record_type=record_type,
                record_id=record_id,
                value_hash=value_hash,
                parser_id=parser_id,
                canonical_parser_version=canonical_parser_version,
                version=version_str,
            )
        except SequencerUnavailableError as exc:
            logger.error(
                "sequencer_append_unavailable shard=%s record=%s",
                sanitize_for_log(shard_id),
                sanitize_for_log(record_id),
            )
            raise HTTPException(
                status_code=503,
                detail="Sequencer unavailable.",
            ) from exc
        except SequencerResponseError as exc:
            logger.error(
                "sequencer_append_error shard=%s record=%s status=%d",
                sanitize_for_log(shard_id),
                sanitize_for_log(record_id),
                exc.status_code,
            )
            raise HTTPException(
                status_code=502,
                detail="Sequencer returned an error.",
            ) from exc

        sequencer_proof: SequencerInclusionProof | None = None
        if want_proof:
            try:
                sequencer_proof = await backend.get_inclusion_proof(
                    shard_id=shard_id,
                    record_type=record_type,
                    record_id=record_id,
                    root=bytes.fromhex(append_result.new_root),
                    version=version_str,
                )
            except SequencerUnavailableError as exc:
                logger.error(
                    "sequencer_proof_unavailable shard=%s record=%s",
                    sanitize_for_log(shard_id),
                    sanitize_for_log(record_id),
                )
                raise HTTPException(
                    status_code=503,
                    detail="Sequencer unavailable.",
                ) from exc
            except SequencerResponseError as exc:
                logger.error(
                    "sequencer_proof_error shard=%s record=%s status=%d",
                    sanitize_for_log(shard_id),
                    sanitize_for_log(record_id),
                    exc.status_code,
                )
                raise HTTPException(
                    status_code=502,
                    detail="Sequencer returned an error.",
                ) from exc

        # Lazy import to avoid pulling protocol.timestamps into module load.
        from protocol.timestamps import current_timestamp

        return AppendRecordResult(
            root_hash=bytes.fromhex(append_result.new_root),
            # The Go sequencer is the system of record for this leaf; use the
            # sequencer-returned leaf_value_hash as a stable per-leaf
            # commitment identifier. There is no Python-shaped LedgerEntry
            # on this path.
            ledger_entry_hash=append_result.leaf_value_hash,
            ts=current_timestamp(),
            poseidon_root=None,
            storage_proof=None,
            sequencer_proof=sequencer_proof,
            backend="sequencer",
            persisted=False,
        )

    # StorageLayer path: the underlying call is sync, so dispatch it to a
    # worker thread to avoid blocking the event loop.
    if signing_key is None:
        raise HTTPException(
            status_code=500,
            detail="signing_key is required for the StorageLayer write path.",
        )

    storage = backend

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
        sequencer_proof=None,
        backend="storage",
        persisted=True,
    )
