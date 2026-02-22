"""
Public audit API for Olympus Phase 0.5

PRODUCTION API (PostgreSQL RECOMMENDED)
========================================

This is the PRODUCTION FastAPI application for Olympus.
It uses PostgreSQL 16+ for full ACID transaction guarantees.

DATABASE: PostgreSQL 16+ (via storage.postgres.StorageLayer)
PERSISTENCE: Full transactional persistence across four tables
CONCURRENCY: Safe for concurrent access
PRODUCTION USE: ✅ YES - This is the production API

Environment Variables:
- DATABASE_URL: PostgreSQL connection string (required for DB endpoints)

LAZY INITIALIZATION:
- The app can start without a PostgreSQL connection
- DB-dependent endpoints return HTTP 503 if the database is not available
- Non-DB endpoints (/, /health) always work

For testing proof logic without PostgreSQL, use app_testonly/main.py (test-only).

See docs/08_database_strategy.md for complete database strategy documentation.

This module provides read-only HTTP endpoints for third-party auditors
to verify records, proofs, signatures, and ledger integrity.

All responses include everything required for offline verification.
"""

import logging
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from api.ingest import router as ingest_router
from protocol.canonical_json import canonical_json_encode


# Type for lazy-loaded storage layer
# Import StorageLayer at type-checking time only to avoid circular imports
if TYPE_CHECKING:
    from storage.postgres import StorageLayer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lazy storage layer management
_storage: "StorageLayer | None" = None
_db_error: str | None = None  # Error message if DB init failed


def _get_storage() -> "StorageLayer":
    """
    Get the storage layer, initializing lazily on first use.

    Returns:
        StorageLayer instance

    Raises:
        HTTPException: 503 if database is not available
    """
    global _storage, _db_error

    if _storage is not None:
        return _storage

    if _db_error is not None:
        raise HTTPException(
            status_code=503,
            detail=f"Database not available: {_db_error}",
        )

    # Try to initialize the storage layer
    try:
        from psycopg import connect

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

        storage = StorageLayer(DATABASE_URL)
        storage.init_schema()
        logger.info("Database schema initialized successfully")

        # Quick connectivity check
        with connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
            if result and result[0] == 1:
                logger.info("Database connectivity verified: SELECT 1 succeeded")
            else:
                raise RuntimeError(
                    f"Database connectivity check failed: unexpected result {result}"
                )

        _storage = storage
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


# API models for responses
class ShardInfo(BaseModel):
    """Information about a shard."""

    shard_id: str
    latest_seq: int
    latest_root: str  # Hex-encoded


class ShardHeaderResponse(BaseModel):
    """Shard header with signature for verification."""

    shard_id: str
    seq: int
    root_hash: str  # Hex-encoded 32-byte root
    header_hash: str  # Hex-encoded 32-byte header hash
    previous_header_hash: str  # Hex-encoded (empty for genesis)
    timestamp: str  # ISO 8601
    signature: str  # Hex-encoded 64-byte Ed25519 signature
    pubkey: str  # Hex-encoded 32-byte Ed25519 public key
    canonical_header_json: str  # For offline verification


class ExistenceProofResponse(BaseModel):
    """Existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str  # Hex-encoded 32-byte key
    value_hash: str  # Hex-encoded 32-byte value hash
    siblings: list[str]  # 256 hex-encoded 32-byte sibling hashes
    root_hash: str  # Hex-encoded 32-byte root
    shard_header: ShardHeaderResponse  # Latest header for this shard


class NonExistenceProofResponse(BaseModel):
    """Non-existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str  # Hex-encoded 32-byte key
    siblings: list[str]  # 256 hex-encoded 32-byte sibling hashes
    root_hash: str  # Hex-encoded 32-byte root
    shard_header: ShardHeaderResponse  # Latest header for this shard


class LedgerEntryResponse(BaseModel):
    """Ledger entry for chain verification."""

    ts: str  # ISO 8601 timestamp
    record_hash: str  # Hex-encoded
    shard_id: str
    shard_root: str  # Hex-encoded
    canonicalization: dict[str, Any]
    prev_entry_hash: str  # Hex-encoded (empty for genesis)
    entry_hash: str  # Hex-encoded


class LedgerTailResponse(BaseModel):
    """Last N ledger entries for a shard."""

    shard_id: str
    entries: list[LedgerEntryResponse]


class TimestampTokenResponse(BaseModel):
    """RFC 3161 timestamp token for a shard header."""

    tsa_url: str  # URL of the issuing Timestamp Authority
    tst_hex: str  # DER-encoded TimeStampToken, hex-encoded
    hash_hex: str  # Hex-encoded BLAKE3 hash that was submitted to the TSA
    timestamp: str  # ISO 8601 timestamp from the TSA response
    tsa_cert_fingerprint: str | None  # SHA-256 fingerprint of TSA cert


class HeaderVerificationResponse(BaseModel):
    """Combined Ed25519 signature and RFC 3161 timestamp verification result."""

    shard_id: str
    header_hash: str  # Hex-encoded 32-byte header hash
    signature_valid: bool
    timestamp_token: TimestampTokenResponse | None  # None if not yet timestamped
    timestamp_valid: bool | None  # None if no token available


# Initialize FastAPI app
app = FastAPI(
    title="Olympus Public Audit API",
    description="API for verifying and ingesting Olympus ledger records, proofs, and signatures",
    version="0.5.0",
)

# Register write/ingest endpoints
app.include_router(ingest_router)


@app.get("/")
async def root() -> dict[str, Any]:
    """API root with basic info."""
    return {
        "name": "Olympus Public Audit API",
        "version": "0.5.0",
        "description": "API for verifying and ingesting Olympus protocol records",
        "endpoints": [
            "/shards",
            "/shards/{shard_id}/header/latest",
            "/shards/{shard_id}/header/latest/verify",
            "/shards/{shard_id}/proof",
            "/ledger/{shard_id}/tail",
            "/ingest/records",
            "/ingest/records/{proof_id}/proof",
            "/health",
        ],
    }


@app.get("/shards", response_model=list[ShardInfo])
async def list_shards() -> list[ShardInfo]:
    """
    List all shards with their latest state.

    Returns:
        List of shard information
    """
    storage = _require_storage()
    try:
        shard_ids = storage.get_all_shard_ids()
        result = []

        for shard_id in shard_ids:
            header_data = storage.get_latest_header(shard_id)
            if header_data:
                result.append(
                    ShardInfo(
                        shard_id=shard_id,
                        latest_seq=header_data["seq"],
                        latest_root=header_data["header"]["root_hash"],
                    )
                )

        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list shards: {str(e)}") from e


@app.get("/shards/{shard_id}/header/latest", response_model=ShardHeaderResponse)
async def get_latest_header(shard_id: str) -> ShardHeaderResponse:
    """
    Get the latest shard header with signature.

    Includes everything needed for offline Ed25519 signature verification.

    Args:
        shard_id: Shard identifier

    Returns:
        Latest shard header with signature and canonical JSON
    """
    storage = _require_storage()
    try:
        header_data = storage.get_latest_header(shard_id)

        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        header = header_data["header"]

        # Create canonical header JSON for verification
        canonical_header = {
            "shard_id": header["shard_id"],
            "root_hash": header["root_hash"],
            "timestamp": header["timestamp"],
            "previous_header_hash": header["previous_header_hash"],
        }
        canonical_json = canonical_json_encode(canonical_header)

        return ShardHeaderResponse(
            shard_id=header["shard_id"],
            seq=header_data["seq"],
            root_hash=header["root_hash"],
            header_hash=header["header_hash"],
            previous_header_hash=header["previous_header_hash"],
            timestamp=header["timestamp"],
            signature=header_data["signature"],
            pubkey=header_data["pubkey"],
            canonical_header_json=canonical_json,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get header: {str(e)}") from e


@app.get("/shards/{shard_id}/proof")
async def get_proof(
    shard_id: str,
    record_type: str = Query(..., description="Type of record (e.g., 'document')"),
    record_id: str = Query(..., description="Record identifier"),
    version: int = Query(..., description="Record version", ge=1),
) -> ExistenceProofResponse | NonExistenceProofResponse:
    """
    Get existence or non-existence proof for a record.

    Includes full 256-entry Merkle sibling path for offline verification.

    Args:
        shard_id: Shard identifier
        record_type: Type of record
        record_id: Record identifier
        version: Record version (must be >= 1)

    Returns:
        Existence proof if record exists, non-existence proof otherwise
    """
    storage = _require_storage()
    try:
        # Try to get existence proof
        proof = storage.get_proof(shard_id, record_type, record_id, version)

        # Get latest header
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        # Build header response
        header = header_data["header"]
        canonical_header = {
            "shard_id": header["shard_id"],
            "root_hash": header["root_hash"],
            "timestamp": header["timestamp"],
            "previous_header_hash": header["previous_header_hash"],
        }
        canonical_json = canonical_json_encode(canonical_header)

        shard_header = ShardHeaderResponse(
            shard_id=header["shard_id"],
            seq=header_data["seq"],
            root_hash=header["root_hash"],
            header_hash=header["header_hash"],
            previous_header_hash=header["previous_header_hash"],
            timestamp=header["timestamp"],
            signature=header_data["signature"],
            pubkey=header_data["pubkey"],
            canonical_header_json=canonical_json,
        )

        if proof is not None:
            # Record exists - return existence proof
            return ExistenceProofResponse(
                shard_id=shard_id,
                record_type=record_type,
                record_id=record_id,
                version=version,
                key=proof.key.hex(),
                value_hash=proof.value_hash.hex(),
                siblings=[s.hex() for s in proof.siblings],
                root_hash=proof.root_hash.hex(),
                shard_header=shard_header,
            )
        else:
            # Record doesn't exist - return non-existence proof
            non_proof = storage.get_nonexistence_proof(shard_id, record_type, record_id, version)
            return NonExistenceProofResponse(
                shard_id=shard_id,
                record_type=record_type,
                record_id=record_id,
                version=version,
                key=non_proof.key.hex(),
                siblings=[s.hex() for s in non_proof.siblings],
                root_hash=non_proof.root_hash.hex(),
                shard_header=shard_header,
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get proof: {str(e)}") from e


@app.get("/ledger/{shard_id}/tail", response_model=LedgerTailResponse)
async def get_ledger_tail(
    shard_id: str, n: int = Query(10, description="Number of entries to retrieve", ge=1, le=1000)
) -> LedgerTailResponse:
    """
    Get the last N ledger entries for a shard.

    Entries are returned in reverse chronological order (most recent first).
    Use this to verify the ledger chain linkage.

    Args:
        shard_id: Shard identifier
        n: Number of entries to retrieve (1-1000, default 10)

    Returns:
        List of ledger entries
    """
    storage = _require_storage()
    try:
        entries = storage.get_ledger_tail(shard_id, n)

        return LedgerTailResponse(
            shard_id=shard_id,
            entries=[
                LedgerEntryResponse(
                    ts=entry.ts,
                    record_hash=entry.record_hash,
                    shard_id=entry.shard_id,
                    shard_root=entry.shard_root,
                    canonicalization=entry.canonicalization,
                    prev_entry_hash=entry.prev_entry_hash,
                    entry_hash=entry.entry_hash,
                )
                for entry in entries
            ],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get ledger tail: {str(e)}") from e


@app.get("/shards/{shard_id}/header/latest/verify", response_model=HeaderVerificationResponse)
async def verify_latest_header(shard_id: str) -> HeaderVerificationResponse:
    """
    Verify the Ed25519 signature and RFC 3161 timestamp of the latest shard header.

    Returns both the signature validity and, if a timestamp token has been stored,
    the RFC 3161 token and whether it is cryptographically valid.

    Args:
        shard_id: Shard identifier.

    Returns:
        Verification result including signature status, timestamp token, and
        timestamp validity.
    """
    storage = _require_storage()
    try:
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        header = header_data["header"]
        header_hash = header["header_hash"]

        # Signature is already verified by get_latest_header (raises ValueError if invalid)
        signature_valid = True

        # Retrieve timestamp token if stored
        token_dict = storage.get_timestamp_token(shard_id, header_hash)
        timestamp_token: TimestampTokenResponse | None = None
        timestamp_valid: bool | None = None

        if token_dict is not None:
            timestamp_token = TimestampTokenResponse(
                tsa_url=token_dict["tsa_url"],
                tst_hex=token_dict["tst_hex"],
                hash_hex=token_dict["hash_hex"],
                timestamp=token_dict["timestamp"],
                tsa_cert_fingerprint=token_dict["tsa_cert_fingerprint"],
            )
            from protocol.rfc3161 import verify_timestamp_token

            try:
                timestamp_valid = verify_timestamp_token(
                    bytes.fromhex(token_dict["tst_hex"]),
                    token_dict["hash_hex"],
                )
            except Exception:
                timestamp_valid = False

        return HeaderVerificationResponse(
            shard_id=shard_id,
            header_hash=header_hash,
            signature_valid=signature_valid,
            timestamp_token=timestamp_token,
            timestamp_valid=timestamp_valid,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to verify header: {str(e)}") from e


# Health check endpoint
@app.get("/health")
async def health() -> dict[str, Any]:
    """
    Health check endpoint.

    Returns basic health status. DB-dependent operations may still fail
    even if this endpoint returns healthy.
    """
    global _storage, _db_error

    db_status = (
        "connected" if _storage is not None else ("error" if _db_error else "not_initialized")
    )

    # Attempt a lightweight DB connectivity check when connected
    db_check = False
    if _storage is not None:
        try:
            from psycopg import connect

            DATABASE_URL = os.environ.get("DATABASE_URL", "")
            if DATABASE_URL:
                with connect(DATABASE_URL) as conn, conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    result = cur.fetchone()
                    db_check = result is not None and result[0] == 1
        except Exception:
            db_check = False
            db_status = "degraded"

    overall = "healthy" if db_status != "error" else "degraded"

    return {
        "status": overall,
        "version": "0.5.0",
        "database": db_status,
        "db_check": db_check,
        "endpoints": [
            "/shards",
            "/shards/{shard_id}/header/latest",
            "/shards/{shard_id}/header/latest/verify",
            "/shards/{shard_id}/proof",
            "/ledger/{shard_id}/tail",
            "/ingest/records",
            "/ingest/records/{proof_id}/proof",
        ],
    }
