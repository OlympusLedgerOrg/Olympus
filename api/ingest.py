"""
Write API for Olympus — batch record ingestion and proof retrieval.

This module provides FastAPI endpoints for ingesting records into Olympus,
including batch operations, content-hash deduplication, and asynchronous
proof retrieval.

Endpoints:
    POST /ingest/records         — Atomically ingest a batch of records
    GET  /ingest/records/{proof_id}/proof — Retrieve proof for an ingested record
    POST /ingest/commit          — Commit a pre-computed artifact hash to the ledger

All write operations are append-only and maintain ledger chain integrity.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from time import monotonic
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

import httpx
import nacl.signing
from fastapi import APIRouter, File, HTTPException, Path, Request, UploadFile
from pydantic import BaseModel, Field, field_validator

from api.auth import (
    RateLimit,
    RequireCommitScope,
    RequireIngestScope,
    RequireVerifyScope,
    _get_backend as _get_rate_limit_backend,
    _get_client_ip,
    _register_api_key_for_tests as _auth_register_api_key_for_tests,
    _reset_auth_state_for_tests,
    _reset_rate_limit_backend_for_tests,
    _TokenBucket as _AuthTokenBucket,
)
from api.config import get_settings
from api.services.upload_validation import validate_file_magic
from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes, leaf_hash, record_key
from protocol.ledger import Ledger
from protocol.merkle import (
    MERKLE_VERSION,
    PROOF_VERSION,
    MerkleProof,
    MerkleTree,
    deserialize_merkle_proof,
    merkle_leaf_hash,
    verify_proof,
)
from protocol.ssmf import ExistenceProof
from protocol.telemetry import INGEST_TOTAL, LEDGER_HEIGHT, timed_operation
from protocol.timestamps import current_timestamp


if TYPE_CHECKING:
    from protocol.poseidon_smt import PoseidonSMT
    from storage.postgres import StorageLayer


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

# Maximum number of bytes read per iteration when streaming an upload.
_UPLOAD_CHUNK_SIZE = 65_536


async def _read_upload_bounded(file: UploadFile, max_bytes: int, max_mb: int) -> bytes:
    """Read *file* in fixed-size chunks, aborting if the total exceeds *max_bytes*.

    Security: This function implements multiple defenses against memory exhaustion:
    1. Caller must check Content-Length header before calling this function.
       (See verify_record_upload endpoint at line ~1449 for reference implementation.)
    2. Per-chunk timeout prevents slow-loris attacks (upload_read_timeout_seconds)
    3. Size check before accumulating each chunk prevents OOM before limit check
    4. Uses list of immutable bytes chunks to avoid bytearray reallocation overhead
       and eliminates the final bytearray-to-bytes conversion step

    Args:
        file: FastAPI UploadFile to read.
        max_bytes: Hard upper bound on accepted payload size in bytes.
        max_mb: Human-readable equivalent (for error messages).

    Returns:
        The full file contents as a single :class:`bytes` object.

    Raises:
        HTTPException 413: If the payload exceeds *max_bytes* before EOF.
        HTTPException 408: If a chunk read exceeds the timeout.
    """
    settings = get_settings()
    chunks: list[bytes] = []
    total = 0
    max_chunk = min(_UPLOAD_CHUNK_SIZE, max_bytes)
    while True:
        remaining = max_bytes - total
        read_size = min(max_chunk, remaining + 1)
        try:
            chunk = await asyncio.wait_for(
                file.read(read_size),
                timeout=settings.upload_read_timeout_seconds,
            )
        except TimeoutError as exc:
            await file.close()
            raise HTTPException(
                status_code=408,
                detail="Upload read timed out.",
            ) from exc
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum size of {max_mb} MB.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


# Allowlist pattern for identifier fields. Permits alphanumeric chars plus the
# small set of punctuation needed for record/artifact IDs
# (e.g. "org/repo/v1.2.3-rc.1", "doc-001").
# Deliberately excludes control characters, null bytes, shell metacharacters
# (\ * ? < > | ; ` $ ! &), and Unicode homoglyphs (pure ASCII allowlist).
_SHARD_ID_PATTERN = r"^[a-zA-Z0-9_.:\-]+$"
_IDENTIFIER_PATTERN = r"^[a-zA-Z0-9_./:@+\-]+$"
_IDENTIFIER_MAX_LEN = 256
# Artifact IDs (e.g. 'org/repo/v1.2.3-rc.1+build.42') are typically longer than shard/record IDs.
_ARTIFACT_ID_MAX_LEN = 512

# H-3 Fix: Content validation limits (matching canonicalizer limits).
# These are enforced at Pydantic deserialization time, before the potentially
# expensive canonicalization step, to prevent DoS via deeply nested JSON.
_MAX_CONTENT_DEPTH = 128  # Maximum nesting depth for content JSON
_MAX_CONTENT_SIZE_ESTIMATE = 16 * 1024 * 1024  # 16 MiB rough size limit per record content


def _check_json_depth(obj: Any, current_depth: int = 0) -> int:
    """Check the nesting depth of a JSON-like object.

    Uses an iterative approach (explicit stack) to avoid Python recursion
    limits on adversarial input (L-4 hardening).

    Args:
        obj: The object to check.
        current_depth: Initial depth offset (normally 0).

    Returns:
        Maximum depth found in the object.

    Raises:
        ValueError: If depth exceeds _MAX_CONTENT_DEPTH.
    """
    max_depth = current_depth
    # Explicit stack of (value, depth) pairs replaces recursion
    stack: list[tuple[Any, int]] = [(obj, current_depth)]

    while stack:
        current, depth = stack.pop()

        if depth >= _MAX_CONTENT_DEPTH:
            raise ValueError(f"Content nesting depth exceeds limit of {_MAX_CONTENT_DEPTH}")

        if depth > max_depth:
            max_depth = depth

        if isinstance(current, dict):
            for value in current.values():
                stack.append((value, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))

    return max_depth


def _estimate_json_size(obj: Any) -> int:
    """Estimate the serialized size of a JSON-like object.

    This is a rough estimate based on traversing the object. It's not exact
    but is good enough to catch obvious DoS attempts before full serialization.

    Args:
        obj: The object to estimate size for.

    Returns:
        Estimated size in bytes.
    """
    if obj is None:
        return 4  # "null"
    elif isinstance(obj, bool):
        return 5  # "true" or "false"
    elif isinstance(obj, (int, float)):
        return len(str(obj))
    elif isinstance(obj, str):
        # Use UTF-8 encoding for accurate size of multi-byte characters
        return len(obj.encode("utf-8")) + 2  # quotes
    elif isinstance(obj, dict):
        # keys + values + colons + commas + braces
        size = 2  # {}
        for key, value in obj.items():
            # Keys are also UTF-8 encoded in JSON
            size += len(str(key).encode("utf-8")) + 2 + 1 + _estimate_json_size(value) + 1
        return size
    elif isinstance(obj, list):
        # items + commas + brackets
        size = 2  # []
        for item in obj:
            size += _estimate_json_size(item) + 1  # item,
        return size
    else:
        return len(str(obj))


class RecordInput(BaseModel):
    """A single record to ingest."""

    shard_id: str = Field(
        ...,
        description=(
            "Target shard identifier. "
            "Allowed characters: ASCII letters, digits, underscore, dot, colon, "
            "and hyphen (regex: ^[a-zA-Z0-9_.:\\-]+$). Max 256 characters."
        ),
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_SHARD_ID_PATTERN,
    )
    record_type: str = Field(
        ...,
        description="Record type (e.g. 'document')",
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
    )
    record_id: str = Field(
        ...,
        description="Unique record identifier",
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
    )
    version: int = Field(..., ge=1, description="Record version (≥ 1)")
    content: dict[str, Any] = Field(..., description="Record content (JSON document)")

    @field_validator("content")
    @classmethod
    def validate_content_limits(cls, v: dict[str, Any]) -> dict[str, Any]:
        """H-3 Fix: Validate content depth and size at Pydantic layer.

        This prevents DoS attacks via deeply nested or very large JSON content
        before the expensive canonicalization step runs.
        """
        # Check depth
        try:
            _check_json_depth(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        # Estimate size
        estimated_size = _estimate_json_size(v)
        if estimated_size > _MAX_CONTENT_SIZE_ESTIMATE:
            raise ValueError(
                f"Content size estimate ({estimated_size} bytes) exceeds limit "
                f"of {_MAX_CONTENT_SIZE_ESTIMATE} bytes per record"
            )

        return v


class BatchIngestionRequest(BaseModel):
    """Request body for batch record ingestion."""

    records: list[RecordInput] = Field(
        ..., min_length=1, max_length=1000, description="Records to ingest"
    )


class IngestionResult(BaseModel):
    """Result for a single ingested record."""

    proof_id: str = Field(..., description="Proof identifier for async retrieval")
    record_id: str
    shard_id: str
    content_hash: str = Field(..., description="BLAKE3 content hash (hex)")
    deduplicated: bool = Field(False, description="True if record was already present")
    idempotent: bool = Field(
        False,
        description=(
            "True when this response returns an existing record instead of "
            "creating a new one. Callers can use this to distinguish a fresh "
            "insert from a deduplicated return."
        ),
    )


class BatchIngestionResponse(BaseModel):
    """Response for a batch ingestion request."""

    ingested: int = Field(..., description="Number of records ingested")
    deduplicated: int = Field(..., description="Number of duplicates skipped")
    results: list[IngestionResult]
    ledger_entry_hash: str = Field(..., description="Hash of the ledger entry for this batch")
    timestamp: str
    canonicalization: dict[str, Any]
    batch_id: str | None = Field(None, description="Durable batch identifier")


class IngestionProofResponse(BaseModel):
    """Proof for an ingested record."""

    proof_id: str
    record_id: str
    shard_id: str
    content_hash: str
    merkle_root: str
    merkle_proof: dict[str, Any]
    ledger_entry_hash: str
    timestamp: str
    canonicalization: dict[str, Any]
    batch_id: str | None = Field(None, description="Batch identifier if available")
    poseidon_root: str | None = Field(
        None, description="Optional Poseidon root associated with the commitment"
    )


class HashVerificationResponse(IngestionProofResponse):
    """Verification result for a committed content hash."""

    merkle_proof_valid: bool


class ProofVerificationRequest(BaseModel):
    """Request body for server-side verification of a proof bundle."""

    proof_id: str | None = Field(None, description="Optional client-side proof identifier")
    content_hash: str = Field(..., description="Hex-encoded BLAKE3 hash committed by Olympus")
    merkle_root: str = Field(..., description="Hex-encoded Merkle root anchoring the content hash")
    merkle_proof: dict[str, Any] = Field(..., description="Serialized Merkle proof bundle")


class ProofVerificationResponse(BaseModel):
    """Server-side verification result for a submitted proof bundle."""

    proof_id: str | None
    content_hash: str
    merkle_root: str
    content_hash_matches_proof: bool
    merkle_proof_valid: bool
    known_to_server: bool
    poseidon_root: str | None = None


# DEPRECATED: submit_proof_bundle no longer accepts a JSON body.
# Retained for migration period. Will be removed in a future release.
class ProofSubmissionRequest(ProofVerificationRequest):
    """Proof bundle payload that can be submitted to the API for later retrieval."""

    record_id: str = Field(
        ...,
        description="Record identifier associated with the proof bundle",
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
    )
    shard_id: str = Field(
        ...,
        description=(
            "Shard identifier associated with the proof bundle. "
            "Allowed characters: ASCII letters, digits, underscore, dot, colon, "
            "and hyphen (regex: ^[a-zA-Z0-9_.:\\-]+$). Max 256 characters."
        ),
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_SHARD_ID_PATTERN,
    )
    ledger_entry_hash: str = Field(..., description="Ledger entry anchoring the proof bundle")
    timestamp: str = Field(..., description="ISO 8601 timestamp associated with the bundle")
    canonicalization: dict[str, Any] = Field(
        ..., description="Canonicalization provenance metadata"
    )
    batch_id: str | None = Field(None, description="Optional batch identifier for the proof bundle")


class ProofSubmissionResponse(IngestionProofResponse):
    """Response body for a proof bundle submitted to the ingest API."""

    submitted: bool
    deduplicated: bool


# ---------------------------------------------------------------------------
# In-memory state for ingestion tracking
# ---------------------------------------------------------------------------

# Storage layer (PostgreSQL persistence)
_storage: StorageLayer | None = None
_signing_key: nacl.signing.SigningKey | None = None

# L4-F: Test mode flag to allow in-memory storage for tests only
# Production deployments MUST set DATABASE_URL
_TEST_MODE: bool = False

# Legacy in-memory stores (kept for backward compatibility during migration)
# proof_id → ingestion metadata (LRU-bounded to prevent OOM)
_ingestion_store: OrderedDict[str, dict[str, Any]] = OrderedDict()

# content_hash → proof_id (dedup index, LRU-bounded to prevent OOM)
_content_index: OrderedDict[str, str] = OrderedDict()

# Shared ledger for write path (legacy, unused when storage is enabled)
_write_ledger = Ledger()

# API key store and loaded flag have been removed - authentication is now unified
# through api.auth module. The key store is maintained by api.auth._key_store.

# ---------------------------------------------------------------------------
# Go sequencer client configuration
# ---------------------------------------------------------------------------

# All record commits route through the Go sequencer's QueueLeaf endpoint.
# SEQUENCER_ADDR (default localhost:9090) and SEQUENCER_API_TOKEN configure
# the HTTP client.
_sequencer_addr: str = os.environ.get("SEQUENCER_ADDR", "localhost:9090")
_sequencer_token: str = os.environ.get("SEQUENCER_API_TOKEN", "")

# Module-level singleton for sequencer HTTP calls.  Lazily initialised by
# _get_sequencer_client() so that the connection pool is only created when
# the sequencer path is actually used (avoids touching the event loop at
# import time).  Call _close_sequencer_client() from the application
# shutdown hook to drain in-flight connections cleanly.
_sequencer_http_client: httpx.AsyncClient | None = None


def _get_sequencer_client() -> httpx.AsyncClient:
    """Return the module-level sequencer HTTP client, creating it on first call.

    The client is a singleton so that all requests share a single connection
    pool (max_keepalive_connections=20).  Creating a new AsyncClient per call
    would tear down the pool after every request, exhausting file descriptors
    under load.
    """
    global _sequencer_http_client
    if _sequencer_http_client is None:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        _sequencer_http_client = httpx.AsyncClient(timeout=30.0, limits=limits)
    return _sequencer_http_client


async def _close_sequencer_client() -> None:
    """Close the module-level sequencer HTTP client.

    Should be called from the application lifespan shutdown hook so that
    in-flight connections are drained before the process exits.
    """
    global _sequencer_http_client
    if _sequencer_http_client is not None:
        await _sequencer_http_client.aclose()
        _sequencer_http_client = None


logger.info("ingest_path=sequencer addr=%s", _sequencer_addr)
# Warn loudly if the auth token is missing — requests will be rejected
# by the sequencer's requireToken middleware.  The token value itself is
# intentionally never logged to avoid credential exposure.
if not _sequencer_token:
    logger.warning(
        "ingest: SEQUENCER_API_TOKEN is not set — sequencer requests will be unauthorized"
    )


def _dev_signing_key_enabled() -> bool:
    """Return True when dev-mode auto signing key generation is enabled."""
    return os.environ.get("OLYMPUS_DEV_SIGNING_KEY", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


_EPHEMERAL_KEY_WITH_DB_ERROR = (
    "OLYMPUS_DEV_SIGNING_KEY=1 is set but DATABASE_URL is also configured. "
    "Ephemeral signing keys cannot be used with a persistent database — all signed "
    "shard headers would become permanently unverifiable after restart. "
    "Either set OLYMPUS_INGEST_SIGNING_KEY to a stable key, or unset DATABASE_URL "
    "to use in-memory mode only."
)

# Hard fail when persistence is configured without a signing key
if os.environ.get("DATABASE_URL") and not os.environ.get("OLYMPUS_INGEST_SIGNING_KEY"):
    if not _dev_signing_key_enabled():
        raise RuntimeError(
            "DATABASE_URL is set but OLYMPUS_INGEST_SIGNING_KEY is missing - "
            "ingest persistence cannot start without a signing key"
        )
    raise RuntimeError(_EPHEMERAL_KEY_WITH_DB_ERROR)


def _get_storage() -> StorageLayer | None:
    """
    Get the storage layer, initializing lazily if DATABASE_URL is set.

    Returns None if DATABASE_URL is not configured (falls back to in-memory mode).
    """
    global _storage, _signing_key

    if _storage is not None:
        return _storage

    # Check if PostgreSQL is configured
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        # L4-F: In production, require DATABASE_URL; allow in-memory for tests only
        if not _TEST_MODE:
            raise RuntimeError(
                "DATABASE_URL not set - in-memory storage is not allowed. "
                "Configure DATABASE_URL for production-safe persistence."
            )
        logger.warning("DATABASE_URL not set - using in-memory storage (test mode only)")
        return None

    # Check if signing key is configured
    signing_key_hex = os.environ.get("OLYMPUS_INGEST_SIGNING_KEY")
    if not signing_key_hex:
        if not _dev_signing_key_enabled():
            logger.critical(
                "DATABASE_URL is configured but OLYMPUS_INGEST_SIGNING_KEY is missing - "
                "refusing to start"
            )
            raise RuntimeError("OLYMPUS_INGEST_SIGNING_KEY is required when DATABASE_URL is set")
        raise RuntimeError(_EPHEMERAL_KEY_WITH_DB_ERROR)

    try:
        from storage.postgres import StorageLayer

        # Initialize storage
        psycopg_database_url = (
            "postgresql://" + database_url[len("postgresql+asyncpg://") :]
            if database_url.startswith("postgresql+asyncpg://")
            else database_url
        )
        storage = StorageLayer(psycopg_database_url)
        storage.init_schema()
        storage.check_ingestion_schema()

        if signing_key_hex:
            # Initialize signing key
            signing_key_bytes = bytes.fromhex(signing_key_hex)
            if len(signing_key_bytes) != 32:
                raise ValueError("OLYMPUS_INGEST_SIGNING_KEY must be 32 bytes (64 hex chars)")
            _signing_key = nacl.signing.SigningKey(signing_key_bytes)

        logger.info("PostgreSQL storage layer initialized for ingest persistence")
        _storage = storage
        return _storage
    except Exception as e:
        logger.error(f"Failed to initialize storage layer: {e}")
        raise RuntimeError(f"Storage layer initialization failed: {e}") from e


def _cache_ingestion_record(entry: dict[str, Any]) -> None:
    """
    Cache ingestion metadata in memory for fast lookups with LRU eviction.

    Implements LRU eviction to prevent unbounded memory growth under sustained
    ingestion load. When the cache exceeds _INGESTION_CACHE_LRU_CAP entries,
    the oldest entries are evicted.
    """
    poseidon_root = entry.get("poseidon_root")
    if poseidon_root is None:
        canonicalization = entry.get("canonicalization") or {}
        poseidon_root = canonicalization.get("poseidon_root")
        if poseidon_root is not None:
            entry["poseidon_root"] = poseidon_root
    proof_id = entry["proof_id"]
    content_hash = entry["content_hash"]

    # Evict oldest entries if at capacity (applies to both stores)
    while len(_ingestion_store) >= _INGESTION_CACHE_LRU_CAP:
        oldest_proof_id, oldest_entry = _ingestion_store.popitem(last=False)
        # Also remove from content_index if it still points to this proof_id
        oldest_content_hash = oldest_entry.get("content_hash")
        if oldest_content_hash and _content_index.get(oldest_content_hash) == oldest_proof_id:
            _content_index.pop(oldest_content_hash, None)

    while len(_content_index) >= _INGESTION_CACHE_LRU_CAP:
        _content_index.popitem(last=False)

    _ingestion_store[proof_id] = entry
    _content_index[content_hash] = proof_id


def _fetch_persisted_proof(proof_id: str) -> dict[str, Any] | None:
    """Load a persisted proof mapping from storage and cache it."""
    storage = _get_storage()
    if storage is None:
        return None
    record = storage.get_ingestion_proof(proof_id)
    if record is None:
        return None
    _cache_ingestion_record(record)
    return record


def _fetch_by_content_hash(content_hash_hex: str) -> dict[str, Any] | None:
    """Lookup proof metadata by content hash from memory or storage."""
    proof_id = _content_index.get(content_hash_hex)
    if proof_id and proof_id in _ingestion_store:
        return _ingestion_store[proof_id]

    storage = _get_storage()
    if storage is None:
        return None
    record = storage.get_ingestion_proof_by_content_hash(bytes.fromhex(content_hash_hex))
    if record:
        _cache_ingestion_record(record)
    return record


# ---------------------------------------------------------------------------
# Rate-limit policy (action → capacity, refill_rate_per_second)
#
# H-3 Fix: The bucket *storage* is now delegated to the shared auth backend
# (api.auth._get_backend), eliminating the dual-system vulnerability.  Only
# the per-action policy table lives here; the actual TokenBucket instances
# are managed by the single MemoryRateLimitBackend (or future Redis backend).
# ---------------------------------------------------------------------------

_rate_limit_policy: dict[str, tuple[float, float]] = {
    "ingest": (60.0, 1.0),
    "commit": (30.0, 0.5),
    "verify": (120.0, 2.0),
}

# L5-B: Maximum number of entries in rate-limit buckets to prevent memory leaks
_RATE_LIMIT_LRU_CAP = 10_000

# Maximum number of entries in ingestion caches to prevent OOM under sustained load
_INGESTION_CACHE_LRU_CAP = 50_000


def _parse_timestamp(raw: str) -> datetime:
    """Parse ISO-8601 timestamp with optional Z suffix."""
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _append_security_audit_event(event: str, details: dict[str, Any]) -> None:
    """Append a security audit event to the append-only ledger."""
    payload = {
        "event": event,
        "timestamp": current_timestamp(),
        "details": details,
    }
    payload_hash = hash_bytes(document_to_bytes(canonicalize_document(payload))).hex()
    _write_ledger.append(
        record_hash=payload_hash,
        shard_id="audit/security",
        shard_root=payload_hash,
        canonicalization=canonicalization_provenance("application/json", CANONICAL_VERSION),
    )


def _register_api_key_for_tests(
    api_key: str, key_id: str, scopes: set[str], expires_at: str
) -> None:  # pragma: no cover - test utility
    """Register hashed API key (used by env bootstrap and tests).

    This delegates to the unified auth module's key registration to ensure
    that all authentication paths share the same key store.
    """
    _auth_register_api_key_for_tests(api_key, key_id, scopes, expires_at)
    _append_security_audit_event(
        "api_key_registered",
        {"key_id": key_id, "scopes": sorted(scopes), "expires_at": expires_at},
    )


def _reset_ingest_state_for_tests() -> None:  # pragma: no cover - test utility
    """Reset in-memory ingestion, auth, and rate-limit state and enable test mode."""
    global _write_ledger, _storage, _signing_key, _TEST_MODE
    # L4-F: Enable test mode to allow in-memory storage
    _TEST_MODE = True
    storage = _storage
    _ingestion_store.clear()
    _content_index.clear()
    # Reset the unified auth module's key store AND rate-limit backend (H-3)
    _reset_auth_state_for_tests()
    _reset_rate_limit_backend_for_tests()
    _storage = None
    _signing_key = None
    if storage is not None:
        try:
            storage.clear_rate_limits()
        except Exception:
            logger.warning("Failed to clear persisted rate limits during reset", exc_info=True)
    _write_ledger = Ledger()


def _set_rate_limit_for_tests(
    action: str, capacity: float, refill_rate_per_second: float
) -> None:  # pragma: no cover - test utility
    """Override rate-limit policy for tests."""
    _rate_limit_policy[action] = (capacity, refill_rate_per_second)
    # H-3: Reset the shared auth backend so stale buckets don't survive
    _reset_rate_limit_backend_for_tests()
    if _storage is not None:
        try:
            _storage.clear_rate_limits()
        except Exception:
            logger.warning("Failed to clear persisted rate limits during test setup", exc_info=True)


def _consume_rate_limit(subject_type: str, subject: str, action: str) -> bool:
    """Consume a token for the given subject/action.

    H-3 Fix: Delegates to the shared auth backend (api.auth._get_backend)
    so that ingest and auth rate limiting share a single bucket store,
    eliminating the dual-system vulnerability.

    Falls back to the auth backend's in-memory store if the database
    storage layer is unavailable.
    """
    capacity, refill = _rate_limit_policy[action]

    # Try database-backed rate limiting first (multi-process safe)
    storage = None
    try:
        storage = _get_storage()
    except RuntimeError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "rate_limit_storage_unavailable",
            extra={"action": action, "subject_type": subject_type, "error": str(exc)},
        )

    if storage is not None:
        try:
            return storage.consume_rate_limit(
                subject_type=subject_type,
                subject=subject,
                action=action,
                capacity=capacity,
                refill_rate_per_second=refill,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "rate_limit_storage_error",
                extra={
                    "action": action,
                    "subject_type": subject_type,
                    "subject": subject,
                    "error": str(exc),
                },
            )

    # H-3: Fall back to the *shared* auth backend instead of a separate
    # ingest-local bucket store.  Composite key ensures action/subject
    # isolation within the single backend.
    backend = _get_rate_limit_backend()
    composite_key = f"ingest:{action}:{subject_type}:{subject}"
    bucket = backend.get(composite_key)

    if bucket is None:
        bucket = _AuthTokenBucket(
            capacity=capacity,
            refill_rate=refill,
            tokens=capacity,
            last_refill=monotonic(),
        )

    allowed = bucket.consume()
    backend.set(composite_key, bucket)
    return allowed


def _apply_rate_limits(request: Request, api_key_id: str, action: str) -> None:
    """Apply rate limiting for API key and IP after authentication.

    This function is called after successful authentication to enforce
    per-key and per-IP rate limits for ingest operations.

    Args:
        request: The incoming HTTP request.
        api_key_id: The authenticated API key ID.
        action: The action being performed (e.g., 'ingest', 'commit', 'verify').

    Raises:
        HTTPException 429: If rate limit is exceeded.
    """
    client_ip = _get_client_ip(request)

    if not _consume_rate_limit("api_key", api_key_id, action):
        logger.warning(
            "rate_limit_hit",
            extra={"dimension": "api_key", "key_id": api_key_id, "action": action},
        )
        _append_security_audit_event(
            "rate_limit_hit",
            {
                "dimension": "api_key",
                "key_id": api_key_id,
                "client_ip": client_ip,
                "action": action,
            },
        )
        raise HTTPException(status_code=429, detail="Rate limit exceeded for API key")

    if not _consume_rate_limit("ip", client_ip, action):
        logger.warning(
            "rate_limit_hit",
            extra={"dimension": "ip", "client_ip": client_ip, "action": action},
        )
        _append_security_audit_event(
            "rate_limit_hit",
            {"dimension": "ip", "key_id": api_key_id, "client_ip": client_ip, "action": action},
        )
        raise HTTPException(status_code=429, detail="Rate limit exceeded for IP address")


def _parse_content_hash(content_hash: str) -> bytes:
    """Validate and decode a hex-encoded BLAKE3 content hash."""
    try:
        raw = bytes.fromhex(content_hash)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="content_hash must be valid hex") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="content_hash must be a 32-byte BLAKE3 hash")
    return raw


def _merkle_proof_from_store(data: dict[str, Any]) -> MerkleProof:
    """Convert stored ingestion proof metadata into a MerkleProof instance."""
    proof_data = data["merkle_proof"]
    return deserialize_merkle_proof(proof_data)


def _normalize_merkle_root(merkle_root: str) -> str:
    """Validate and normalize a hex-encoded Merkle root."""
    try:
        raw = bytes.fromhex(merkle_root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="merkle_root must be valid hex") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="merkle_root must be a 32-byte hash")
    return raw.hex()


def _normalize_source_url(source_url: str) -> str:
    """Validate and normalize a provenance source URL."""
    parsed = urlparse(source_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="source_url must use http or https")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="source_url must include a hostname")
    return source_url


_BN128_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _value_hash_to_poseidon_field(value_hash: bytes) -> int:
    """Convert a 32-byte value hash into a BN128 field element.

    Applies modular reduction by the BN128 scalar field prime so that
    the returned value is always a valid field element. Without this
    reduction, values derived from BLAKE3 hashes can exceed the prime
    (2^256 - 1 is ~5.3x the BN128 prime), causing incorrect Poseidon
    hash outputs and enabling hash collisions.
    """
    if len(value_hash) != 32:
        raise ValueError(f"value_hash must be 32 bytes, got {len(value_hash)}")
    return int.from_bytes(value_hash, byteorder="big") % _BN128_FIELD_PRIME


def _resolved_poseidon_root(persisted_root: str | None, fallback_root: str) -> str:
    """Resolve persisted Poseidon root with a deterministic fallback."""
    return persisted_root if persisted_root is not None else fallback_root


def _build_poseidon_smt_for_storage_shard(
    storage: StorageLayer, shard_id: str, *, up_to_ts: datetime | str | None = None
) -> PoseidonSMT:
    """Rebuild the current PoseidonSMT view for a shard from persisted SMT leaves."""
    from protocol.poseidon_smt import PoseidonSMT

    with storage._get_connection() as conn, conn.cursor() as cur:
        # O(N) leaf scan — only runs when Poseidon / ZK proofs are enabled.
        if up_to_ts is not None:
            if isinstance(up_to_ts, str):
                up_to_ts = datetime.fromisoformat(up_to_ts)
            cur.execute(
                "SELECT key, value_hash FROM smt_leaves WHERE ts <= %s ORDER BY key",
                (up_to_ts,),
            )
        else:
            cur.execute("SELECT key, value_hash FROM smt_leaves ORDER BY key")

        poseidon_smt = PoseidonSMT()
        for row in cur.fetchall():
            leaf_key = bytes(row["key"])
            value_hash = bytes(row["value_hash"])
            poseidon_smt.update(leaf_key, _value_hash_to_poseidon_field(value_hash))
    return poseidon_smt


def _get_or_build_poseidon_smt(shard_id: str) -> PoseidonSMT:
    """Get a Poseidon SMT for the given shard, using storage if available."""
    storage = _get_storage()
    if storage is not None:
        return _build_poseidon_smt_for_storage_shard(storage, shard_id)
    else:
        from protocol.poseidon_smt import PoseidonSMT

        return PoseidonSMT()


def _evaluate_proof_bundle(
    content_hash: str, merkle_root: str, merkle_proof_data: dict[str, Any]
) -> tuple[str, str, bool, bool]:
    """Validate and verify a submitted proof bundle."""
    normalized_hash = _parse_content_hash(content_hash).hex()
    normalized_root = _normalize_merkle_root(merkle_root)
    try:
        merkle_proof = deserialize_merkle_proof(merkle_proof_data)
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=400, detail="Invalid merkle_proof: malformed proof data"
        ) from None

    content_hash_bytes = bytes.fromhex(normalized_hash)
    expected_leaf_hash = merkle_leaf_hash(content_hash_bytes)
    smt_key_hex = merkle_proof_data.get("smt_key")
    if smt_key_hex is not None:
        try:
            smt_key = bytes.fromhex(str(smt_key_hex))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="smt_key must be valid hex") from exc
        if len(smt_key) != 32:
            raise HTTPException(
                status_code=400, detail="smt_key must be a 32-byte key (64 hex chars)"
            )
        expected_leaf_hash = leaf_hash(smt_key, content_hash_bytes)

    content_hash_matches_proof = merkle_proof.leaf_hash == expected_leaf_hash
    if merkle_proof.root_hash.hex() != normalized_root:
        return normalized_hash, normalized_root, content_hash_matches_proof, False

    try:
        merkle_proof_valid = content_hash_matches_proof and verify_proof(merkle_proof)
    except ValueError:
        merkle_proof_valid = False

    return normalized_hash, normalized_root, content_hash_matches_proof, merkle_proof_valid


def _smt_proof_to_merkle_proof_dict(proof: ExistenceProof, value_hash: bytes) -> dict[str, Any]:
    """
    Convert a sparse Merkle proof to the MerkleProof serialization used by the ingest API.

    Args:
        proof: SMT existence proof from storage layer
        value_hash: The value hash bound to the SMT leaf

    Returns:
        Dict with merkle_proof structure expected by ingest API
    """
    if len(value_hash) != 32:
        raise ValueError("value_hash must be 32 bytes")
    if len(proof.key) != 32:
        raise ValueError("proof.key must be 32 bytes")
    if len(proof.root_hash) != 32:
        raise ValueError("proof.root_hash must be 32 bytes")

    leaf_index = int.from_bytes(proof.key, byteorder="big", signed=False)
    siblings_with_positions: list[list[str | bool]] = []
    for level, sibling_hash in enumerate(proof.siblings):
        if len(sibling_hash) != 32:
            raise ValueError(f"sibling at level {level} must be 32 bytes")
        is_right = ((leaf_index >> level) & 1) == 0
        siblings_with_positions.append([sibling_hash.hex(), is_right])

    smt_leaf_hash = leaf_hash(proof.key, value_hash)

    return {
        "leaf_hash": smt_leaf_hash.hex(),
        "leaf_index": str(leaf_index),
        "siblings": siblings_with_positions,
        "root_hash": proof.root_hash.hex(),
        "tree_size": str(1 << 256),
        "proof_version": PROOF_VERSION,
        "tree_version": MERKLE_VERSION,
        "smt_key": proof.key.hex(),
    }


# ---------------------------------------------------------------------------
# Async helpers for CPU-bound operations
# ---------------------------------------------------------------------------


async def _async_canonicalize_and_hash(content: dict[str, Any]) -> tuple[bytes, str]:
    """
    Canonicalize document and compute hash asynchronously.

    Runs the CPU-bound canonicalization and hashing in a thread pool executor
    to avoid blocking the async event loop, which is critical when processing
    large batches of documents.

    Args:
        content: Document content to canonicalize and hash

    Returns:
        Tuple of (canonical_bytes, content_hash_hex)
    """
    loop = asyncio.get_running_loop()

    # AUDIT(doc_hash provenance): content_hash is the authoritative document
    # fingerprint for the ingest path.  It is derived exclusively from
    # canonical_v2 bytes:
    #   1. canonicalize_document() — applies NFC, homoglyph scrub, numeric
    #      normalization, sorted keys (canonical_v2 pipeline).
    #   2. document_to_bytes()     — deterministic JSON encoding (RFC 8785-
    #      style compact separators, ensure_ascii).
    #   3. hash_bytes()            — BLAKE3 with LEGACY_BYTES_PREFIX domain
    #      separation.
    # The resulting hex digest becomes the Merkle leaf in build_tree().
    canonical = await loop.run_in_executor(None, canonicalize_document, content)
    content_bytes = document_to_bytes(canonical)
    content_hash = hash_bytes(content_bytes).hex()

    return content_bytes, content_hash


async def _process_record_canonicalization(
    record: RecordInput, batch_id: str
) -> tuple[RecordInput, str, bytes, str, bytes]:
    """
    Process a single record's canonicalization asynchronously.

    Returns:
        Tuple of (record, content_hash_hex, content_hash_bytes, proof_id, canonical_content_bytes)
    """
    content_bytes, content_hash = await _async_canonicalize_and_hash(record.content)
    content_hash_bytes = bytes.fromhex(content_hash)
    proof_id = str(uuid.uuid4())
    return record, content_hash, content_hash_bytes, proof_id, content_bytes


async def _call_sequencer_queue_leaf(
    shard_id: str,
    record_type: str,
    record_id: str,
    version: str | None,
    canonical_content: bytes,
) -> dict[str, Any]:
    """Call the Go sequencer's QueueLeaf endpoint.

    Sends the canonical record to the Go sequencer over HTTP/JSON. Returns the
    parsed response dict (keys: new_root, global_key, leaf_value_hash, tree_size).

    Args:
        shard_id: Shard identifier for the record.
        record_type: Record type string.
        record_id: Record identifier.
        version: Optional version string (empty string if absent).
        canonical_content: Canonical JSON bytes for the record.

    Returns:
        Parsed QueueLeafResponse dict from the sequencer.

    Raises:
        HTTPException 503: If the sequencer is unreachable or returns a non-2xx status.
    """
    url = f"http://{_sequencer_addr}/v1/queue-leaf"
    payload = {
        "shard_id": shard_id,
        "record_type": record_type,
        "record_id": record_id,
        "version": version or "",
        "content": base64.b64encode(canonical_content).decode(),
        "content_type": "application/json",
    }
    try:
        client = _get_sequencer_client()
        resp = await client.post(
            url,
            json=payload,
            headers={"X-Sequencer-Token": _sequencer_token},
        )
    except httpx.RequestError as exc:
        logger.error("sequencer_unreachable error=%s", exc)
        raise HTTPException(status_code=503, detail="Sequencer unavailable") from exc

    if resp.status_code != 200:
        logger.error(
            "sequencer_error status=%d body=%.200s",
            resp.status_code,
            resp.text,
        )
        raise HTTPException(status_code=503, detail="Sequencer returned an error")

    return cast(dict[str, Any], resp.json())


async def _call_sequencer_queue_leaves_batch(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Call /v1/queue-leaves for an entire shard group in one HTTP roundtrip.

    Args:
        records: List of dicts with keys: shard_id, record_type, record_id,
                 version (str|None), canonical_content (bytes).

    Returns:
        List of QueueLeafResponse dicts in the same order as the input.

    Raises:
        HTTPException 503: If the sequencer is unreachable or returns non-2xx.
    """
    url = f"http://{_sequencer_addr}/v1/queue-leaves"
    payload = {
        "records": [
            {
                "shard_id": r["shard_id"],
                "record_type": r["record_type"],
                "record_id": r["record_id"],
                "version": r.get("version") or "",
                "content": base64.b64encode(r["canonical_content"]).decode(),
                "content_type": "application/json",
            }
            for r in records
        ]
    }
    try:
        client = _get_sequencer_client()
        resp = await client.post(
            url,
            json=payload,
            headers={"X-Sequencer-Token": _sequencer_token},
        )
    except httpx.RequestError as exc:
        logger.error("sequencer_unreachable error=%s", exc)
        raise HTTPException(status_code=503, detail="Sequencer unavailable") from exc

    if resp.status_code != 200:
        logger.error("sequencer_batch_error status=%d body=%.200s", resp.status_code, resp.text)
        raise HTTPException(status_code=503, detail="Sequencer returned an error")

    data = cast(dict[str, Any], resp.json())
    return cast(list[dict[str, Any]], data["results"])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/records", response_model=BatchIngestionResponse)
async def ingest_batch(
    batch: BatchIngestionRequest, request: Request, _api_key: RequireIngestScope
) -> BatchIngestionResponse:
    """
    Atomically ingest a batch of records.

    Each record is canonicalized, hashed, and checked for duplicates.
    Non-duplicate records are committed to a Merkle tree and appended
    to the ledger.  The response includes proof IDs for async proof
    retrieval.

    Supports multi-shard batches by grouping records by shard_id and
    processing each group separately. Canonicalization is parallelized
    across the batch to maximize throughput on training dataset scale.

    If PostgreSQL is configured (DATABASE_URL and OLYMPUS_INGEST_SIGNING_KEY),
    records are persisted durably. Otherwise, they are stored in-memory only.

    Args:
        batch: Batch of records to ingest.

    Returns:
        Ingestion results with proof IDs.
    """
    # Apply rate limiting after authentication
    _apply_rate_limits(request, _api_key.key_id, "ingest")

    # Validate batch is not empty
    if not batch.records:
        raise HTTPException(status_code=400, detail="Batch cannot be empty")

    # Group records by shard_id for multi-shard support
    from collections import defaultdict

    shard_groups: dict[str, list[tuple[int, RecordInput]]] = defaultdict(list)
    for original_idx, record in enumerate(batch.records):
        shard_groups[record.shard_id].append((original_idx, record))

    # Try to get storage layer (returns None if not configured)
    storage = _get_storage()
    batch_id = str(uuid.uuid4())

    # Parallelize canonicalization across all records in the batch
    # This is the key optimization for training dataset scale (thousands of documents)
    canonicalization_tasks = [
        _process_record_canonicalization(record, batch_id) for record in batch.records
    ]
    canonicalized_results = await asyncio.gather(*canonicalization_tasks)

    # Build a map from original index to canonicalized data
    record_data_map: dict[int, tuple[str, bytes, str, bytes]] = {
        i: (content_hash, content_hash_bytes, proof_id, canonical_content)
        for i, (_, content_hash, content_hash_bytes, proof_id, canonical_content) in enumerate(
            canonicalized_results
        )
    }

    # Now process each shard group
    all_results: list[tuple[int, IngestionResult]] = []
    total_dedup_count = 0
    canonicalization = canonicalization_provenance("application/json", CANONICAL_VERSION)
    ts = current_timestamp()
    final_ledger_entry_hash = ""

    for shard_id, shard_records in shard_groups.items():
        with timed_operation("commit", shard_id=shard_id) as span:
            from protocol.poseidon_smt import PoseidonSMT

            span.set_attribute("batch_size", len(shard_records))
            span.set_attribute("using_postgres", storage is not None)

            results: list[tuple[int, IngestionResult]] = []
            new_hashes: list[bytes] = []
            dedup_count = 0
            persist_queue: list[dict[str, Any]] = []
            ledger_entry_hash = ""
            # RT-H5 MITIGATION: Pre-transaction Poseidon SMT build.
            # NOTE: When storage is configured, this value is recomputed authoritatively
            # inside the SERIALIZABLE transaction (storage/postgres.py:1360-1394) to
            # prevent stale roots under concurrent writes. The pre-transaction value
            # is used only as a flag to enable Poseidon computation (poseidon_root != None).
            # The transaction-authoritative value from ledger_entry.poseidon_root is the
            # source of truth and is used in the final ingestion_entry.
            poseidon_smt = (
                _build_poseidon_smt_for_storage_shard(storage, shard_id)
                if storage is not None
                else PoseidonSMT()
            )

            # Build batch payload and call sequencer once for all records in this shard
            seq_results: list[dict[str, Any]] | None = None
            if storage is not None and _signing_key is not None:
                batch_inputs = [
                    {
                        "shard_id": record.shard_id,
                        "record_type": record.record_type,
                        "record_id": record.record_id,
                        "version": str(record.version) if record.version is not None else None,
                        "canonical_content": record_data_map[original_idx][3],
                    }
                    for original_idx, record in shard_records
                ]
                seq_results = await _call_sequencer_queue_leaves_batch(batch_inputs)

            loop_index = 0
            for original_idx, record in shard_records:
                content_hash, content_hash_bytes, proof_id, canonical_content = record_data_map[
                    original_idx
                ]
                record_smt_key = record_key(record.record_type, record.record_id, record.version)

                # In-memory-only dedup: when no storage is configured, RT-H1
                # cannot run, so check the in-memory cache here instead.
                if storage is None:
                    existing_record = _fetch_by_content_hash(content_hash)
                    if existing_record is not None:
                        results.append(
                            (
                                original_idx,
                                IngestionResult(
                                    proof_id=existing_record["proof_id"],
                                    record_id=existing_record["record_id"],
                                    shard_id=existing_record["shard_id"],
                                    content_hash=existing_record["content_hash"],
                                    deduplicated=True,
                                    idempotent=True,
                                ),
                            )
                        )
                        dedup_count += 1
                        ledger_entry_hash = existing_record.get(
                            "ledger_entry_hash", ledger_entry_hash
                        )
                        INGEST_TOTAL.labels(outcome="deduplicated").inc()
                        continue

                # If PostgreSQL is configured, persist record durably
                if storage is not None and _signing_key is not None:
                    poseidon_smt.update(
                        record_smt_key, _value_hash_to_poseidon_field(content_hash_bytes)
                    )
                    poseidon_root = str(poseidon_smt.get_root())
                    persisted_poseidon_root = poseidon_root
                    canonicalization_with_poseidon = {
                        **canonicalization,
                        "poseidon_root": persisted_poseidon_root,
                    }

                    # Use pre-fetched batch response (seq_results is guaranteed set
                    # by the batch call above when storage and signing_key are configured)
                    if seq_results is None:
                        raise RuntimeError(
                            "Sequencer batch response missing when storage is configured"
                        )
                    seq_resp = seq_results[loop_index]
                    seq_merkle_root = seq_resp["new_root"]
                    seq_global_key = seq_resp["global_key"]
                    seq_leaf_hash = seq_resp["leaf_value_hash"]
                    seq_committed_ts = current_timestamp()
                    seq_merkle_proof: dict[str, Any] = {
                        "leaf_hash": seq_leaf_hash,
                        "leaf_index": str(int(seq_global_key, 16)),
                        "siblings": [],
                        "root_hash": seq_merkle_root,
                        "tree_size": str(seq_resp["tree_size"]),
                        "proof_version": PROOF_VERSION,
                        "tree_version": MERKLE_VERSION,
                        "smt_key": seq_global_key,
                    }
                    # ledger_entry_hash is the BLAKE3 hash of the canonical record bytes,
                    # consistent with hash_bytes() applied to the same canonical content
                    # that _process_record_canonicalization already computed.
                    record_ledger_hash = hash_bytes(canonical_content).hex()
                    ingestion_entry = {
                        "proof_id": proof_id,
                        "record_id": record.record_id,
                        "shard_id": record.shard_id,
                        "record_type": record.record_type,
                        "version": record.version,
                        "content_hash": content_hash,
                        "merkle_root": seq_merkle_root,
                        "merkle_proof": seq_merkle_proof,
                        "ledger_entry_hash": record_ledger_hash,
                        "timestamp": seq_committed_ts,
                        "canonicalization": canonicalization_with_poseidon,
                        "persisted": True,
                        "batch_id": batch_id,
                        "batch_index": len(persist_queue),
                        "poseidon_root": persisted_poseidon_root,
                    }
                    _cache_ingestion_record(ingestion_entry)
                    persist_queue.append(ingestion_entry)
                    ts = seq_committed_ts
                    ledger_entry_hash = record_ledger_hash
                    logger.info("Record %s sequenced via Go sequencer", record.record_id)
                else:
                    # Fall back to in-memory storage
                    new_hashes.append(content_hash_bytes)
                    poseidon_smt.update(
                        record_smt_key, _value_hash_to_poseidon_field(content_hash_bytes)
                    )

                results.append(
                    (
                        original_idx,
                        IngestionResult(
                            proof_id=proof_id,
                            record_id=record.record_id,
                            shard_id=record.shard_id,
                            content_hash=content_hash,
                            deduplicated=False,
                            idempotent=False,
                        ),
                    )
                )

                _content_index[content_hash] = proof_id
                loop_index += 1

            # Build Merkle tree from new content hashes (in-memory path only)
            ingested_count = len(shard_records) - dedup_count
            if new_hashes and storage is None:
                # In-memory path: build batch Merkle tree and ledger
                tree = MerkleTree(new_hashes)
                merkle_root = tree.get_root().hex()
                poseidon_root = str(poseidon_smt.get_root())
                canonicalization_with_poseidon = {
                    **canonicalization,
                    "poseidon_root": poseidon_root,
                }

                # Append to ledger
                ledger_entry = _write_ledger.append(
                    record_hash=merkle_root,
                    shard_id=shard_id,
                    shard_root=merkle_root,
                    canonicalization=canonicalization_with_poseidon,
                    poseidon_root=poseidon_root,
                )
                ledger_entry_hash = ledger_entry.entry_hash
                ledger_height = len(_write_ledger.entries)
                LEDGER_HEIGHT.set(ledger_height)
                span.set_attribute("ledger_height", ledger_height)

                # Store proof metadata for each new record
                new_record_counter = 0
                for original_idx, result in results:
                    if not result.deduplicated:
                        merkle_proof = tree.generate_proof(new_record_counter)
                        _ingestion_store[result.proof_id] = {
                            "proof_id": result.proof_id,
                            "record_id": result.record_id,
                            "shard_id": result.shard_id,
                            "content_hash": result.content_hash,
                            "merkle_root": merkle_root,
                            "merkle_proof": {
                                "leaf_hash": merkle_proof.leaf_hash.hex(),
                                "leaf_index": merkle_proof.leaf_index,
                                "siblings": [
                                    [h.hex(), is_right == "right"]
                                    for h, is_right in merkle_proof.siblings
                                ],
                                "root_hash": merkle_proof.root_hash.hex(),
                                "proof_version": merkle_proof.proof_version,
                                "tree_version": merkle_proof.tree_version,
                                "epoch": merkle_proof.epoch,
                                "tree_size": merkle_proof.tree_size,
                            },
                            "ledger_entry_hash": ledger_entry_hash,
                            "timestamp": ts,
                            "canonicalization": canonicalization_with_poseidon,
                            "persisted": False,
                            "batch_id": batch_id,
                            "batch_index": new_record_counter,
                            "poseidon_root": poseidon_root,
                        }
                        _cache_ingestion_record(_ingestion_store[result.proof_id])
                        INGEST_TOTAL.labels(outcome="committed").inc()
                        new_record_counter += 1
            elif storage is not None:
                # Proof metadata is written in a single DB transaction by
                # store_ingestion_batch, so all records in the batch are
                # committed atomically at the DB level.  Sequencer HTTP calls
                # (above) happen per-record before this point; if one fails
                # with a 503 the HTTPException propagates and store_ingestion_batch
                # is never reached, keeping the DB consistent.
                if persist_queue:
                    storage.store_ingestion_batch(batch_id, persist_queue)
                # Get the latest ledger entry hash for response
                for original_idx, result in results:
                    if not result.deduplicated and result.proof_id in _ingestion_store:
                        ledger_entry_hash = _ingestion_store[result.proof_id]["ledger_entry_hash"]
                        INGEST_TOTAL.labels(outcome="committed").inc()
            else:
                ledger_entry_hash = (
                    _write_ledger.entries[-1].entry_hash if _write_ledger.entries else ""
                )

            span.set_attribute("ingested", ingested_count)
            span.set_attribute("deduplicated", dedup_count)

            all_results.extend(results)
            total_dedup_count += dedup_count
            if ledger_entry_hash:
                final_ledger_entry_hash = ledger_entry_hash

    # Sort results back to original order
    all_results.sort(key=lambda x: x[0])
    ordered_results = [result for _, result in all_results]

    total_ingested = len(batch.records) - total_dedup_count

    logger.info(
        "batch_ingested",
        extra={
            "ingested": total_ingested,
            "deduplicated": total_dedup_count,
            "total": len(batch.records),
            "shard_count": len(shard_groups),
            "using_postgres": storage is not None,
        },
    )

    return BatchIngestionResponse(
        ingested=total_ingested,
        deduplicated=total_dedup_count,
        results=ordered_results,
        ledger_entry_hash=final_ledger_entry_hash,
        timestamp=ts,
        canonicalization=canonicalization,
        batch_id=batch_id,
    )


@router.get("/records/{proof_id}/proof", response_model=IngestionProofResponse)
async def get_ingestion_proof(
    *,
    proof_id: str = Path(
        ..., pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ),
    _scope: RequireVerifyScope,
) -> IngestionProofResponse:
    """
    Retrieve the proof for a previously ingested record.

    Args:
        proof_id: Proof identifier returned by the ingestion endpoint.

    Returns:
        Full ingestion proof including Merkle proof and ledger entry hash.

    Raises:
        HTTPException: 404 if proof_id is not found.
    """
    data = _ingestion_store.get(proof_id) or _fetch_persisted_proof(proof_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Proof not found")

    return IngestionProofResponse(**data)


@router.get("/records/hash/{content_hash}/verify", response_model=HashVerificationResponse)
async def verify_ingested_content_hash(
    content_hash: str, request: Request, _api_key: RequireVerifyScope
) -> HashVerificationResponse:
    """
    Verify that a committed BLAKE3 content hash exists in the ingestion store.

    This endpoint returns the stored proof bundle plus a server-side Merkle proof
    verification result so public portals can display both the commitment data and
    the verifiable transcript needed for independent re-checking.
    """
    # Apply rate limiting after authentication
    _apply_rate_limits(request, _api_key.key_id, "verify")

    with timed_operation("verify") as span:
        normalized_hash = _parse_content_hash(content_hash).hex()
        span.set_attribute("content_hash", normalized_hash)
        record = _fetch_by_content_hash(normalized_hash)
        if record is None:
            raise HTTPException(
                status_code=404, detail="Content hash not found in the ingestion store"
            )

        merkle_proof_valid = verify_proof(_merkle_proof_from_store(record))
        span.set_attribute("merkle_proof_valid", merkle_proof_valid)
        return HashVerificationResponse(**record, merkle_proof_valid=merkle_proof_valid)


@router.post("/proofs/verify", response_model=ProofVerificationResponse)
async def verify_submitted_proof_bundle(
    proof_request: ProofVerificationRequest, request: Request, _api_key: RequireVerifyScope
) -> ProofVerificationResponse:
    """Verify an externally supplied proof bundle without persisting it."""
    # Apply rate limiting after authentication
    _apply_rate_limits(request, _api_key.key_id, "verify")

    normalized_hash, normalized_root, content_hash_matches, merkle_proof_valid = (
        _evaluate_proof_bundle(
            proof_request.content_hash,
            proof_request.merkle_root,
            proof_request.merkle_proof,
        )
    )
    record = _fetch_by_content_hash(normalized_hash)
    # Return server-known poseidon_root only (HIGH-02 security fix)
    return ProofVerificationResponse(
        proof_id=record["proof_id"] if record is not None else proof_request.proof_id,
        content_hash=normalized_hash,
        merkle_root=normalized_root,
        content_hash_matches_proof=content_hash_matches,
        merkle_proof_valid=merkle_proof_valid,
        known_to_server=record is not None,
        poseidon_root=record.get("poseidon_root") if record is not None else None,
    )


@router.post("/proofs", response_model=ProofSubmissionResponse)
async def submit_proof_bundle(
    request: Request,
    _api_key: RequireVerifyScope,
    _rl: RateLimit,
    file: UploadFile = File(...),
) -> ProofSubmissionResponse:
    """Retrieve the server-computed proof bundle for a committed document.

    The caller supplies only the raw document bytes. The server
    canonicalizes, hashes, and looks up its authoritative proof record.
    No caller-supplied metadata is accepted — all proof fields are
    derived from the server's own ingestion records.

    Returns 404 if the document has not been committed yet. Commit
    first via POST /ingest/records.
    """
    _apply_rate_limits(request, _api_key.key_id, "verify")

    settings = get_settings()
    max_mb = settings.max_upload_bytes // 1024 // 1024

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum size of {max_mb} MB.",
                )
        except ValueError:
            pass

    file_bytes = await _read_upload_bounded(file, settings.max_upload_bytes, max_mb)
    validate_file_magic(file_bytes, file.content_type or "application/octet-stream")

    # Parse as JSON and canonicalize — same pipeline as the main ingest path.
    try:
        content = json.loads(file_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="File must be a valid JSON document.",
        ) from exc

    if not isinstance(content, dict):
        raise HTTPException(
            status_code=400,
            detail="Document must be a JSON object.",
        )

    _, content_hash = await _async_canonicalize_and_hash(content)

    record = _fetch_by_content_hash(content_hash)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Document not found in ledger. "
                "Commit the document first via POST /ingest/records, "
                "then retrieve its proof bundle here."
            ),
        )

    return ProofSubmissionResponse(
        **record,
        submitted=False,
        deduplicated=True,
    )


# ---------------------------------------------------------------------------
# Artifact commit endpoint
# ---------------------------------------------------------------------------


class ArtifactCommitRequest(BaseModel):
    """Request body for committing a pre-computed artifact hash to the ledger.

    Security boundary:
        ``id`` and ``namespace`` are validated by ``_IDENTIFIER_PATTERN`` at API
        ingestion time before persistence. This keeps externally supplied
        artifact identifiers constrained before they can flow into downstream
        proof tooling and subprocess-based proof backends.
    """

    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash of the artifact")
    namespace: str = Field(
        ...,
        description="Namespace for the artifact (e.g. 'github')",
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
    )
    id: str = Field(
        ...,
        description="Artifact identifier (e.g. 'org/repo/v1.0.0')",
        max_length=_ARTIFACT_ID_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_url: str | None = Field(
        None,
        description="Optional http(s) URL describing where the artifact was retrieved from",
        max_length=2048,
    )
    raw_pdf_hash: str | None = Field(
        None,
        description=(
            "Optional 64-character hex-encoded raw-PDF BLAKE3 hash anchored "
            "alongside OCR/text hashes"
        ),
    )


class ArtifactCommitResponse(BaseModel):
    """Response for a successful artifact commitment."""

    proof_id: str = Field(..., description="Proof identifier for future verification")
    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash that was committed")
    namespace: str
    id: str
    committed_at: str = Field(..., description="ISO 8601 commitment timestamp")
    ledger_entry_hash: str = Field(..., description="Hash of the ledger entry")
    poseidon_root: str | None = Field(
        None, description="Optional Poseidon root bound to the artifact commitment"
    )


@router.post("/commit", response_model=ArtifactCommitResponse)
async def commit_artifact(
    request: ArtifactCommitRequest, http_request: Request, _api_key: RequireCommitScope
) -> ArtifactCommitResponse:
    """
    Commit a pre-computed artifact hash to the Olympus ledger.

    This endpoint is the primary integration point for CI/CD pipelines.
    The caller is responsible for computing the BLAKE3 hash of the artifact
    before calling this endpoint.  The hash is committed to an append-only
    ledger entry, and a proof ID is returned for future verification.

    If PostgreSQL is configured, the artifact is persisted durably.

    Args:
        request: Artifact commit request with hash, namespace, and id.

    Returns:
        Commitment response with proof_id and ledger anchor details.
    """
    # Apply rate limiting after authentication
    _apply_rate_limits(http_request, _api_key.key_id, "commit")

    shard_id = f"artifacts/{request.namespace}"
    batch_id = str(uuid.uuid4())

    # Try to get storage layer (returns None if not configured)
    storage = _get_storage()

    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("namespace", request.namespace)
        span.set_attribute("artifact_id", request.id)
        span.set_attribute("using_postgres", storage is not None)

        # Validate artifact_hash is a well-formed 32-byte BLAKE3 hex string
        artifact_hash_bytes = _parse_content_hash(request.artifact_hash)
        artifact_hash_hex = artifact_hash_bytes.hex()

        # In-memory-only dedup: when no storage is configured, RT-H1 cannot
        # run, so check the in-memory cache here instead.
        if storage is None:
            existing = _fetch_by_content_hash(artifact_hash_hex)
            if existing is not None:
                existing_proof_id = existing["proof_id"]
                INGEST_TOTAL.labels(outcome="deduplicated").inc()
                return ArtifactCommitResponse(
                    proof_id=existing_proof_id,
                    artifact_hash=artifact_hash_hex,
                    namespace=existing.get("namespace", request.namespace),
                    id=existing.get("record_id", request.id),
                    committed_at=existing["timestamp"],
                    ledger_entry_hash=existing["ledger_entry_hash"],
                    poseidon_root=existing.get("poseidon_root"),
                )

        proof_id = str(uuid.uuid4())
        artifact_key = record_key("artifact", request.id, 1)
        # Always compute Poseidon root server-side (HIGH-02 security fix)
        poseidon_smt = _get_or_build_poseidon_smt(shard_id)
        poseidon_smt.update(artifact_key, _value_hash_to_poseidon_field(artifact_hash_bytes))
        poseidon_root_normalized = str(poseidon_smt.get_root())
        persisted_poseidon_root = _resolved_poseidon_root(None, poseidon_root_normalized)
        canonicalization = canonicalization_provenance(
            "application/octet-stream", CANONICAL_VERSION
        )
        # Poseidon root is always computed server-side (HIGH-02 security fix)
        canonicalization = dict(canonicalization)
        canonicalization["poseidon_root"] = persisted_poseidon_root
        if request.source_url:
            canonicalization["source_url"] = _normalize_source_url(request.source_url)
        if request.raw_pdf_hash:
            canonicalization["raw_pdf_hash"] = _parse_content_hash(request.raw_pdf_hash).hex()

        # If PostgreSQL is configured, persist artifact durably
        if storage is not None and _signing_key is not None:
            try:
                # Convert the server-computed Poseidon root decimal string to bytes for the
                # storage layer, which uses raw 32-byte big-endian encoding.
                poseidon_root_bytes = int(persisted_poseidon_root).to_bytes(32, byteorder="big")

                root_hash, proof, _header, _signature, ledger_entry = storage.append_record(
                    shard_id=shard_id,
                    record_type="artifact",
                    record_id=request.id,
                    version=1,  # Artifacts default to version 1
                    value_hash=artifact_hash_bytes,
                    signing_key=_signing_key,
                    canonicalization=canonicalization,
                    poseidon_root=poseidon_root_bytes,
                )
                persisted_poseidon_root = _resolved_poseidon_root(
                    ledger_entry.poseidon_root,
                    persisted_poseidon_root,
                )

                # Store mapping from proof_id to record coordinates
                ingestion_entry = {
                    "proof_id": proof_id,
                    "record_id": request.id,
                    "shard_id": shard_id,
                    "record_type": "artifact",
                    "version": 1,
                    "content_hash": artifact_hash_hex,
                    "namespace": request.namespace,
                    "merkle_root": root_hash.hex(),
                    "merkle_proof": _smt_proof_to_merkle_proof_dict(proof, artifact_hash_bytes),
                    "ledger_entry_hash": ledger_entry.entry_hash,
                    "timestamp": ledger_entry.ts,
                    "canonicalization": {
                        **canonicalization,
                        "poseidon_root": persisted_poseidon_root,
                    },
                    "persisted": True,
                    "batch_id": batch_id,
                    "batch_index": 0,
                    "poseidon_root": persisted_poseidon_root,
                }
                _ingestion_store[proof_id] = ingestion_entry
                _content_index[artifact_hash_hex] = proof_id
                storage.store_ingestion_batch(batch_id, [ingestion_entry])
                INGEST_TOTAL.labels(outcome="committed").inc()

                logger.info(
                    "artifact_committed",
                    extra={
                        "proof_id": proof_id,
                        "namespace": request.namespace,
                        "id": request.id,
                        "using_postgres": True,
                    },
                )

                return ArtifactCommitResponse(
                    proof_id=proof_id,
                    artifact_hash=artifact_hash_hex,
                    namespace=request.namespace,
                    id=request.id,
                    committed_at=ledger_entry.ts,
                    ledger_entry_hash=ledger_entry.entry_hash,
                    poseidon_root=persisted_poseidon_root,
                )
            except ValueError as e:
                error_msg = str(e)
                is_dedup = (
                    "Record already exists" in error_msg
                    or "Content hash already committed" in error_msg
                )
                if is_dedup:
                    existing = _fetch_by_content_hash(artifact_hash_hex) or {}
                    existing_proof_id = existing.get("proof_id", proof_id)
                    INGEST_TOTAL.labels(outcome="deduplicated").inc()
                    return ArtifactCommitResponse(
                        proof_id=existing_proof_id,
                        artifact_hash=artifact_hash_hex,
                        namespace=existing.get("namespace", request.namespace),
                        id=existing.get("record_id", request.id),
                        committed_at=existing.get("timestamp", current_timestamp()),
                        ledger_entry_hash=existing.get("ledger_entry_hash", ""),
                        poseidon_root=existing.get("poseidon_root", persisted_poseidon_root),
                    )
                else:
                    logger.exception(
                        "artifact_commit_storage_failed",
                        extra={"namespace": request.namespace, "id": request.id},
                    )
                    raise HTTPException(
                        status_code=500,
                        detail="Failed to persist artifact commitment.",
                    ) from e

        # Fall back to in-memory storage
        tree = MerkleTree([artifact_hash_bytes])
        merkle_root = tree.get_root().hex()

        # Append a ledger entry
        ledger_entry = _write_ledger.append(
            record_hash=merkle_root,
            shard_id=shard_id,
            shard_root=merkle_root,
            canonicalization=canonicalization,
        )
        ledger_height = len(_write_ledger.entries)
        LEDGER_HEIGHT.set(ledger_height)
        span.set_attribute("ledger_height", ledger_height)

        ts = current_timestamp()
        merkle_proof = tree.generate_proof(0)

        # Store metadata for future retrieval / verification
        _ingestion_store[proof_id] = {
            "proof_id": proof_id,
            "record_id": request.id,
            "shard_id": shard_id,
            "content_hash": artifact_hash_hex,
            "namespace": request.namespace,
            "merkle_root": merkle_root,
            "merkle_proof": {
                "leaf_hash": merkle_proof.leaf_hash.hex(),
                "leaf_index": merkle_proof.leaf_index,
                "siblings": [
                    [h.hex(), is_right == "right"] for h, is_right in merkle_proof.siblings
                ],
                "root_hash": merkle_proof.root_hash.hex(),
                "proof_version": merkle_proof.proof_version,
                "tree_version": merkle_proof.tree_version,
                "epoch": merkle_proof.epoch,
                "tree_size": merkle_proof.tree_size,
            },
            "ledger_entry_hash": ledger_entry.entry_hash,
            "timestamp": ts,
            "canonicalization": canonicalization,
            "persisted": False,
            "batch_id": batch_id,
            "batch_index": 0,
            "poseidon_root": poseidon_root_normalized,
        }
        _content_index[artifact_hash_hex] = proof_id
        INGEST_TOTAL.labels(outcome="committed").inc()

    logger.info(
        "artifact_committed",
        extra={
            "proof_id": proof_id,
            "namespace": request.namespace,
            "id": request.id,
            "using_postgres": storage is not None,
        },
    )

    return ArtifactCommitResponse(
        proof_id=proof_id,
        artifact_hash=artifact_hash_hex,
        namespace=request.namespace,
        id=request.id,
        committed_at=ts,
        ledger_entry_hash=ledger_entry.entry_hash,
        poseidon_root=poseidon_root_normalized,
    )
