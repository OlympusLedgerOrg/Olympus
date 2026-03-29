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
import hmac as _hmac_module  # used ONLY for hmac.compare_digest (timing-safe comparison)
import json
import logging
import os
import uuid
import warnings
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import TYPE_CHECKING, Any

import nacl.signing
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth import _ip_in_ranges
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
from protocol.redaction_ledger import poseidon_root_to_bytes
from protocol.ssmf import ExistenceProof
from protocol.telemetry import INGEST_TOTAL, LEDGER_HEIGHT, timed_operation
from protocol.timestamps import current_timestamp


if TYPE_CHECKING:
    from protocol.poseidon_smt import PoseidonSMT
    from storage.postgres import StorageLayer


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


# Allowlist pattern for identifier fields.  Permits alphanumeric chars plus the
# small set of punctuation genuinely needed for shard/record/artifact IDs
# (e.g. "watauga:2025:budget", "org/repo/v1.2.3-rc.1", "doc-001").
# Deliberately excludes control characters, null bytes, shell metacharacters
# (\ * ? < > | ; ` $ ! &), and Unicode homoglyphs (pure ASCII allowlist).
_IDENTIFIER_PATTERN = r"^[a-zA-Z0-9_./:@+\-]+$"
_IDENTIFIER_MAX_LEN = 256
# Artifact IDs (e.g. 'org/repo/v1.2.3-rc.1+build.42') are typically longer than shard/record IDs.
_ARTIFACT_ID_MAX_LEN = 512


class RecordInput(BaseModel):
    """A single record to ingest."""

    shard_id: str = Field(
        ...,
        description="Target shard identifier",
        max_length=_IDENTIFIER_MAX_LEN,
        pattern=_IDENTIFIER_PATTERN,
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
    poseidon_root: str | None = Field(
        None, description="Optional Poseidon root bound to the same commitment"
    )


class ProofVerificationResponse(BaseModel):
    """Server-side verification result for a submitted proof bundle."""

    proof_id: str | None
    content_hash: str
    merkle_root: str
    content_hash_matches_proof: bool
    merkle_proof_valid: bool
    known_to_server: bool
    poseidon_root: str | None = None


class ProofSubmissionRequest(ProofVerificationRequest):
    """Proof bundle payload that can be submitted to the API for later retrieval."""

    record_id: str = Field(..., description="Record identifier associated with the proof bundle")
    shard_id: str = Field(..., description="Shard identifier associated with the proof bundle")
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

# API key hash -> key record
_api_key_store: dict[str, ApiKeyRecord] = {}
_api_keys_loaded = False

# L4-E: Trusted proxy IP ranges for X-Forwarded-For parsing.
# Only parse X-Forwarded-For header when the direct peer is a known trusted proxy.
# This prevents IP spoofing attacks where a client sets a fake X-Forwarded-For header.
# Configure via OLYMPUS_TRUSTED_PROXY_IPS environment variable (comma-separated IPs or CIDRs).
TRUSTED_PROXY_RANGES: list[str] = [
    ip.strip() for ip in os.environ.get("OLYMPUS_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()
]


def _dev_signing_key_enabled() -> bool:
    """Return True when dev-mode auto signing key generation is enabled."""
    return os.environ.get("OLYMPUS_DEV_SIGNING_KEY", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# Hard fail when persistence is configured without a signing key
if os.environ.get("DATABASE_URL") and not os.environ.get("OLYMPUS_INGEST_SIGNING_KEY"):
    if not _dev_signing_key_enabled():
        raise RuntimeError(
            "DATABASE_URL is set but OLYMPUS_INGEST_SIGNING_KEY is missing - "
            "ingest persistence cannot start without a signing key"
        )
    logger.warning(
        "DATABASE_URL is set but OLYMPUS_INGEST_SIGNING_KEY is missing - "
        "using a dev-generated signing key (OLYMPUS_DEV_SIGNING_KEY enabled)"
    )


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
        logger.critical(
            "*** DEV SIGNING KEY IN USE *** "
            "OLYMPUS_INGEST_SIGNING_KEY is missing - using a dev-generated signing key "
            "(OLYMPUS_DEV_SIGNING_KEY enabled). "
            "All previously signed shard headers will become unverifiable after restart. "
            "Do NOT use this in production."
        )
        _signing_key = nacl.signing.SigningKey.generate()

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


@dataclass
class ApiKeyRecord:
    """Hashed API key record with scoped permissions and expiry."""

    key_id: str
    key_hash: str
    scopes: set[str]
    expires_at: datetime


@dataclass
class TokenBucket:
    """Simple token-bucket rate limiter state."""

    capacity: float
    refill_rate_per_second: float
    tokens: float
    last_refill_ts: float

    def consume(self, tokens: float = 1.0) -> bool:
        """Consume tokens if available."""
        now = monotonic()
        elapsed = max(0.0, now - self.last_refill_ts)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_second)
        self.last_refill_ts = now
        if self.tokens < tokens:
            return False
        self.tokens -= tokens
        return True


_rate_limit_policy: dict[str, tuple[float, float]] = {
    "ingest": (60.0, 1.0),
    "commit": (30.0, 0.5),
    "verify": (120.0, 2.0),
}

# L5-B: Maximum number of entries in rate-limit buckets to prevent memory leaks
_RATE_LIMIT_LRU_CAP = 10_000

# Maximum number of entries in ingestion caches to prevent OOM under sustained load
_INGESTION_CACHE_LRU_CAP = 50_000

# Use OrderedDict to implement LRU eviction when cap is reached
_rate_limit_key_buckets: dict[str, OrderedDict[str, TokenBucket]] = {
    "ingest": OrderedDict(),
    "commit": OrderedDict(),
    "verify": OrderedDict(),
}
_rate_limit_ip_buckets: dict[str, OrderedDict[str, TokenBucket]] = {
    "ingest": OrderedDict(),
    "commit": OrderedDict(),
    "verify": OrderedDict(),
}

# L5-C: Thread lock for rate-limit bucket access to prevent race conditions
# in concurrent request handling (identified in red team security audit).
_rate_limit_lock = Lock()

# fix-07: Warn operators that rate limiting is in-process only.  In a
# multi-process or multi-node deployment each worker maintains its own
# independent token buckets, so the effective limits are multiplied by the
# number of workers.  A distributed backend (e.g. Redis) is needed to
# enforce consistent per-key / per-IP limits across processes.
warnings.warn(
    "Rate limiting is in-process only. In multi-worker/multi-node deployments "
    "effective limits are multiplied by the number of workers. Consider a "
    "distributed rate-limit backend (e.g. Redis) for production.",
    stacklevel=1,
)


def _parse_timestamp(raw: str) -> datetime:
    """Parse ISO-8601 timestamp with optional Z suffix."""
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _hash_api_key(api_key: str) -> str:
    """Hash API key material for at-rest storage."""
    return hash_bytes(api_key.encode("utf-8")).hex()


def _constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe string equality check.

    Wraps :func:`hmac.compare_digest` to make intent explicit: this is
    a **constant-time comparison**, not an HMAC/MAC computation.  The
    ``hmac`` stdlib module is used solely because it provides the only
    timing-safe comparator in the Python standard library.

    All cryptographic hashing in Olympus uses BLAKE3 (via
    ``protocol.hashes``); Ed25519 signing uses ``nacl``.  This function
    is **not** part of either cryptographic path — it exists only to
    prevent timing oracle attacks on hash comparisons.
    """
    return _hmac_module.compare_digest(a, b)


def _constant_time_api_key_lookup(key_hash: str) -> ApiKeyRecord | None:
    """
    Lookup API key record using constant-time comparison (L4-D).

    Uses hmac.compare_digest to prevent timing oracle attacks where an
    attacker could measure response times to determine how many characters
    of a key hash match.

    Note: This function deliberately iterates through ALL stored keys even
    after finding a match, to ensure constant-time execution regardless of
    key position. This is O(n) where n is the number of API keys, which is
    acceptable for typical deployments (<1000 keys). For deployments with
    significantly more keys, consider alternative constant-time lookup
    strategies or rate-limiting at the network layer.

    Args:
        key_hash: Hex-encoded BLAKE3 hash of the API key.

    Returns:
        ApiKeyRecord if found, None otherwise.
    """
    # Iterate through all stored keys and use constant-time comparison
    # This prevents timing attacks based on early dictionary key rejection
    found_record: ApiKeyRecord | None = None
    for stored_hash, record in _api_key_store.items():
        if _constant_time_equals(stored_hash, key_hash):
            found_record = record
    return found_record


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


def _load_api_keys_from_env() -> None:
    """Load API keys once from OLYMPUS_API_KEYS_JSON or OLYMPUS_FOIA_API_KEYS.

    Checks OLYMPUS_API_KEYS_JSON first; falls back to OLYMPUS_FOIA_API_KEYS so
    operators only need to configure one variable.
    """
    global _api_keys_loaded
    if _api_keys_loaded:
        return
    _api_keys_loaded = True
    # Prefer OLYMPUS_API_KEYS_JSON; fall back to OLYMPUS_FOIA_API_KEYS for consolidated config
    raw_str = os.environ.get("OLYMPUS_API_KEYS_JSON") or os.environ.get(
        "OLYMPUS_FOIA_API_KEYS", "[]"
    )
    try:
        raw = json.loads(raw_str)
    except json.JSONDecodeError as exc:
        raise ValueError("API keys env var must be valid JSON") from exc
    for item in raw:
        if "key_hash" not in item:
            raise ValueError(
                "API keys must contain hashed API keys under 'key_hash' "
                "(hex-encoded). Raw API keys are not accepted."
            )
        _register_hashed_api_key(
            key_hash=item["key_hash"],
            key_id=item.get("key_id", "default"),
            scopes=set(item.get("scopes", ["ingest", "commit", "verify"])),
            expires_at=item.get("expires_at", "2099-01-01T00:00:00Z"),
        )


def _register_api_key_for_tests(
    api_key: str, key_id: str, scopes: set[str], expires_at: str
) -> None:  # pragma: no cover - test utility
    """Register hashed API key (used by env bootstrap and tests)."""
    key_hash = _hash_api_key(api_key)
    _api_key_store[key_hash] = ApiKeyRecord(
        key_id=key_id,
        key_hash=key_hash,
        scopes=scopes,
        expires_at=_parse_timestamp(expires_at),
    )
    _append_security_audit_event(
        "api_key_registered",
        {"key_id": key_id, "scopes": sorted(scopes), "expires_at": expires_at},
    )


def _register_hashed_api_key(key_hash: str, key_id: str, scopes: set[str], expires_at: str) -> None:
    """Register a pre-hashed API key (preferred for production bootstrap)."""
    try:
        decoded = bytes.fromhex(key_hash)
    except ValueError as exc:
        raise ValueError("key_hash must be hex-encoded") from exc
    if len(decoded) != 32:
        raise ValueError("key_hash must be 32 bytes (64 hex characters)")
    _api_key_store[key_hash] = ApiKeyRecord(
        key_id=key_id,
        key_hash=key_hash,
        scopes=scopes,
        expires_at=_parse_timestamp(expires_at),
    )
    _append_security_audit_event(
        "api_key_registered",
        {"key_id": key_id, "scopes": sorted(scopes), "expires_at": expires_at},
    )


def _reset_ingest_state_for_tests() -> None:  # pragma: no cover - test utility
    """Reset in-memory ingestion, auth, and rate-limit state and enable test mode."""
    global _write_ledger, _api_keys_loaded, _storage, _signing_key, _TEST_MODE
    # L4-F: Enable test mode to allow in-memory storage
    _TEST_MODE = True
    storage = _storage
    _ingestion_store.clear()
    _content_index.clear()
    _api_key_store.clear()
    _api_keys_loaded = False
    _storage = None
    _signing_key = None
    # L5-C: Acquire lock when clearing rate-limit buckets
    with _rate_limit_lock:
        for action in _rate_limit_key_buckets:
            _rate_limit_key_buckets[action].clear()
            _rate_limit_ip_buckets[action].clear()
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
    # L5-C: Acquire lock when clearing rate-limit buckets
    with _rate_limit_lock:
        _rate_limit_key_buckets[action].clear()
        _rate_limit_ip_buckets[action].clear()
    if _storage is not None:
        try:
            _storage.clear_rate_limits()
        except Exception:
            logger.warning("Failed to clear persisted rate limits during test setup", exc_info=True)


def _client_ip(request: Request) -> str:
    """
    Resolve the caller IP address for abuse controls.

    L4-E: Only parses X-Forwarded-For if the direct peer is a trusted proxy.
    This prevents IP spoofing attacks where a malicious client sets a fake
    X-Forwarded-For header to bypass rate limiting.

    Args:
        request: The incoming HTTP request.

    Returns:
        The client IP address (from X-Forwarded-For if behind a trusted proxy,
        otherwise the direct peer IP).
    """
    peer_ip = request.client.host if request.client else None

    # Only parse X-Forwarded-For if the peer is a trusted proxy (CIDR-aware check)
    if peer_ip and TRUSTED_PROXY_RANGES and _ip_in_ranges(peer_ip, TRUSTED_PROXY_RANGES):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # X-Forwarded-For format: "client, proxy1, proxy2, ..."
            # The leftmost IP is the original client
            forwarded_ip = xff.split(",")[0].strip()
            if forwarded_ip:
                return forwarded_ip

    return peer_ip or "unknown"


def _extract_api_key(request: Request) -> str:
    """Extract API key from X-API-Key header or Authorization: Bearer token."""
    header_key = request.headers.get("x-api-key")
    if header_key:
        return header_key
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    raise HTTPException(status_code=401, detail="API key is required")


def _get_bucket(buckets: OrderedDict[str, TokenBucket], subject: str, action: str) -> TokenBucket:
    """
    Get/create a token bucket for the subject and action.

    L5-B: Implements LRU eviction when the bucket count exceeds _RATE_LIMIT_LRU_CAP.
    Existing buckets are moved to the end (most recently used) when accessed.
    When creating a new bucket and the cap is exceeded, the oldest (least recently
    used) bucket is removed.

    IMPORTANT: This function must be called while holding _rate_limit_lock (L5-C).
    The assertion below will catch violations during testing/development.
    """
    # L5-C: Ensure lock is held to catch programming errors early
    if not _rate_limit_lock.locked():
        raise RuntimeError("_get_bucket must be called while holding _rate_limit_lock")

    existing = buckets.get(subject)
    if existing is not None:
        # Move to end (mark as recently used)
        buckets.move_to_end(subject)
        return existing

    # L5-B: Evict oldest entries if at capacity
    while len(buckets) >= _RATE_LIMIT_LRU_CAP:
        buckets.popitem(last=False)  # Remove oldest (first) entry

    capacity, refill = _rate_limit_policy[action]
    created = TokenBucket(
        capacity=capacity,
        refill_rate_per_second=refill,
        tokens=capacity,
        last_refill_ts=monotonic(),
    )
    buckets[subject] = created
    return created


def _consume_rate_limit(subject_type: str, subject: str, action: str) -> bool:
    """
    Consume a token for the given subject/action, preferring the shared storage backend.

    Falls back to process-local buckets if storage is unavailable or errors.
    """
    capacity, refill = _rate_limit_policy[action]
    storage = None
    try:
        storage = _get_storage()
    except RuntimeError:
        # Configuration errors should propagate; let caller handle.
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

    # L5-C: Acquire lock before accessing in-memory rate-limit buckets.
    # This prevents race conditions where concurrent requests could corrupt
    # the OrderedDict state or read inconsistent token values.
    with _rate_limit_lock:
        buckets = _rate_limit_key_buckets if subject_type == "api_key" else _rate_limit_ip_buckets
        bucket = _get_bucket(buckets[action], subject, action)
        return bucket.consume()


def _authorize_and_rate_limit(request: Request, action: str) -> ApiKeyRecord:
    """Authenticate API key, enforce scope/expiry, and apply token buckets."""
    _load_api_keys_from_env()
    api_key = _extract_api_key(request)
    key_hash = _hash_api_key(api_key)
    # L4-D: Use constant-time lookup to prevent timing oracle attacks
    record = _constant_time_api_key_lookup(key_hash)
    client_ip = _client_ip(request)
    if record is None:
        _append_security_audit_event("api_key_invalid", {"client_ip": client_ip, "action": action})
        raise HTTPException(status_code=401, detail="Invalid API key")
    if datetime.now(timezone.utc) >= record.expires_at:
        _append_security_audit_event(
            "api_key_expired", {"key_id": record.key_id, "client_ip": client_ip, "action": action}
        )
        raise HTTPException(status_code=401, detail="API key expired")
    if action not in record.scopes:
        _append_security_audit_event(
            "api_key_scope_denied",
            {"key_id": record.key_id, "client_ip": client_ip, "action": action},
        )
        raise HTTPException(status_code=403, detail=f"API key lacks required scope: {action}")

    if not _consume_rate_limit("api_key", record.key_id, action):
        logger.warning(
            "rate_limit_hit",
            extra={"dimension": "api_key", "key_id": record.key_id, "action": action},
        )
        _append_security_audit_event(
            "rate_limit_hit",
            {
                "dimension": "api_key",
                "key_id": record.key_id,
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
            {"dimension": "ip", "key_id": record.key_id, "client_ip": client_ip, "action": action},
        )
        raise HTTPException(status_code=429, detail="Rate limit exceeded for IP address")
    return record


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


def _value_hash_to_poseidon_field(value_hash: bytes) -> int:
    """Convert a 32-byte value hash into the BN128 field element used by PoseidonSMT."""
    if len(value_hash) != 32:
        raise ValueError(f"value_hash must be 32 bytes, got {len(value_hash)}")
    return int.from_bytes(value_hash, byteorder="big")


def _build_poseidon_smt_for_storage_shard(storage: StorageLayer, shard_id: str) -> PoseidonSMT:
    """Rebuild the current PoseidonSMT view for a shard from persisted SMT leaves."""
    from protocol.poseidon_smt import PoseidonSMT

    with storage._get_connection() as conn, conn.cursor() as cur:
        tree = storage._load_tree_state(cur, shard_id)

    poseidon_smt = PoseidonSMT()
    for key, value_hash in tree.leaves.items():
        poseidon_smt.update(key, _value_hash_to_poseidon_field(value_hash))
    return poseidon_smt


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
) -> tuple[RecordInput, str, bytes, str]:
    """
    Process a single record's canonicalization asynchronously.

    Returns:
        Tuple of (record, content_hash_hex, content_hash_bytes, proof_id)
    """
    content_bytes, content_hash = await _async_canonicalize_and_hash(record.content)
    content_hash_bytes = bytes.fromhex(content_hash)
    proof_id = str(uuid.uuid4())
    return record, content_hash, content_hash_bytes, proof_id


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/records", response_model=BatchIngestionResponse)
async def ingest_batch(batch: BatchIngestionRequest, request: Request) -> BatchIngestionResponse:
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
    _authorize_and_rate_limit(request, action="ingest")

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
    record_data_map: dict[int, tuple[str, bytes, str]] = {
        i: (content_hash, content_hash_bytes, proof_id)
        for i, (_, content_hash, content_hash_bytes, proof_id) in enumerate(canonicalized_results)
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
            poseidon_smt = (
                _build_poseidon_smt_for_storage_shard(storage, shard_id)
                if storage is not None
                else PoseidonSMT()
            )

            for original_idx, record in shard_records:
                content_hash, content_hash_bytes, proof_id = record_data_map[original_idx]
                record_smt_key = record_key(record.record_type, record.record_id, record.version)

                # Dedup check (in-memory or persisted)
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
                    ledger_entry_hash = existing_record.get("ledger_entry_hash", ledger_entry_hash)
                    INGEST_TOTAL.labels(outcome="deduplicated").inc()
                    continue

                # If PostgreSQL is configured, persist record durably
                if storage is not None and _signing_key is not None:
                    try:
                        poseidon_smt.update(
                            record_smt_key, _value_hash_to_poseidon_field(content_hash_bytes)
                        )
                        poseidon_root = str(poseidon_smt.get_root())
                        canonicalization_with_poseidon = {
                            **canonicalization,
                            "poseidon_root": poseidon_root,
                        }
                        root_hash, proof, _header, _signature, ledger_entry = storage.append_record(
                            shard_id=record.shard_id,
                            record_type=record.record_type,
                            record_id=record.record_id,
                            version=record.version,
                            value_hash=content_hash_bytes,
                            signing_key=_signing_key,
                            canonicalization=canonicalization_with_poseidon,
                            poseidon_root=int(poseidon_root).to_bytes(32, byteorder="big"),
                        )

                        # Store mapping from proof_id to record coordinates for later retrieval
                        ingestion_entry = {
                            "proof_id": proof_id,
                            "record_id": record.record_id,
                            "shard_id": record.shard_id,
                            "record_type": record.record_type,
                            "version": record.version,
                            "content_hash": content_hash,
                            "merkle_root": root_hash.hex(),
                            "merkle_proof": _smt_proof_to_merkle_proof_dict(
                                proof, content_hash_bytes
                            ),
                            "ledger_entry_hash": ledger_entry.entry_hash,
                            "timestamp": ledger_entry.ts,
                            "canonicalization": canonicalization_with_poseidon,
                            "persisted": True,
                            "batch_id": batch_id,
                            "batch_index": len(persist_queue),
                            "poseidon_root": poseidon_root,
                        }
                        _cache_ingestion_record(ingestion_entry)
                        persist_queue.append(ingestion_entry)
                        ts = ledger_entry.ts
                        ledger_entry_hash = ledger_entry.entry_hash
                        logger.info(f"Record {record.record_id} persisted to PostgreSQL")
                    except ValueError as e:
                        if "Record already exists" in str(e):
                            # Record exists in database, treat as dedup and hydrate mapping
                            poseidon_smt = _build_poseidon_smt_for_storage_shard(storage, shard_id)
                            existing_record = _fetch_by_content_hash(content_hash)
                            existing_proof_id = (
                                existing_record["proof_id"] if existing_record else proof_id
                            )
                            results.append(
                                (
                                    original_idx,
                                    IngestionResult(
                                        proof_id=existing_proof_id,
                                        record_id=record.record_id,
                                        shard_id=record.shard_id,
                                        content_hash=content_hash,
                                        deduplicated=True,
                                        idempotent=True,
                                    ),
                                )
                            )
                            dedup_count += 1
                            INGEST_TOTAL.labels(outcome="deduplicated").inc()
                            if existing_record:
                                ledger_entry_hash = existing_record.get(
                                    "ledger_entry_hash", ledger_entry_hash
                                )
                            continue
                        else:
                            raise
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
                LEDGER_HEIGHT.labels(shard_id=shard_id).set(ledger_height)
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
                # PostgreSQL path: records already persisted individually
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
async def get_ingestion_proof(proof_id: str) -> IngestionProofResponse:
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
    content_hash: str, request: Request
) -> HashVerificationResponse:
    """
    Verify that a committed BLAKE3 content hash exists in the ingestion store.

    This endpoint returns the stored proof bundle plus a server-side Merkle proof
    verification result so public portals can display both the commitment data and
    the verifiable transcript needed for independent re-checking.
    """
    _authorize_and_rate_limit(request, action="verify")
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
    proof_request: ProofVerificationRequest, request: Request
) -> ProofVerificationResponse:
    """Verify an externally supplied proof bundle without persisting it."""
    _authorize_and_rate_limit(request, action="verify")
    normalized_hash, normalized_root, content_hash_matches, merkle_proof_valid = (
        _evaluate_proof_bundle(
            proof_request.content_hash,
            proof_request.merkle_root,
            proof_request.merkle_proof,
        )
    )
    record = _fetch_by_content_hash(normalized_hash)
    return ProofVerificationResponse(
        proof_id=record["proof_id"] if record is not None else proof_request.proof_id,
        content_hash=normalized_hash,
        merkle_root=normalized_root,
        content_hash_matches_proof=content_hash_matches,
        merkle_proof_valid=merkle_proof_valid,
        known_to_server=record is not None,
        poseidon_root=proof_request.poseidon_root
        if record is None
        else record.get("poseidon_root"),
    )


@router.post("/proofs", response_model=ProofSubmissionResponse)
async def submit_proof_bundle(
    proof_request: ProofSubmissionRequest, request: Request
) -> ProofSubmissionResponse:
    """Accept a verified proof bundle so it can be retrieved through the API later."""
    _authorize_and_rate_limit(request, action="verify")
    normalized_hash, normalized_root, content_hash_matches, merkle_proof_valid = (
        _evaluate_proof_bundle(
            proof_request.content_hash,
            proof_request.merkle_root,
            proof_request.merkle_proof,
        )
    )
    if not content_hash_matches or not merkle_proof_valid:
        raise HTTPException(status_code=400, detail="Submitted proof bundle failed verification")

    existing = _fetch_by_content_hash(normalized_hash)
    if existing is not None:
        return ProofSubmissionResponse(**existing, submitted=False, deduplicated=True)

    proof_id = proof_request.proof_id or str(uuid.uuid4())
    stored_entry = {
        "proof_id": proof_id,
        "record_id": proof_request.record_id,
        "shard_id": proof_request.shard_id,
        "content_hash": normalized_hash,
        "merkle_root": normalized_root,
        "merkle_proof": proof_request.merkle_proof,
        "ledger_entry_hash": proof_request.ledger_entry_hash,
        "timestamp": proof_request.timestamp,
        "canonicalization": proof_request.canonicalization,
        "batch_id": proof_request.batch_id,
        "poseidon_root": proof_request.poseidon_root,
        "persisted": False,
    }
    _cache_ingestion_record(stored_entry)
    return ProofSubmissionResponse(
        proof_id=proof_id,
        record_id=proof_request.record_id,
        shard_id=proof_request.shard_id,
        content_hash=normalized_hash,
        merkle_root=normalized_root,
        merkle_proof=proof_request.merkle_proof,
        ledger_entry_hash=proof_request.ledger_entry_hash,
        timestamp=proof_request.timestamp,
        canonicalization=proof_request.canonicalization,
        batch_id=proof_request.batch_id,
        poseidon_root=proof_request.poseidon_root,
        submitted=True,
        deduplicated=False,
    )


# ---------------------------------------------------------------------------
# Artifact commit endpoint
# ---------------------------------------------------------------------------


class ArtifactCommitRequest(BaseModel):
    """Request body for committing a pre-computed artifact hash to the ledger."""

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
    poseidon_root: str | None = Field(
        None,
        description=(
            "Optional Poseidon root (decimal string) to bind a ZK circuit root to the"
            " committed artifact hash"
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
    request: ArtifactCommitRequest, http_request: Request
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
    _authorize_and_rate_limit(http_request, action="commit")
    shard_id = f"artifacts/{request.namespace}"
    batch_id = str(uuid.uuid4())
    poseidon_root_input = request.poseidon_root
    poseidon_root_normalized: str | None = None

    if poseidon_root_input is not None:
        poseidon_bytes = poseidon_root_to_bytes(poseidon_root_input)
        poseidon_root_normalized = str(int.from_bytes(poseidon_bytes, byteorder="big"))

    # Try to get storage layer (returns None if not configured)
    storage = _get_storage()

    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("namespace", request.namespace)
        span.set_attribute("artifact_id", request.id)
        span.set_attribute("using_postgres", storage is not None)

        # Validate artifact_hash is a well-formed 32-byte BLAKE3 hex string
        artifact_hash_bytes = _parse_content_hash(request.artifact_hash)
        artifact_hash_hex = artifact_hash_bytes.hex()

        # Dedup: if this exact hash has already been committed, return existing proof
        existing = _fetch_by_content_hash(artifact_hash_hex)
        if existing is not None:
            existing_poseidon = existing.get("poseidon_root")
            if poseidon_root_normalized is not None and existing_poseidon not in (
                None,
                poseidon_root_normalized,
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Conflicting poseidon_root for existing artifact commitment",
                )
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
        if poseidon_root_normalized is None:
            if storage is not None:
                poseidon_smt = _build_poseidon_smt_for_storage_shard(storage, shard_id)
            else:
                from protocol.poseidon_smt import PoseidonSMT

                poseidon_smt = PoseidonSMT()
            poseidon_smt.update(artifact_key, _value_hash_to_poseidon_field(artifact_hash_bytes))
            poseidon_root_normalized = str(poseidon_smt.get_root())
        canonicalization = canonicalization_provenance(
            "application/octet-stream", CANONICAL_VERSION
        )
        if poseidon_root_normalized is not None:
            canonicalization = dict(canonicalization)
            canonicalization["poseidon_root"] = poseidon_root_normalized

        # If PostgreSQL is configured, persist artifact durably
        if storage is not None and _signing_key is not None:
            try:
                # Convert the normalized Poseidon root decimal string to bytes for the
                # storage layer, which uses raw 32-byte big-endian encoding.
                poseidon_root_bytes: bytes | None = None
                if poseidon_root_normalized is not None:
                    poseidon_root_bytes = int(poseidon_root_normalized).to_bytes(
                        32, byteorder="big"
                    )

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
                    "canonicalization": canonicalization,
                    "persisted": True,
                    "batch_id": batch_id,
                    "batch_index": 0,
                    "poseidon_root": poseidon_root_normalized,
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
                    poseidon_root=poseidon_root_normalized,
                )
            except ValueError as e:
                if "Record already exists" in str(e):
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
                        poseidon_root=existing.get("poseidon_root", poseidon_root_normalized),
                    )
                else:
                    raise

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
        LEDGER_HEIGHT.labels(shard_id=shard_id).set(ledger_height)
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
