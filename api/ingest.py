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

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import TYPE_CHECKING, Any

import nacl.signing
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleProof, MerkleTree, deserialize_merkle_proof, verify_proof
from protocol.redaction_ledger import poseidon_root_to_bytes
from protocol.ssmf import ExistenceProof
from protocol.telemetry import INGEST_TOTAL, LEDGER_HEIGHT, timed_operation
from protocol.timestamps import current_timestamp


if TYPE_CHECKING:
    from storage.postgres import StorageLayer


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RecordInput(BaseModel):
    """A single record to ingest."""

    shard_id: str = Field(..., description="Target shard identifier")
    record_type: str = Field(..., description="Record type (e.g. 'document')")
    record_id: str = Field(..., description="Unique record identifier")
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


# ---------------------------------------------------------------------------
# In-memory state for ingestion tracking
# ---------------------------------------------------------------------------

# Storage layer (PostgreSQL persistence)
_storage: StorageLayer | None = None
_signing_key: nacl.signing.SigningKey | None = None

# Legacy in-memory stores (kept for backward compatibility during migration)
# proof_id → ingestion metadata
_ingestion_store: dict[str, dict[str, Any]] = {}

# content_hash → proof_id (dedup index)
_content_index: dict[str, str] = {}

# Shared ledger for write path (legacy, unused when storage is enabled)
_write_ledger = Ledger()

# API key hash -> key record
_api_key_store: dict[str, ApiKeyRecord] = {}
_api_keys_loaded = False


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
        logger.warning("DATABASE_URL not set - using in-memory storage (not production-safe)")
        return None

    # Check if signing key is configured
    signing_key_hex = os.environ.get("OLYMPUS_INGEST_SIGNING_KEY")
    if not signing_key_hex:
        logger.warning("OLYMPUS_INGEST_SIGNING_KEY not set - using in-memory storage")
        return None

    try:
        from storage.postgres import StorageLayer

        # Initialize storage
        storage = StorageLayer(database_url)
        storage.init_schema()
        storage.check_ingestion_schema()

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
        return None


def _cache_ingestion_record(entry: dict[str, Any]) -> None:
    """Cache ingestion metadata in memory for fast lookups."""
    poseidon_root = entry.get("poseidon_root")
    if poseidon_root is None:
        canonicalization = entry.get("canonicalization") or {}
        poseidon_root = canonicalization.get("poseidon_root")
        if poseidon_root is not None:
            entry["poseidon_root"] = poseidon_root
    proof_id = entry["proof_id"]
    _ingestion_store[proof_id] = entry
    _content_index[entry["content_hash"]] = proof_id


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
_rate_limit_key_buckets: dict[str, dict[str, TokenBucket]] = {
    "ingest": {},
    "commit": {},
    "verify": {},
}
_rate_limit_ip_buckets: dict[str, dict[str, TokenBucket]] = {
    "ingest": {},
    "commit": {},
    "verify": {},
}


def _parse_timestamp(raw: str) -> datetime:
    """Parse ISO-8601 timestamp with optional Z suffix."""
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware")
    return parsed.astimezone(UTC)


def _hash_api_key(api_key: str) -> str:
    """Hash API key material for at-rest storage."""
    return hash_bytes(api_key.encode("utf-8")).hex()


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
    """Load API keys once from OLYMPUS_API_KEYS_JSON."""
    global _api_keys_loaded
    if _api_keys_loaded:
        return
    _api_keys_loaded = True
    try:
        raw = json.loads(os.environ.get("OLYMPUS_API_KEYS_JSON", "[]"))
    except json.JSONDecodeError as exc:
        raise ValueError("OLYMPUS_API_KEYS_JSON must be valid JSON") from exc
    for item in raw:
        _register_api_key_for_tests(
            api_key=item["api_key"],
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


def _reset_ingest_state_for_tests() -> None:  # pragma: no cover - test utility
    """Reset in-memory ingestion, auth, and rate-limit state."""
    global _write_ledger, _api_keys_loaded, _storage, _signing_key
    _ingestion_store.clear()
    _content_index.clear()
    _api_key_store.clear()
    _api_keys_loaded = False
    _storage = None
    _signing_key = None
    for action in _rate_limit_key_buckets:
        _rate_limit_key_buckets[action].clear()
        _rate_limit_ip_buckets[action].clear()
    _write_ledger = Ledger()


def _set_rate_limit_for_tests(
    action: str, capacity: float, refill_rate_per_second: float
) -> None:  # pragma: no cover - test utility
    """Override rate-limit policy for tests."""
    _rate_limit_policy[action] = (capacity, refill_rate_per_second)
    _rate_limit_key_buckets[action].clear()
    _rate_limit_ip_buckets[action].clear()


def _client_ip(request: Request) -> str:
    """Resolve the caller IP address for abuse controls."""
    host = request.client.host if request.client else None
    return host or "unknown"


def _extract_api_key(request: Request, body_api_key: str | None = None) -> str:
    """Extract API key from header, bearer token, or request body fallback."""
    header_key = request.headers.get("x-api-key")
    if header_key:
        return header_key
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    if body_api_key:
        return body_api_key
    raise HTTPException(status_code=401, detail="API key is required")


def _get_bucket(buckets: dict[str, TokenBucket], subject: str, action: str) -> TokenBucket:
    """Get/create a token bucket for the subject and action."""
    existing = buckets.get(subject)
    if existing is not None:
        return existing
    capacity, refill = _rate_limit_policy[action]
    created = TokenBucket(
        capacity=capacity,
        refill_rate_per_second=refill,
        tokens=capacity,
        last_refill_ts=monotonic(),
    )
    buckets[subject] = created
    return created


def _authorize_and_rate_limit(
    request: Request, action: str, body_api_key: str | None = None
) -> ApiKeyRecord:
    """Authenticate API key, enforce scope/expiry, and apply token buckets."""
    _load_api_keys_from_env()
    api_key = _extract_api_key(request, body_api_key=body_api_key)
    key_hash = _hash_api_key(api_key)
    record = _api_key_store.get(key_hash)
    client_ip = _client_ip(request)
    if record is None:
        _append_security_audit_event("api_key_invalid", {"client_ip": client_ip, "action": action})
        raise HTTPException(status_code=401, detail="Invalid API key")
    if datetime.now(UTC) >= record.expires_at:
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

    key_bucket = _get_bucket(_rate_limit_key_buckets[action], record.key_id, action)
    if not key_bucket.consume():
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

    ip_bucket = _get_bucket(_rate_limit_ip_buckets[action], client_ip, action)
    if not ip_bucket.consume():
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


def _smt_proof_to_merkle_proof_dict(proof: ExistenceProof, leaf_hash: bytes) -> dict[str, Any]:
    """
    Convert an SMT ExistenceProof to Merkle proof dict format.

    The ingest API currently uses a simplified Merkle tree format, while the storage
    layer uses Sparse Merkle Trees. This helper bridges the two formats.

    Args:
        proof: SMT existence proof from storage layer
        leaf_hash: The leaf hash being proven

    Returns:
        Dict with merkle_proof structure expected by ingest API
    """
    # SMT proofs have a different structure - convert siblings format
    # For now, we'll create a simplified representation
    # TODO: Enhance this once we unify the proof formats
    return {
        "leaf_hash": leaf_hash.hex(),
        "leaf_index": 0,  # SMT proofs don't have leaf indices
        "siblings": [],  # Simplified for now
        "root_hash": proof.root_hash.hex(),
    }


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

    If PostgreSQL is configured (DATABASE_URL and OLYMPUS_INGEST_SIGNING_KEY),
    records are persisted durably. Otherwise, they are stored in-memory only.

    Args:
        batch: Batch of records to ingest.

    Returns:
        Ingestion results with proof IDs.
    """
    _authorize_and_rate_limit(request, action="ingest")
    shard_id = batch.records[0].shard_id

    # Try to get storage layer (returns None if not configured)
    storage = _get_storage()

    batch_id = str(uuid.uuid4())

    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("batch_size", len(batch.records))
        span.set_attribute("using_postgres", storage is not None)
        results: list[IngestionResult] = []
        new_hashes: list[bytes] = []
        dedup_count = 0
        persist_queue: list[dict[str, Any]] = []
        canonicalization = canonicalization_provenance(
            "application/json",
            CANONICAL_VERSION,
        )
        ts = current_timestamp()
        ledger_entry_hash = ""

        for record in batch.records:
            # Canonicalize and hash
            canonical = canonicalize_document(record.content)
            content_bytes = document_to_bytes(canonical)
            content_hash = hash_bytes(content_bytes).hex()
            content_hash_bytes = bytes.fromhex(content_hash)

            # Dedup check (in-memory or persisted)
            existing_record = _fetch_by_content_hash(content_hash)
            if existing_record is not None:
                results.append(
                    IngestionResult(
                        proof_id=existing_record["proof_id"],
                        record_id=existing_record["record_id"],
                        shard_id=existing_record["shard_id"],
                        content_hash=existing_record["content_hash"],
                        deduplicated=True,
                    )
                )
                dedup_count += 1
                ledger_entry_hash = existing_record.get("ledger_entry_hash", ledger_entry_hash)
                INGEST_TOTAL.labels(outcome="deduplicated").inc()
                continue

            proof_id = str(uuid.uuid4())

            # If PostgreSQL is configured, persist record durably
            if storage is not None and _signing_key is not None:
                try:
                    root_hash, proof, header, signature, ledger_entry = storage.append_record(
                        shard_id=record.shard_id,
                        record_type=record.record_type,
                        record_id=record.record_id,
                        version=record.version,
                        value_hash=content_hash_bytes,
                        signing_key=_signing_key,
                        canonicalization=canonicalization,
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
                        "merkle_proof": _smt_proof_to_merkle_proof_dict(proof, content_hash_bytes),
                        "ledger_entry_hash": ledger_entry.entry_hash,
                        "timestamp": ledger_entry.ts,
                        "canonicalization": canonicalization,
                        "persisted": True,
                        "batch_id": batch_id,
                        "batch_index": len(persist_queue),
                    }
                    _cache_ingestion_record(ingestion_entry)
                    persist_queue.append(ingestion_entry)
                    ts = ledger_entry.ts
                    ledger_entry_hash = ledger_entry.entry_hash
                    logger.info(f"Record {record.record_id} persisted to PostgreSQL")
                except ValueError as e:
                    if "Record already exists" in str(e):
                        # Record exists in database, treat as dedup and hydrate mapping
                        existing_record = _fetch_by_content_hash(content_hash)
                        existing_proof_id = (
                            existing_record["proof_id"] if existing_record else proof_id
                        )
                        results.append(
                            IngestionResult(
                                proof_id=existing_proof_id,
                                record_id=record.record_id,
                                shard_id=record.shard_id,
                                content_hash=content_hash,
                                deduplicated=True,
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

            results.append(
                IngestionResult(
                    proof_id=proof_id,
                    record_id=record.record_id,
                    shard_id=record.shard_id,
                    content_hash=content_hash,
                    deduplicated=False,
                )
            )

            _content_index[content_hash] = proof_id

        # Build Merkle tree from new content hashes (in-memory path only)
        ingested_count = len(batch.records) - dedup_count
        ts = current_timestamp()
        if new_hashes and storage is None:
            # In-memory path: build batch Merkle tree and ledger
            tree = MerkleTree(new_hashes)
            merkle_root = tree.get_root().hex()

            # Append to ledger
            ledger_entry = _write_ledger.append(
                record_hash=merkle_root,
                shard_id=shard_id,
                shard_root=merkle_root,
                canonicalization=canonicalization,
            )
            ledger_entry_hash = ledger_entry.entry_hash
            ledger_height = len(_write_ledger.entries)
            LEDGER_HEIGHT.labels(shard_id=shard_id).set(ledger_height)
            span.set_attribute("ledger_height", ledger_height)

            # Store proof metadata for each new record
            for i, result in enumerate(results):
                if not result.deduplicated:
                    # Find this record's index among new records
                    new_idx = sum(1 for r in results[: i + 1] if not r.deduplicated) - 1
                    merkle_proof = tree.generate_proof(new_idx)
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
                        "canonicalization": canonicalization,
                        "persisted": False,
                        "batch_id": batch_id,
                        "batch_index": sum(1 for r in results[: i + 1] if not r.deduplicated) - 1,
                    }
                    _cache_ingestion_record(_ingestion_store[result.proof_id])
                    INGEST_TOTAL.labels(outcome="committed").inc()
        elif storage is not None:
            # PostgreSQL path: records already persisted individually
            if persist_queue:
                storage.store_ingestion_batch(batch_id, persist_queue)
            # Get the latest ledger entry hash for response
            for result in results:
                if not result.deduplicated and result.proof_id in _ingestion_store:
                    ledger_entry_hash = _ingestion_store[result.proof_id]["ledger_entry_hash"]
                    INGEST_TOTAL.labels(outcome="committed").inc()
        else:
            ledger_entry_hash = (
                _write_ledger.entries[-1].entry_hash if _write_ledger.entries else ""
            )

        span.set_attribute("ingested", ingested_count)
        span.set_attribute("deduplicated", dedup_count)

    logger.info(
        "batch_ingested",
        extra={
            "ingested": ingested_count,
            "deduplicated": dedup_count,
            "total": len(batch.records),
            "using_postgres": storage is not None,
        },
    )

    return BatchIngestionResponse(
        ingested=ingested_count,
        deduplicated=dedup_count,
        results=results,
        ledger_entry_hash=ledger_entry_hash,
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
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")

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
                status_code=404, detail=f"Committed hash not found: {normalized_hash}"
            )

        merkle_proof_valid = verify_proof(_merkle_proof_from_store(record))
        span.set_attribute("merkle_proof_valid", merkle_proof_valid)
        return HashVerificationResponse(**record, merkle_proof_valid=merkle_proof_valid)


# ---------------------------------------------------------------------------
# Artifact commit endpoint
# ---------------------------------------------------------------------------


class ArtifactCommitRequest(BaseModel):
    """Request body for committing a pre-computed artifact hash to the ledger."""

    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash of the artifact")
    namespace: str = Field(..., description="Namespace for the artifact (e.g. 'github')")
    id: str = Field(..., description="Artifact identifier (e.g. 'org/repo/v1.0.0')")
    poseidon_root: str | None = Field(
        None,
        description=(
            "Optional Poseidon root (decimal string) to bind a ZK circuit root to the"
            " committed artifact hash"
        ),
    )
    api_key: str | None = Field(None, description="Optional API key for authentication")


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
    _authorize_and_rate_limit(http_request, action="commit", body_api_key=request.api_key)
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
        canonicalization = canonicalization_provenance(
            "application/octet-stream", CANONICAL_VERSION
        )
        if poseidon_root_normalized is not None:
            canonicalization = dict(canonicalization)
            canonicalization["poseidon_root"] = poseidon_root_normalized

        # If PostgreSQL is configured, persist artifact durably
        if storage is not None and _signing_key is not None:
            try:
                root_hash, proof, header, signature, ledger_entry = storage.append_record(
                    shard_id=shard_id,
                    record_type="artifact",
                    record_id=request.id,
                    version=1,  # Artifacts default to version 1
                    value_hash=artifact_hash_bytes,
                    signing_key=_signing_key,
                    canonicalization=canonicalization,
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
