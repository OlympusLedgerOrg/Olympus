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

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleProof, MerkleTree, verify_proof
from protocol.telemetry import INGEST_TOTAL, LEDGER_HEIGHT, timed_operation
from protocol.timestamps import current_timestamp


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


class HashVerificationResponse(IngestionProofResponse):
    """Verification result for a committed content hash."""

    merkle_proof_valid: bool


# ---------------------------------------------------------------------------
# In-memory state for ingestion tracking
# (Production would use the PostgreSQL StorageLayer)
# ---------------------------------------------------------------------------

# proof_id → ingestion metadata
_ingestion_store: dict[str, dict[str, Any]] = {}

# content_hash → proof_id (dedup index)
_content_index: dict[str, str] = {}

# Shared ledger for write path
_write_ledger = Ledger()


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
    siblings = [
        (bytes.fromhex(hash_hex), "right" if is_right else "left")
        for hash_hex, is_right in proof_data["siblings"]
    ]
    return MerkleProof(
        leaf_hash=bytes.fromhex(proof_data["leaf_hash"]),
        leaf_index=int(proof_data["leaf_index"]),
        siblings=siblings,
        root_hash=bytes.fromhex(proof_data["root_hash"]),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/records", response_model=BatchIngestionResponse)
async def ingest_batch(batch: BatchIngestionRequest) -> BatchIngestionResponse:
    """
    Atomically ingest a batch of records.

    Each record is canonicalized, hashed, and checked for duplicates.
    Non-duplicate records are committed to a Merkle tree and appended
    to the ledger.  The response includes proof IDs for async proof
    retrieval.

    Args:
        batch: Batch of records to ingest.

    Returns:
        Ingestion results with proof IDs.
    """
    shard_id = batch.records[0].shard_id
    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("batch_size", len(batch.records))
        results: list[IngestionResult] = []
        new_hashes: list[bytes] = []
        dedup_count = 0
        canonicalization = canonicalization_provenance(
            "application/json",
            CANONICAL_VERSION,
        )

        for record in batch.records:
            # Canonicalize and hash
            canonical = canonicalize_document(record.content)
            content_bytes = document_to_bytes(canonical)
            content_hash = hash_bytes(content_bytes).hex()

            # Dedup check
            if content_hash in _content_index:
                existing_proof_id = _content_index[content_hash]
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
                continue

            proof_id = str(uuid.uuid4())
            new_hashes.append(bytes.fromhex(content_hash))

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

        # Build Merkle tree from new content hashes
        ingested_count = len(batch.records) - dedup_count
        ts = current_timestamp()

        if new_hashes:
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
                    proof = tree.generate_proof(new_idx)
                    _ingestion_store[result.proof_id] = {
                        "proof_id": result.proof_id,
                        "record_id": result.record_id,
                        "shard_id": result.shard_id,
                        "content_hash": result.content_hash,
                        "merkle_root": merkle_root,
                        "merkle_proof": {
                            "leaf_hash": proof.leaf_hash.hex(),
                            "leaf_index": proof.leaf_index,
                            "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
                            "root_hash": proof.root_hash.hex(),
                        },
                        "ledger_entry_hash": ledger_entry_hash,
                        "timestamp": ts,
                        "canonicalization": canonicalization,
                    }
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
        },
    )

    return BatchIngestionResponse(
        ingested=ingested_count,
        deduplicated=dedup_count,
        results=results,
        ledger_entry_hash=ledger_entry_hash,
        timestamp=ts,
        canonicalization=canonicalization,
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
    if proof_id not in _ingestion_store:
        raise HTTPException(status_code=404, detail=f"Proof not found: {proof_id}")

    data = _ingestion_store[proof_id]
    return IngestionProofResponse(**data)


@router.get("/records/hash/{content_hash}/verify", response_model=HashVerificationResponse)
async def verify_ingested_content_hash(content_hash: str) -> HashVerificationResponse:
    """
    Verify that a committed BLAKE3 content hash exists in the ingestion store.

    This endpoint returns the stored proof bundle plus a server-side Merkle proof
    verification result so public portals can display both the commitment data and
    the verifiable transcript needed for independent re-checking.
    """
    with timed_operation("verify") as span:
        normalized_hash = _parse_content_hash(content_hash).hex()
        span.set_attribute("content_hash", normalized_hash)
        proof_id = _content_index.get(normalized_hash)
        if proof_id is None:
            raise HTTPException(
                status_code=404, detail=f"Committed hash not found: {normalized_hash}"
            )

        data = _ingestion_store[proof_id]
        merkle_proof_valid = verify_proof(_merkle_proof_from_store(data))
        span.set_attribute("merkle_proof_valid", merkle_proof_valid)
        return HashVerificationResponse(**data, merkle_proof_valid=merkle_proof_valid)


# ---------------------------------------------------------------------------
# Artifact commit endpoint
# ---------------------------------------------------------------------------


class ArtifactCommitRequest(BaseModel):
    """Request body for committing a pre-computed artifact hash to the ledger."""

    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash of the artifact")
    namespace: str = Field(..., description="Namespace for the artifact (e.g. 'github')")
    id: str = Field(..., description="Artifact identifier (e.g. 'org/repo/v1.0.0')")
    api_key: str | None = Field(None, description="Optional API key for authentication")


class ArtifactCommitResponse(BaseModel):
    """Response for a successful artifact commitment."""

    proof_id: str = Field(..., description="Proof identifier for future verification")
    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash that was committed")
    namespace: str
    id: str
    committed_at: str = Field(..., description="ISO 8601 commitment timestamp")
    ledger_entry_hash: str = Field(..., description="Hash of the ledger entry")


@router.post("/commit", response_model=ArtifactCommitResponse)
async def commit_artifact(request: ArtifactCommitRequest) -> ArtifactCommitResponse:
    """
    Commit a pre-computed artifact hash to the Olympus ledger.

    This endpoint is the primary integration point for CI/CD pipelines.
    The caller is responsible for computing the BLAKE3 hash of the artifact
    before calling this endpoint.  The hash is committed to an append-only
    ledger entry, and a proof ID is returned for future verification.

    Args:
        request: Artifact commit request with hash, namespace, and id.

    Returns:
        Commitment response with proof_id and ledger anchor details.
    """
    shard_id = f"artifacts/{request.namespace}"
    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("namespace", request.namespace)
        span.set_attribute("artifact_id", request.id)

        # Validate artifact_hash is a well-formed 32-byte BLAKE3 hex string
        artifact_hash_bytes = _parse_content_hash(request.artifact_hash)
        artifact_hash_hex = artifact_hash_bytes.hex()

        # Dedup: if this exact hash has already been committed, return existing proof
        if artifact_hash_hex in _content_index:
            existing_proof_id = _content_index[artifact_hash_hex]
            existing = _ingestion_store[existing_proof_id]
            INGEST_TOTAL.labels(outcome="deduplicated").inc()
            return ArtifactCommitResponse(
                proof_id=existing_proof_id,
                artifact_hash=artifact_hash_hex,
                namespace=existing.get("namespace", request.namespace),
                id=existing.get("record_id", request.id),
                committed_at=existing["timestamp"],
                ledger_entry_hash=existing["ledger_entry_hash"],
            )

        # Build a single-leaf Merkle tree for this artifact
        tree = MerkleTree([artifact_hash_bytes])
        merkle_root = tree.get_root().hex()

        # Append a ledger entry
        canonicalization = canonicalization_provenance(
            "application/octet-stream", CANONICAL_VERSION
        )
        ledger_entry = _write_ledger.append(
            record_hash=merkle_root,
            shard_id=shard_id,
            shard_root=merkle_root,
            canonicalization=canonicalization,
        )
        ledger_height = len(_write_ledger.entries)
        LEDGER_HEIGHT.labels(shard_id=shard_id).set(ledger_height)
        span.set_attribute("ledger_height", ledger_height)

        proof_id = str(uuid.uuid4())
        ts = current_timestamp()
        proof = tree.generate_proof(0)

        # Store metadata for future retrieval / verification
        _ingestion_store[proof_id] = {
            "proof_id": proof_id,
            "record_id": request.id,
            "shard_id": shard_id,
            "content_hash": artifact_hash_hex,
            "namespace": request.namespace,
            "merkle_root": merkle_root,
            "merkle_proof": {
                "leaf_hash": proof.leaf_hash.hex(),
                "leaf_index": proof.leaf_index,
                "siblings": [[h.hex(), is_right] for h, is_right in proof.siblings],
                "root_hash": proof.root_hash.hex(),
            },
            "ledger_entry_hash": ledger_entry.entry_hash,
            "timestamp": ts,
            "canonicalization": canonicalization,
        }
        _content_index[artifact_hash_hex] = proof_id
        INGEST_TOTAL.labels(outcome="committed").inc()

    logger.info(
        "artifact_committed",
        extra={"proof_id": proof_id, "namespace": request.namespace, "id": request.id},
    )

    return ArtifactCommitResponse(
        proof_id=proof_id,
        artifact_hash=artifact_hash_hex,
        namespace=request.namespace,
        id=request.id,
        committed_at=ts,
        ledger_entry_hash=ledger_entry.entry_hash,
    )
