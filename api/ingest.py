"""
Write API for Olympus — batch record ingestion and proof retrieval.

This module provides FastAPI endpoints for ingesting records into Olympus,
including batch operations, content-hash deduplication, and asynchronous
proof retrieval.

Endpoints:
    POST /ingest/records         — Atomically ingest a batch of records
    GET  /ingest/records/{proof_id}/proof — Retrieve proof for an ingested record

All write operations are append-only and maintain ledger chain integrity.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleTree
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
    results: list[IngestionResult] = []
    new_hashes: list[bytes] = []
    dedup_count = 0

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
        shard_id = batch.records[0].shard_id
        ledger_entry = _write_ledger.append(
            record_hash=merkle_root,
            shard_id=shard_id,
            shard_root=merkle_root,
        )
        ledger_entry_hash = ledger_entry.entry_hash

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
                }
    else:
        ledger_entry_hash = _write_ledger.entries[-1].entry_hash if _write_ledger.entries else ""

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
