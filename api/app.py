"""
Public audit API for Olympus Phase 0.5

This module provides read-only HTTP endpoints for third-party auditors
to verify records, proofs, signatures, and ledger integrity.

All responses include everything required for offline verification.
"""

import logging
import os

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from storage.postgres import StorageLayer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    prev_entry_hash: str  # Hex-encoded (empty for genesis)
    entry_hash: str  # Hex-encoded


class LedgerTailResponse(BaseModel):
    """Last N ledger entries for a shard."""
    shard_id: str
    entries: list[LedgerEntryResponse]


# Initialize FastAPI app
app = FastAPI(
    title="Olympus Public Audit API",
    description="Read-only API for verifying Olympus ledger, proofs, and signatures",
    version="0.5.0"
)

# Get database connection string from environment
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/olympus')
storage = StorageLayer(DATABASE_URL)


# Initialize schema on app startup
try:
    storage.init_schema()
    logger.info("Database schema initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize schema on startup: {e}")
    logger.warning("Schema will be initialized on first request if needed")


@app.get("/")
async def root():
    """API root with basic info."""
    return {
        "name": "Olympus Public Audit API",
        "version": "0.5.0",
        "description": "Read-only API for verifying Olympus protocol integrity",
        "endpoints": [
            "/shards",
            "/shards/{shard_id}/header/latest",
            "/shards/{shard_id}/proof",
            "/ledger/{shard_id}/tail"
        ]
    }


@app.get("/shards", response_model=list[ShardInfo])
async def list_shards():
    """
    List all shards with their latest state.

    Returns:
        List of shard information
    """
    try:
        shard_ids = storage.get_all_shard_ids()
        result = []

        for shard_id in shard_ids:
            header_data = storage.get_latest_header(shard_id)
            if header_data:
                result.append(ShardInfo(
                    shard_id=shard_id,
                    latest_seq=header_data['seq'],
                    latest_root=header_data['header']['root_hash']
                ))

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list shards: {str(e)}") from e


@app.get("/shards/{shard_id}/header/latest", response_model=ShardHeaderResponse)
async def get_latest_header(shard_id: str):
    """
    Get the latest shard header with signature.

    Includes everything needed for offline Ed25519 signature verification.

    Args:
        shard_id: Shard identifier

    Returns:
        Latest shard header with signature and canonical JSON
    """
    try:
        header_data = storage.get_latest_header(shard_id)

        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        header = header_data['header']

        # Create canonical header JSON for verification
        from protocol.canonical_json import canonical_json_encode
        canonical_header = {
            "shard_id": header['shard_id'],
            "root_hash": header['root_hash'],
            "timestamp": header['timestamp'],
            "previous_header_hash": header['previous_header_hash']
        }
        canonical_json = canonical_json_encode(canonical_header)

        return ShardHeaderResponse(
            shard_id=header['shard_id'],
            seq=header_data['seq'],
            root_hash=header['root_hash'],
            header_hash=header['header_hash'],
            previous_header_hash=header['previous_header_hash'],
            timestamp=header['timestamp'],
            signature=header_data['signature'],
            pubkey=header_data['pubkey'],
            canonical_header_json=canonical_json
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
    version: int = Query(..., description="Record version", ge=1)
):
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
    try:
        # Try to get existence proof
        proof = storage.get_proof(shard_id, record_type, record_id, version)

        # Get latest header
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        # Build header response
        header = header_data['header']
        from protocol.canonical_json import canonical_json_encode
        canonical_header = {
            "shard_id": header['shard_id'],
            "root_hash": header['root_hash'],
            "timestamp": header['timestamp'],
            "previous_header_hash": header['previous_header_hash']
        }
        canonical_json = canonical_json_encode(canonical_header)

        shard_header = ShardHeaderResponse(
            shard_id=header['shard_id'],
            seq=header_data['seq'],
            root_hash=header['root_hash'],
            header_hash=header['header_hash'],
            previous_header_hash=header['previous_header_hash'],
            timestamp=header['timestamp'],
            signature=header_data['signature'],
            pubkey=header_data['pubkey'],
            canonical_header_json=canonical_json
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
                shard_header=shard_header
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
                shard_header=shard_header
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get proof: {str(e)}") from e


@app.get("/ledger/{shard_id}/tail", response_model=LedgerTailResponse)
async def get_ledger_tail(
    shard_id: str,
    n: int = Query(10, description="Number of entries to retrieve", ge=1, le=1000)
):
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
                    prev_entry_hash=entry.prev_entry_hash,
                    entry_hash=entry.entry_hash
                )
                for entry in entries
            ]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get ledger tail: {str(e)}") from e


# Health check endpoint
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.5.0"}
