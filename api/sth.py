"""
STH Gossip / Monitoring Endpoints for Olympus.

This module provides public endpoints for observers to collect and compare
Signed Tree Heads (STHs) across nodes, enabling detection of split-view logs.

Endpoints:
    GET /protocol/sth/latest - Get the latest STH for a shard
    GET /protocol/sth/history - Get recent STH history for a shard

These endpoints are intentionally public (no authentication) to allow
independent monitors to compare tree heads and detect inconsistencies.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/protocol/sth", tags=["sth"])

_SHARD_ID_RE = r"^[A-Za-z0-9:._-]{1,128}$"


class STHResponse(BaseModel):
    """Signed Tree Head response."""

    epoch_id: int
    tree_size: int
    merkle_root: str
    timestamp: str
    signature: str
    signer_pubkey: str


class STHHistoryResponse(BaseModel):
    """Historical STH list response."""

    shard_id: str
    sths: list[STHResponse]


# Storage layer will be injected as a dependency
# For now, we use a global that will be set by the main app
_storage = None


def set_storage(storage: Any) -> None:
    """Set the storage layer for STH endpoints."""
    global _storage
    _storage = storage


def _require_storage() -> Any:
    """Get storage layer, raising 503 if not available."""
    if _storage is None:
        raise HTTPException(
            status_code=503,
            detail="Database not available: storage not initialized",
        )
    return _storage


@router.get("/latest", response_model=STHResponse)
async def get_latest_sth(
    shard_id: str = Query(..., description="Shard identifier", pattern=_SHARD_ID_RE),
) -> STHResponse:
    """
    Get the latest Signed Tree Head for a shard.

    This endpoint returns the most recent STH committed for the specified shard.
    Observers can use this to collect STHs from multiple nodes and detect
    split-view logs by comparing roots and signatures.

    Args:
        shard_id: Shard identifier

    Returns:
        Latest Signed Tree Head for the shard

    Raises:
        404: If the shard does not exist or has no STH
        503: If the database is not available
    """
    storage = _require_storage()

    try:
        # Get the latest shard header
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(
                status_code=404,
                detail=f"Shard not found or has no header: {shard_id}",
            )

        header = header_data["header"]

        # Check if we have a stored STH for this shard
        # For now, we construct an STH from the header if one isn't explicitly stored
        # In a real implementation, STHs would be stored separately in the database

        # This is a minimal implementation - in production, you'd want to:
        # 1. Store STHs explicitly in the database with their signatures
        # 2. Have a background process that generates STHs periodically
        # 3. Track epoch_id separately from shard sequence numbers

        tree_size = header.get("tree_size")
        if tree_size is None:
            tree_size = storage.get_leaf_count(shard_id, up_to_ts=header["timestamp"])

        # For now, return a basic response based on the header
        return STHResponse(
            epoch_id=header_data["seq"],  # Using seq as epoch_id for now
            tree_size=tree_size,
            merkle_root=header["root_hash"],
            timestamp=header["timestamp"],
            signature=header_data["signature"],
            signer_pubkey=header_data["pubkey"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get latest STH for shard {shard_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get latest STH: {str(e)}",
        ) from e


@router.get("/history", response_model=STHHistoryResponse)
async def get_sth_history(
    shard_id: str = Query(..., description="Shard identifier", pattern=_SHARD_ID_RE),
    n: int = Query(10, description="Number of STHs to retrieve", ge=1, le=100),
) -> STHHistoryResponse:
    """
    Get recent STH history for a shard.

    Returns the most recent N Signed Tree Heads for the specified shard.
    Observers can use this to:
    - Verify append-only growth by checking consistency proofs
    - Detect rollbacks or forks
    - Compare historical STHs across nodes

    Args:
        shard_id: Shard identifier
        n: Number of STHs to retrieve (1-100, default 10)

    Returns:
        List of recent STHs in reverse chronological order (most recent first)

    Raises:
        404: If the shard does not exist
        503: If the database is not available
    """
    storage = _require_storage()

    try:
        # Get recent shard headers
        history = storage.get_header_history(shard_id, n)
        if not history:
            raise HTTPException(
                status_code=404,
                detail=f"Shard not found or has no history: {shard_id}",
            )

        # Convert headers to STH format
        # This is a simplified implementation - in production, STHs would be
        # stored and retrieved directly
        sths = []
        for entry in history:
            tree_size = entry.get("tree_size")
            if tree_size is None:
                tree_size = storage.get_leaf_count(shard_id, up_to_ts=entry["timestamp"])
            # Get the full header data for each historical entry
            # For now, we'll construct a minimal STH from the history entry
            sths.append(
                STHResponse(
                    epoch_id=entry["seq"],  # Using seq as epoch_id
                    tree_size=tree_size,
                    merkle_root=entry["root_hash"],
                    timestamp=entry["timestamp"],
                    signature="",  # Would need to retrieve from full header
                    signer_pubkey="",  # Would need to retrieve from full header
                )
            )

        return STHHistoryResponse(shard_id=shard_id, sths=sths)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get STH history for shard {shard_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get STH history: {str(e)}",
        ) from e
