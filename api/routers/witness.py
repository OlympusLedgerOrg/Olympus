"""
Witness Protocol API Endpoints.

This module provides FastAPI endpoints for external witnesses to monitor
Olympus nodes and detect split-view attacks. Witnesses collect checkpoints
from multiple nodes and compare them to detect inconsistencies.

This is a Phase 1+ feature implementing the witness protocol described in
docs/17_signed_checkpoints.md.

Endpoints:
    GET  /witness/checkpoints/latest   - Latest announced checkpoint
    GET  /witness/checkpoints/{seq}    - Announcement by sequence number
    GET  /witness/checkpoints          - Paginated list sorted by sequence desc
    POST /witness/observations         - Submit a checkpoint announcement
    GET  /witness/gossip               - Split-view evidence across origins
    GET  /witness/health               - Service health
"""

from __future__ import annotations

import logging
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas.witness import (
    GossipConflictEntry,
    WitnessAnnounceRequest,
    WitnessAnnounceResponse,
    WitnessAnnouncement,
    WitnessHealthResponse,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/witness", tags=["witness"])

# ---------------------------------------------------------------------------
# In-process observation store (Phase 1 — no DB).
# Key: f"{announcement.origin}:{announcement.checkpoint.sequence}"
# Upgrade path: replace this dict with an async DB-backed repository that
# implements the same get/set interface used below.
# ---------------------------------------------------------------------------
_observations: dict[str, WitnessAnnouncement] = {}


@router.get("/checkpoints/latest", response_model=WitnessAnnouncement)
async def get_latest_checkpoint() -> WitnessAnnouncement:
    """Return the announcement with the highest checkpoint sequence.

    Raises:
        404: If no announcements have been stored yet.
    """
    if not _observations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No checkpoints available",
        )
    return max(_observations.values(), key=lambda a: a.checkpoint.sequence)


@router.get("/checkpoints/{sequence}", response_model=WitnessAnnouncement)
async def get_checkpoint_by_sequence(sequence: int) -> WitnessAnnouncement:
    """Return any stored announcement whose checkpoint.sequence matches.

    Args:
        sequence: Checkpoint sequence number to look up.

    Raises:
        404: If no announcement for that sequence exists.

    Note:
        O(n) linear scan over the in-process store is acceptable for Phase 1.
        The DB-backed upgrade path should add a secondary index on
        checkpoint.sequence.
    """
    for announcement in _observations.values():
        if announcement.checkpoint.sequence == sequence:
            return announcement
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No announcement found for sequence {sequence}",
    )


@router.get("/checkpoints", response_model=list[WitnessAnnouncement])
async def list_checkpoints(
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
) -> list[WitnessAnnouncement]:
    """Return a paginated list of announcements sorted by sequence descending.

    Args:
        limit: Maximum number of results (default 20).
        offset: Number of results to skip for pagination.
    """
    sorted_announcements = sorted(
        _observations.values(),
        key=lambda a: a.checkpoint.sequence,
        reverse=True,
    )
    return sorted_announcements[offset : offset + limit]


@router.post(
    "/observations",
    response_model=WitnessAnnounceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_observation(request: WitnessAnnounceRequest) -> WitnessAnnounceResponse:
    """Submit a checkpoint announcement from an origin node.

    Args:
        request: Announcement containing the origin identifier and checkpoint.

    Returns:
        201 confirmation with origin, sequence, and status.

    Raises:
        409: If an announcement from the same origin at the same sequence
             already exists.
    """
    key = f"{request.origin}:{request.checkpoint.sequence}"
    if key in _observations:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Announcement from origin '{request.origin}' at sequence "
                f"{request.checkpoint.sequence} already exists"
            ),
        )

    announcement = WitnessAnnouncement.create(request)
    _observations[key] = announcement

    logger.info(
        "Stored announcement %s: seq=%d hash=%s",
        key,
        announcement.checkpoint.sequence,
        announcement.checkpoint.checkpoint_hash,
    )

    return WitnessAnnounceResponse(
        origin=announcement.origin,
        sequence=announcement.checkpoint.sequence,
        status="recorded",
    )


@router.get("/gossip", response_model=list[GossipConflictEntry])
async def get_gossip_state() -> list[GossipConflictEntry]:
    """Return split-view evidence detected across stored announcements.

    Groups announcements by checkpoint.sequence.  Any sequence where two or
    more distinct origins reported differing checkpoint_hash values is
    considered a conflict.

    Returns:
        List of conflict entries (empty if no conflicts exist).
    """
    # Group by sequence: sequence -> {origin -> checkpoint_hash}
    by_sequence: dict[int, dict[str, str]] = defaultdict(dict)
    for announcement in _observations.values():
        seq = announcement.checkpoint.sequence
        by_sequence[seq][announcement.origin] = announcement.checkpoint.checkpoint_hash

    conflicts: list[GossipConflictEntry] = []
    for seq, origin_hashes in by_sequence.items():
        unique_hashes = set(origin_hashes.values())
        if len(origin_hashes) >= 2 and len(unique_hashes) > 1:
            conflicts.append(
                GossipConflictEntry(
                    sequence=seq,
                    conflicting_origins=sorted(origin_hashes.keys()),
                    hashes=origin_hashes,
                )
            )

    return sorted(conflicts, key=lambda c: c.sequence)


@router.get("/health", response_model=WitnessHealthResponse)
async def witness_health() -> WitnessHealthResponse:
    """Return service health and current observation count."""
    return WitnessHealthResponse(
        status="ok",
        observation_count=len(_observations),
    )


def clear_observations() -> None:
    """Clear all stored observations.

    Intended for use in tests and maintenance operations.
    """
    _observations.clear()
    logger.info("Cleared all witness observations")
