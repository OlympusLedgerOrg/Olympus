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
from collections import OrderedDict, defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, status

from api.auth import RequireAPIKey
from api.schemas.witness import (
    GossipConflictEntry,
    WitnessAnnounceRequest,
    WitnessAnnounceResponse,
    WitnessAnnouncement,
    WitnessHealthResponse,
)
from protocol.timestamps import current_timestamp


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/witness", tags=["witness"])

# Maximum allowed age (in seconds) for announcement timestamps.
# Announcements whose checkpoint.timestamp is older than this are rejected
# as stale to prevent replay attacks.
_MAX_ANNOUNCE_SKEW_SECONDS: int = 60

# Maximum number of nonces to track for deduplication.  When the set
# reaches this size the oldest entries are evicted.
_MAX_NONCE_ENTRIES: int = 100_000

# ---------------------------------------------------------------------------
# In-process observation store (Phase 1 — no DB).
# Key: f"{announcement.origin}:{announcement.checkpoint.sequence}"
# Upgrade path: replace this dict with an async DB-backed repository that
# implements the same get/set interface used below.
# WARNING: this store is not safe for multi-worker deployments. Running
# uvicorn with --workers > 1 splits the store across processes silently,
# causing each worker to see only a fraction of observations. Ensure
# workers=1 (single-process mode) until the DB upgrade is complete.
# ---------------------------------------------------------------------------
_observations: dict[str, WitnessAnnouncement] = {}

# Bounded nonce set for replay-resistance.  Tracks recently seen nonces
# to reject duplicate submissions.  Uses OrderedDict for O(1) lookup and
# FIFO eviction when the capacity is reached.
_seen_nonces: OrderedDict[str, None] = OrderedDict()


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
async def submit_observation(
    request: WitnessAnnounceRequest,
    _api_key: RequireAPIKey,
) -> WitnessAnnounceResponse:
    """Submit a checkpoint announcement from an origin node.

    Args:
        request: Announcement containing the origin identifier, checkpoint,
            and a unique nonce.
        _api_key: Injected API-key dependency — callers must provide a valid
            key via ``X-API-Key`` header or ``Authorization: Bearer`` token.

    Returns:
        201 confirmation with origin, sequence, and status.

    Raises:
        409: If an announcement from the same origin at the same sequence
             already exists, or if the nonce has been seen before.
        422: If the checkpoint timestamp is stale (older than
             ``_MAX_ANNOUNCE_SKEW_SECONDS``).
    """
    # -- Replay-resistance: validate timestamp freshness -----------------
    try:
        ts = datetime.fromisoformat(
            request.checkpoint.timestamp.replace("Z", "+00:00")
        ).astimezone(UTC)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="checkpoint.timestamp must be a valid ISO 8601 UTC string",
        )

    now = datetime.now(UTC)
    age_seconds = (now - ts).total_seconds()
    if age_seconds > _MAX_ANNOUNCE_SKEW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Stale announcement: checkpoint.timestamp is {age_seconds:.0f}s old "
                f"(max {_MAX_ANNOUNCE_SKEW_SECONDS}s)"
            ),
        )
    if age_seconds < -_MAX_ANNOUNCE_SKEW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="checkpoint.timestamp is too far in the future",
        )

    # -- Replay-resistance: nonce deduplication --------------------------
    if request.nonce in _seen_nonces:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate nonce — possible replay",
        )

    key = f"{request.origin}:{request.checkpoint.sequence}"
    if key in _observations:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Announcement from origin '{request.origin}' at sequence "
                f"{request.checkpoint.sequence} already exists"
            ),
        )

    # Record the nonce (evict oldest if at capacity)
    _seen_nonces[request.nonce] = None
    while len(_seen_nonces) > _MAX_NONCE_ENTRIES:
        _seen_nonces.popitem(last=False)

    announcement = WitnessAnnouncement(
        origin=request.origin,
        checkpoint=request.checkpoint,
        received_at=current_timestamp(),
    )
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
    """Clear all stored observations and nonce tracking.

    Intended for use in tests and maintenance operations.
    """
    _observations.clear()
    _seen_nonces.clear()
    logger.info("Cleared all witness observations and nonce state")
