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

import hashlib
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

import nacl.exceptions
import nacl.signing
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import RequireAPIKey
from api.deps import DBSession
from api.models.witness import WitnessNonce, WitnessObservation
from api.schemas.witness import (
    GossipConflictEntry,
    WitnessAnnouncement,
    WitnessAnnounceRequest,
    WitnessAnnounceResponse,
    WitnessHealthResponse,
)
from protocol.log_sanitization import sanitize_for_log
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

# Maximum number of observations to store.
# Prevents unbounded growth under sustained load.
_MAX_OBSERVATIONS: int = 500_000


def _resolve_node_pubkey(origin: str) -> str | None:
    """Return hex pubkey for a registered origin, or None if unknown.

    Reads OLYMPUS_WITNESS_REGISTRY env var as JSON dict:
        {"origin/string": "hexpubkey", ...}

    In production this should be backed by the federation registry
    (protocol/federation/identity.py FederationRegistry).

    TODO: Phase 2 — wire this to FederationRegistry.get_node().
    """
    registry_json = os.environ.get("OLYMPUS_WITNESS_REGISTRY", "{}")
    try:
        registry: dict[str, str] = json.loads(registry_json)
        return registry.get(origin)
    except (json.JSONDecodeError, TypeError):
        logger.error("OLYMPUS_WITNESS_REGISTRY is not valid JSON")
        return None


def _row_to_announcement(row: WitnessObservation) -> WitnessAnnouncement:
    """Deserialize a DB row back into a WitnessAnnouncement."""
    return WitnessAnnouncement.model_validate(json.loads(row.announcement_json))


@router.get("/checkpoints/latest", response_model=WitnessAnnouncement)
async def get_latest_checkpoint(db: DBSession) -> WitnessAnnouncement:
    """Return the announcement with the highest checkpoint sequence.

    Raises:
        404: If no announcements have been stored yet.
    """
    stmt = select(WitnessObservation).order_by(WitnessObservation.sequence.desc()).limit(1)
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No checkpoints available",
        )
    return _row_to_announcement(row)


@router.get("/checkpoints/{sequence}", response_model=WitnessAnnouncement)
async def get_checkpoint_by_sequence(sequence: int, db: DBSession) -> WitnessAnnouncement:
    """Return any stored announcement whose checkpoint.sequence matches.

    Args:
        sequence: Checkpoint sequence number to look up.

    Raises:
        404: If no announcement for that sequence exists.
    """
    stmt = (
        select(WitnessObservation)
        .where(WitnessObservation.sequence == sequence)
        .order_by(WitnessObservation.created_at.asc())
        .limit(1)
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None:
        return _row_to_announcement(row)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No announcement found for sequence {sequence}",
    )


@router.get("/checkpoints", response_model=list[WitnessAnnouncement])
async def list_checkpoints(
    db: DBSession,
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
) -> list[WitnessAnnouncement]:
    """Return a paginated list of announcements sorted by sequence descending.

    Args:
        limit: Maximum number of results (default 20).
        offset: Number of results to skip for pagination.
    """
    stmt = (
        select(WitnessObservation)
        .order_by(WitnessObservation.sequence.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [_row_to_announcement(r) for r in rows]


@router.post(
    "/observations",
    response_model=WitnessAnnounceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_observation(
    request: WitnessAnnounceRequest,
    _api_key: RequireAPIKey,
    db: DBSession,
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
        ts = datetime.fromisoformat(request.checkpoint.timestamp.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="checkpoint.timestamp must be a valid ISO 8601 UTC string",
        )

    now = datetime.now(timezone.utc)
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
    nonce_exists = await db.execute(
        select(WitnessNonce.id).where(WitnessNonce.nonce == request.nonce).limit(1)
    )
    if nonce_exists.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate nonce — possible replay",
        )

    # -- Ed25519 signature verification (C2SP tlog-witness model) --------
    _signed_payload = hashlib.sha256(
        f"{request.origin}:{request.checkpoint.sequence}:{request.checkpoint.checkpoint_hash}".encode()
    ).digest()

    try:
        sig_bytes = bytes.fromhex(request.node_signature)
        pubkey_hex = _resolve_node_pubkey(request.origin)
        if pubkey_hex is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unknown origin — node not registered in federation registry.",
            )
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
        verify_key.verify(_signed_payload, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid checkpoint signature — announcement rejected.",
        )
    except (ValueError, KeyError) as exc:
        logger.warning("Malformed signature or public key: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed signature or public key",
        )

    _origin_key_prefix = hashlib.sha256(request.origin.encode()).hexdigest()[:16]
    key = f"{_origin_key_prefix}:{request.checkpoint.sequence}"

    existing = await db.execute(
        select(WitnessObservation.id).where(WitnessObservation.key == key).limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Announcement from origin '{request.origin}' at sequence "
                f"{request.checkpoint.sequence} already exists"
            ),
        )

    # Evict oldest nonces when at capacity (before adding the new one)
    nonce_count_result = await db.execute(select(func.count(WitnessNonce.id)))
    nonce_count = nonce_count_result.scalar_one()
    if nonce_count >= _MAX_NONCE_ENTRIES:
        excess = nonce_count - _MAX_NONCE_ENTRIES + 1
        oldest_nonce_ids = (
            select(WitnessNonce.id).order_by(WitnessNonce.created_at.asc()).limit(excess)
        )
        await db.execute(delete(WitnessNonce).where(WitnessNonce.id.in_(oldest_nonce_ids)))

    # Record the nonce
    db.add(WitnessNonce(nonce=request.nonce))

    received_at = current_timestamp()
    announcement = WitnessAnnouncement(
        origin=request.origin,
        checkpoint=request.checkpoint,
        received_at=received_at,
    )

    obs = WitnessObservation(
        key=key,
        origin=request.origin,
        sequence=request.checkpoint.sequence,
        checkpoint_hash=request.checkpoint.checkpoint_hash,
        checkpoint_timestamp=request.checkpoint.timestamp,
        received_at=received_at,
        nonce=request.nonce,
        announcement_json=announcement.model_dump_json(),
    )
    # Evict oldest observations when at capacity (before adding the new one)
    obs_count_result = await db.execute(select(func.count(WitnessObservation.id)))
    obs_count = obs_count_result.scalar_one()
    if obs_count >= _MAX_OBSERVATIONS:
        excess = obs_count - _MAX_OBSERVATIONS + 1
        oldest_obs_ids = (
            select(WitnessObservation.id)
            .order_by(WitnessObservation.created_at.asc())
            .limit(excess)
        )
        await db.execute(
            delete(WitnessObservation).where(WitnessObservation.id.in_(oldest_obs_ids))
        )

    db.add(obs)

    await db.commit()

    logger.info(
        "Stored announcement %s: seq=%d hash=%s",
        sanitize_for_log(key),
        announcement.checkpoint.sequence,
        sanitize_for_log(announcement.checkpoint.checkpoint_hash),
    )

    return WitnessAnnounceResponse(
        origin=announcement.origin,
        sequence=announcement.checkpoint.sequence,
        status="recorded",
    )


@router.get("/gossip", response_model=list[GossipConflictEntry])
async def get_gossip_state(db: DBSession) -> list[GossipConflictEntry]:
    """Return split-view evidence detected across stored announcements.

    Groups announcements by checkpoint.sequence.  Any sequence where two or
    more distinct origins reported differing checkpoint_hash values is
    considered a conflict.

    Returns:
        List of conflict entries (empty if no conflicts exist).
    """
    stmt = select(WitnessObservation)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    by_sequence: dict[int, dict[str, str]] = defaultdict(dict)
    for row in rows:
        by_sequence[row.sequence][row.origin] = row.checkpoint_hash

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
async def witness_health(db: DBSession) -> WitnessHealthResponse:
    """Return service health and current observation count."""
    count_result = await db.execute(select(func.count(WitnessObservation.id)))
    count = count_result.scalar_one()
    return WitnessHealthResponse(
        status="ok",
        observation_count=count,
    )


async def clear_observations(db: AsyncSession) -> None:
    """Clear all stored observations and nonce tracking.

    Intended for use in tests and maintenance operations.

    Args:
        db: An async database session.
    """
    await db.execute(delete(WitnessObservation))
    await db.execute(delete(WitnessNonce))
    await db.commit()
    logger.info("Cleared all witness observations and nonce state")
