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
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

import nacl.exceptions
import nacl.signing
from fastapi import APIRouter, HTTPException, Query, status

from api.auth import RequireAPIKey
from api.schemas.witness import (
    GossipConflictEntry,
    WitnessAnnouncement,
    WitnessAnnounceRequest,
    WitnessAnnounceResponse,
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

# Maximum number of observations to store in the in-process store.
# Prevents unbounded memory growth under sustained load.
_MAX_OBSERVATIONS: int = 500_000

# ---------------------------------------------------------------------------
# In-process observation store (Phase 1 — no DB).
# Key: f"{announcement.origin}:{announcement.checkpoint.sequence}"
#
# Uses OrderedDict so that FIFO/LRU eviction (popitem(last=False)) removes the
# oldest entries once _MAX_OBSERVATIONS is reached, preventing unbounded memory
# growth under sustained load.
#
# _observations_by_seq is a secondary index keyed by sequence number for O(1)
# lookups in get_checkpoint_by_sequence().  It mirrors _observations and is
# updated atomically with it.
#
# Upgrade path: replace with an async DB-backed repository that implements the
# same get/set interface used below.
#
# WARNING: this store is not safe for multi-worker deployments. Running
# uvicorn with --workers > 1 splits the store across processes silently,
# causing each worker to see only a fraction of observations. Ensure
# workers=1 (single-process mode) until the DB upgrade is complete.
# ---------------------------------------------------------------------------
_observations: OrderedDict[str, WitnessAnnouncement] = OrderedDict()

# Secondary index: sequence number → first WitnessAnnouncement seen for that sequence.
# Allows O(1) lookups in get_checkpoint_by_sequence() instead of O(n) linear scans.
_observations_by_seq: dict[int, WitnessAnnouncement] = {}

# Bounded nonce set for replay-resistance.  Tracks recently seen nonces
# to reject duplicate submissions.  Uses OrderedDict for O(1) lookup and
# FIFO eviction when the capacity is reached.
_seen_nonces: OrderedDict[str, None] = OrderedDict()

# Warn operators if the witness store is running in a multi-worker deployment.
# Split-view detection requires that all workers share the same store.
_web_concurrency = os.environ.get("WEB_CONCURRENCY", "")
try:
    if _web_concurrency.strip() and int(_web_concurrency) > 1:
        raise RuntimeError(
            f"Witness router: WEB_CONCURRENCY={_web_concurrency} but "
            "_observations is in-process only. Split-view detection "
            "silently fails across workers. Set WEB_CONCURRENCY=1 "
            "or upgrade to a DB-backed observation store."
        )
except ValueError:
    logger.warning(
        "Witness router: WEB_CONCURRENCY=%r is not a valid integer — "
        "multi-worker safety check skipped. Set WEB_CONCURRENCY to an integer.",
        _web_concurrency,
    )


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
    """
    announcement = _observations_by_seq.get(sequence)
    if announcement is not None:
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
    if request.nonce in _seen_nonces:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate nonce — possible replay",
        )

    # -- Ed25519 signature verification (C2SP tlog-witness model) --------
    # Verify the checkpoint signature from the announcing node's registered
    # public key before accepting the announcement.
    # Payload: SHA-256(origin:sequence:checkpoint_hash) as bytes.
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed signature or public key: {exc}",
        )

    _origin_hash = hashlib.sha256(request.origin.encode()).hexdigest()[:16]
    key = f"{_origin_hash}:{request.checkpoint.sequence}"
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
    # Evict oldest entries when observation store is at capacity (LRU).
    # ``while`` (not ``if``) guards against concurrent requests that may have
    # pushed the store past capacity between the check and the insert.
    while len(_observations) >= _MAX_OBSERVATIONS:
        _, evicted = _observations.popitem(last=False)
        # Remove from the secondary index only if it still points to the evicted
        # announcement (another origin may have registered the same sequence).
        seq = evicted.checkpoint.sequence
        if _observations_by_seq.get(seq) is evicted:
            del _observations_by_seq[seq]
    _observations[key] = announcement
    # Populate secondary index: first announcement wins per sequence number.
    _observations_by_seq.setdefault(announcement.checkpoint.sequence, announcement)

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
    _observations_by_seq.clear()
    _seen_nonces.clear()
    logger.info("Cleared all witness observations and nonce state")
