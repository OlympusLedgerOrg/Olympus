"""
Witness transport endpoints for checkpoint gossip and verification.

These endpoints provide lightweight helpers for exchanging signed checkpoints
between witnesses without depending on internal database state.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from api.schemas.witness import (
    SignedCheckpointPayload,
    WitnessAnnouncementPayload,
    WitnessAnnounceRequest,
    WitnessAnnounceResponse,
    WitnessVerifyRequest,
    WitnessVerifyResponse,
)
from protocol.checkpoints import SignedCheckpoint
from protocol.federation import FederationRegistry
from protocol.witness_transport import WitnessAnnouncement, verify_announcement


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/witness", tags=["witness"])


def _to_checkpoint(payload: SignedCheckpointPayload) -> SignedCheckpoint:
    """Convert a Pydantic payload into a protocol SignedCheckpoint."""
    return SignedCheckpoint.from_dict(payload.model_dump())


def _announcement_from_payload(payload: WitnessAnnouncementPayload) -> WitnessAnnouncement:
    """Convert API payload into WitnessAnnouncement."""
    checkpoint = _to_checkpoint(payload.checkpoint)
    return WitnessAnnouncement(
        origin=payload.origin,
        observed_at=payload.observed_at,
        packet_hash=payload.packet_hash,
        checkpoint=checkpoint,
    )


@router.post("/announce", response_model=WitnessAnnounceResponse, status_code=status.HTTP_201_CREATED)
async def announce_checkpoint(request: WitnessAnnounceRequest) -> WitnessAnnounceResponse:
    """
    Build a witness announcement for a supplied checkpoint.

    The endpoint returns a deterministic transport packet that external
    witnesses can mirror or broadcast.
    """
    try:
        checkpoint = _to_checkpoint(request.checkpoint)
        announcement = WitnessAnnouncement.create(
            origin=request.origin,
            checkpoint=checkpoint,
            observed_at=request.observed_at,
        )
    except ValueError as exc:
        logger.warning("Failed to build witness announcement: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    response_checkpoint = SignedCheckpointPayload(**checkpoint.to_dict())
    return WitnessAnnounceResponse(
        origin=announcement.origin,
        observed_at=announcement.observed_at,
        packet_hash=announcement.packet_hash,
        checkpoint=response_checkpoint,
    )


@router.post("/verify", response_model=WitnessVerifyResponse)
async def verify_checkpoint_packet(request: WitnessVerifyRequest) -> WitnessVerifyResponse:
    """
    Verify a witness announcement packet.

    Optionally validates the embedded checkpoint against a supplied federation
    registry when ``validate_checkpoint`` is true.
    """
    try:
        announcement = _announcement_from_payload(request.packet)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail="Invalid packet payload") from exc

    registry: FederationRegistry | None = None
    if request.validate_checkpoint:
        if request.registry is None:
            return WitnessVerifyResponse(
                valid=False,
                reason="Registry required when validate_checkpoint is true",
            )
        try:
            registry = FederationRegistry.from_dict(request.registry)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid registry: {exc}") from exc

    valid = verify_announcement(announcement, registry=registry)
    return WitnessVerifyResponse(valid=valid, reason=None if valid else "Verification failed")
