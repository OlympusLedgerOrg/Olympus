"""
Pydantic v2 schemas for witness protocol endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class WitnessCheckpoint(BaseModel):
    """Checkpoint data carried inside a witness announcement."""

    sequence: int = Field(..., description="Ledger sequence number")
    timestamp: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp from the SignedCheckpoint payload, "
        "used for replay-resistance verification.",
    )
    checkpoint_hash: str = Field(
        ...,
        min_length=64,
        max_length=128,
        pattern=r"^[0-9a-f]{64,128}$",
        description="Lowercase hex-encoded hash of the checkpoint payload (64–128 chars).",
    )


class WitnessAnnounceRequest(BaseModel):
    """Request body for POST /witness/observations."""

    origin: str = Field(..., description="Identifier of the announcing node/origin")
    checkpoint: WitnessCheckpoint = Field(..., description="Checkpoint being announced")


class WitnessAnnouncement(BaseModel):
    """A recorded checkpoint announcement from a specific origin."""

    origin: str = Field(..., description="Identifier of the announcing node/origin")
    checkpoint: WitnessCheckpoint = Field(..., description="Announced checkpoint")
    received_at: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp assigned by the server when the observation was recorded.",
    )


class WitnessAnnounceResponse(BaseModel):
    """Response body for POST /witness/observations."""

    origin: str = Field(..., description="Identifier of the announcing origin")
    sequence: int = Field(..., description="Sequence number of the announcement")
    status: str = Field(..., description="Confirmation status")


class GossipConflictEntry(BaseModel):
    """A single split-view conflict detected by gossip analysis."""

    sequence: int = Field(..., description="Sequence number where the conflict was detected")
    conflicting_origins: list[str] = Field(
        ..., description="Origins that reported differing hashes at this sequence"
    )
    hashes: dict[str, str] = Field(
        ..., description="Mapping of origin identifier to checkpoint hash"
    )


class WitnessHealthResponse(BaseModel):
    """Response body for GET /witness/health."""

    status: str = Field(..., description="Service health status")
    observation_count: int = Field(..., description="Number of stored observations")
