"""
Pydantic v2 schemas for witness protocol endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class WitnessCheckpoint(BaseModel):
    """Checkpoint data carried inside a witness announcement."""

    sequence: int = Field(..., description="Ledger sequence number")
    checkpoint_hash: str = Field(
        ...,
        min_length=64,
        max_length=128,
        pattern=r"^[0-9a-f]{64,128}$",
        description="Lowercase hex-encoded hash of the checkpoint payload (64–128 chars).",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of checkpoint creation, for replay-resistance.",
    )


class WitnessAnnounceRequest(BaseModel):
    """Request body for POST /witness/observations."""

    origin: str = Field(
        ...,
        description="Transparency log origin identifier (URL-like, e.g. 'example.com/my-log').",
        pattern=r"^[A-Za-z0-9._/:-]{1,256}$",
        max_length=256,
    )
    checkpoint: WitnessCheckpoint = Field(..., description="Checkpoint being announced")
    nonce: str = Field(
        ...,
        min_length=16,
        max_length=128,
        description="Unique nonce for replay-resistance. Must not be reused across submissions.",
    )
    node_signature: str = Field(
        ...,
        min_length=128,
        max_length=128,
        pattern=r"^[0-9a-f]{128}$",
        description=(
            "Hex-encoded Ed25519 signature (64 bytes = 128 hex chars) over "
            "the canonical checkpoint payload: "
            "SHA-256(origin || ':' || sequence || ':' || checkpoint_hash)."
        ),
    )


class WitnessAnnouncement(BaseModel):
    """A recorded checkpoint announcement from a specific origin."""

    origin: str = Field(
        ...,
        description="Transparency log origin identifier (URL-like, e.g. 'example.com/my-log').",
        pattern=r"^[A-Za-z0-9._/:-]{1,256}$",
        max_length=256,
    )
    checkpoint: WitnessCheckpoint = Field(..., description="Announced checkpoint")
    received_at: str = Field(
        ...,
        description="Server-assigned ISO 8601 UTC timestamp of when the announcement was received.",
    )


class WitnessAnnounceResponse(BaseModel):
    """Response body for POST /witness/observations."""

    origin: str = Field(
        ...,
        description="Transparency log origin identifier (URL-like, e.g. 'example.com/my-log').",
        pattern=r"^[A-Za-z0-9._/:-]{1,256}$",
        max_length=256,
    )
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
