"""
Pydantic models for witness transport API endpoints.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SignedCheckpointPayload(BaseModel):
    """Serialized checkpoint payload for transport over the API."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    timestamp: str
    ledger_head_hash: str
    previous_checkpoint_hash: str
    ledger_height: int
    shard_roots: dict[str, str] = Field(default_factory=dict)
    consistency_proof: list[str] = Field(default_factory=list)
    checkpoint_hash: str
    federation_quorum_certificate: dict[str, Any] = Field(default_factory=dict)


class WitnessAnnounceRequest(BaseModel):
    """Request body for creating a witness announcement."""

    model_config = ConfigDict(extra="forbid")

    origin: str
    checkpoint: SignedCheckpointPayload
    observed_at: str | None = None


class WitnessAnnouncementPayload(BaseModel):
    """Transport payload returned by the announce endpoint."""

    model_config = ConfigDict(extra="forbid")

    origin: str
    observed_at: str
    packet_hash: str
    checkpoint: SignedCheckpointPayload


class WitnessAnnounceResponse(WitnessAnnouncementPayload):
    """Alias for readability."""


class WitnessVerifyRequest(BaseModel):
    """Request body for verifying a witness packet."""

    model_config = ConfigDict(extra="forbid")

    packet: WitnessAnnouncementPayload
    validate_checkpoint: bool = False
    registry: dict[str, Any] | None = None


class WitnessVerifyResponse(BaseModel):
    """Verification result."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    reason: str | None = None
