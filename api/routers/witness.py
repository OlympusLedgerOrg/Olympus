"""
Witness Protocol API Endpoints.

This module provides FastAPI endpoints for external witnesses to monitor
Olympus nodes and detect split-view attacks. Witnesses collect checkpoints
from multiple nodes and compare them to detect inconsistencies.

This is a Phase 1+ feature implementing the witness protocol described in
docs/17_signed_checkpoints.md.

Endpoints:
    GET /witness/checkpoints/latest - Get latest checkpoint for verification
    GET /witness/checkpoints/{sequence} - Get checkpoint by sequence number
    GET /witness/checkpoints - List recent checkpoints
    POST /witness/observations - Submit checkpoint observations from other nodes
    GET /witness/gossip - Get gossip state for split-view detection
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/witness", tags=["witness"])


# Response Models
class CheckpointResponse(BaseModel):
    """Checkpoint response for witness verification."""

    sequence: int = Field(..., description="Checkpoint sequence number")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    ledger_head_hash: str = Field(..., description="Hash of latest ledger entry")
    previous_checkpoint_hash: str = Field(..., description="Hash of previous checkpoint")
    ledger_height: int = Field(..., description="Total number of ledger entries")
    shard_roots: dict[str, str] = Field(
        default_factory=dict, description="Shard-specific root hashes"
    )
    consistency_proof: list[str] = Field(
        default_factory=list, description="Merkle consistency proof"
    )
    checkpoint_hash: str = Field(..., description="Hash of checkpoint payload")
    federation_quorum_certificate: dict[str, Any] = Field(
        ..., description="Federation quorum certificate"
    )


class CheckpointListResponse(BaseModel):
    """List of recent checkpoints."""

    checkpoints: list[CheckpointResponse]
    count: int


class ObservationRequest(BaseModel):
    """Request body for submitting checkpoint observations."""

    node_id: str = Field(..., description="Identifier of the observed node")
    checkpoint: CheckpointResponse = Field(..., description="Observed checkpoint")


class GossipStateResponse(BaseModel):
    """Current gossip state showing observations from multiple nodes."""

    observations: dict[str, CheckpointResponse] = Field(
        ..., description="Mapping of node_id to latest observed checkpoint"
    )
    fork_evidence: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected fork evidence"
    )


# In-memory storage for witness state (would use persistent storage in production)
_checkpoint_registry: list[dict[str, Any]] = []
_observations: dict[str, dict[str, Any]] = {}


@router.get("/checkpoints/latest", response_model=CheckpointResponse)
async def get_latest_checkpoint() -> CheckpointResponse:
    """
    Get the latest checkpoint for witness verification.

    This endpoint returns the most recent checkpoint created by this node.
    Witnesses can use this to compare against other nodes and detect split views.

    Returns:
        Latest checkpoint

    Raises:
        404: If no checkpoints exist
        503: If checkpoint service is not initialized
    """
    if not _checkpoint_registry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No checkpoints available",
        )

    latest = _checkpoint_registry[-1]
    return CheckpointResponse(**latest)


@router.get("/checkpoints/{sequence}", response_model=CheckpointResponse)
async def get_checkpoint_by_sequence(sequence: int) -> CheckpointResponse:
    """
    Get a specific checkpoint by sequence number.

    Args:
        sequence: Checkpoint sequence number

    Returns:
        Checkpoint with the specified sequence

    Raises:
        404: If checkpoint not found
        503: If checkpoint service is not initialized
    """
    for checkpoint in _checkpoint_registry:
        if checkpoint["sequence"] == sequence:
            return CheckpointResponse(**checkpoint)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Checkpoint with sequence {sequence} not found",
    )


@router.get("/checkpoints", response_model=CheckpointListResponse)
async def list_checkpoints(
    limit: int = Query(10, ge=1, le=100, description="Maximum number of checkpoints to return"),
    offset: int = Query(0, ge=0, description="Number of checkpoints to skip"),
) -> CheckpointListResponse:
    """
    List recent checkpoints in reverse chronological order.

    Witnesses can use this to verify checkpoint chain integrity and detect
    any inconsistencies with other nodes.

    Args:
        limit: Maximum number of checkpoints to return (1-100)
        offset: Number of checkpoints to skip

    Returns:
        List of checkpoints with pagination metadata
    """
    # Return checkpoints in reverse chronological order (most recent first)
    start = len(_checkpoint_registry) - offset - 1
    end = max(start - limit, -1)

    checkpoints = []
    for i in range(start, end, -1):
        if i >= 0 and i < len(_checkpoint_registry):
            checkpoints.append(CheckpointResponse(**_checkpoint_registry[i]))

    return CheckpointListResponse(
        checkpoints=checkpoints,
        count=len(checkpoints),
    )


@router.post(
    "/observations",
    response_model=dict[str, str],
    status_code=status.HTTP_201_CREATED,
)
async def submit_observation(observation: ObservationRequest) -> dict[str, str]:
    """
    Submit a checkpoint observation from another node.

    Witnesses use this endpoint to share checkpoint observations from other
    nodes they are monitoring. The local witness can then compare these
    observations to detect split views.

    Args:
        observation: Checkpoint observation from another node

    Returns:
        Confirmation message

    Note:
        In production, this endpoint would:
        1. Verify the checkpoint signature
        2. Check for fork evidence against local state
        3. Store observation in persistent storage
        4. Trigger alerts if forks are detected
    """
    node_id = observation.node_id
    checkpoint_data = observation.checkpoint.model_dump()

    # Store observation (in production, would use persistent storage)
    _observations[node_id] = checkpoint_data

    logger.info(
        f"Recorded checkpoint observation from {node_id}: "
        f"seq={checkpoint_data['sequence']}, hash={checkpoint_data['checkpoint_hash']}"
    )

    # TODO: Check for fork evidence
    # from protocol.checkpoints import detect_checkpoint_fork
    # for existing_node_id, existing_checkpoint in _observations.items():
    #     if existing_node_id != node_id:
    #         if detect_checkpoint_fork(checkpoint_data, existing_checkpoint):
    #             logger.warning(f"Fork detected between {node_id} and {existing_node_id}")

    return {
        "status": "recorded",
        "node_id": node_id,
        "sequence": str(checkpoint_data["sequence"]),
    }


@router.get("/gossip", response_model=GossipStateResponse)
async def get_gossip_state() -> GossipStateResponse:
    """
    Get current gossip state showing observations from multiple nodes.

    This endpoint returns all checkpoint observations collected from other
    nodes, along with any detected fork evidence. Witnesses use this to
    monitor the global state and detect split views.

    Returns:
        Current gossip state with observations and fork evidence

    Note:
        In production, this would:
        1. Return observations from persistent storage
        2. Include computed fork evidence
        3. Filter by time window for recent observations
    """
    observations_response = {
        node_id: CheckpointResponse(**checkpoint)
        for node_id, checkpoint in _observations.items()
    }

    # TODO: Compute fork evidence
    # from protocol.checkpoints import detect_gossip_checkpoint_forks
    # from protocol.federation import FederationRegistry
    #
    # registry = ...  # Load registry
    # evidence = detect_gossip_checkpoint_forks(
    #     observations=_observations,
    #     registry=registry
    # )

    fork_evidence: list[dict[str, Any]] = []

    return GossipStateResponse(
        observations=observations_response,
        fork_evidence=fork_evidence,
    )


@router.get("/health", response_model=dict[str, str])
async def witness_health() -> dict[str, str]:
    """
    Health check for witness service.

    Returns:
        Service health status
    """
    return {
        "status": "ok",
        "checkpoints": str(len(_checkpoint_registry)),
        "observations": str(len(_observations)),
    }


# Admin/internal endpoints (would be protected in production)
def register_checkpoint(checkpoint_data: dict[str, Any]) -> None:
    """
    Register a checkpoint in the witness service.

    This is an internal function called when new checkpoints are created.
    In production, this would be triggered by the checkpoint creation process.

    Args:
        checkpoint_data: Checkpoint data to register
    """
    _checkpoint_registry.append(checkpoint_data)
    logger.info(
        f"Registered checkpoint {checkpoint_data['sequence']} with hash "
        f"{checkpoint_data['checkpoint_hash']}"
    )


def clear_observations() -> None:
    """
    Clear all observations (for testing/maintenance).

    This is an internal function for maintenance operations.
    """
    _observations.clear()
    logger.info("Cleared all checkpoint observations")
