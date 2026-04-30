"""Federation API endpoints for Guardian replication.

This module provides endpoints for Guardian nodes to participate in
the federation quorum signing protocol.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import nacl.signing
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from api.auth import RequireIngestScope
from api.deps import DBSession
from api.models.document import DocCommit
from protocol.federation.identity import FEDERATION_DOMAIN_TAG, FederationRegistry
from protocol.federation.quorum import (
    _build_federation_vote_message,
    serialize_vote_message,
)
from protocol.hashes import hash_bytes
from protocol.timestamps import current_timestamp


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/federation", tags=["federation"])


def _env_flag_enabled(name: str) -> bool:
    """Return True when an environment flag is enabled with common truthy values.

    This is a shared utility to ensure consistent boolean parsing across the codebase.
    """
    return os.environ.get(name, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _guardian_enabled() -> bool:
    """Return True when Guardian replication is enabled."""
    return _env_flag_enabled("OLYMPUS_GUARDIAN_ENABLED")


def _get_guardian_registry() -> FederationRegistry | None:
    """Load the Guardian federation registry from the configured path."""
    if not _guardian_enabled():
        return None

    registry_path = os.environ.get(
        "OLYMPUS_GUARDIAN_REGISTRY_PATH",
        "examples/federation_registry.json",
    )

    try:
        return FederationRegistry.from_file(registry_path)
    except Exception as exc:
        logger.error("Failed to load Guardian registry from %s: %s", registry_path, exc)
        return None


def _get_local_signing_key() -> nacl.signing.SigningKey | None:
    """Get the local node's Ed25519 signing key."""
    signing_key_hex = os.environ.get("OLYMPUS_INGEST_SIGNING_KEY")
    if not signing_key_hex:
        return None

    try:
        signing_key_bytes = bytes.fromhex(signing_key_hex)
        if len(signing_key_bytes) != 32:
            logger.error("OLYMPUS_INGEST_SIGNING_KEY must be 32 bytes (64 hex chars)")
            return None
        return nacl.signing.SigningKey(signing_key_bytes)
    except Exception as exc:
        logger.error("Failed to parse OLYMPUS_INGEST_SIGNING_KEY: %s", exc)
        return None


def _get_local_node_id(registry: FederationRegistry) -> str | None:
    """Determine the local node's ID by matching the signing key's public key."""
    signing_key = _get_local_signing_key()
    if signing_key is None:
        return None

    local_pubkey = signing_key.verify_key.encode()

    for node in registry.nodes:
        if node.pubkey == local_pubkey:
            return node.node_id

    return None


class SignHeaderRequest(BaseModel):
    """Request body for the sign-header endpoint."""

    domain: str = Field(..., description="Federation domain tag")
    node_id: str = Field(..., description="Requesting node's ID")
    event_id: str = Field(..., description="Deterministic event identifier")
    shard_id: str = Field(..., description="Shard identifier")
    entry_seq: int = Field(..., description="Consensus height")
    round_number: int = Field(..., description="Consensus round")
    shard_root: str = Field(..., description="Header hash")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    epoch: int = Field(..., description="Federation registry epoch")
    validator_set_hash: str = Field(..., description="Membership hash")
    header: dict[str, Any] = Field(..., description="Full shard header for fork detection")


class SignHeaderResponse(BaseModel):
    """Response body for the sign-header endpoint."""

    node_id: str = Field(..., description="Signing node's ID")
    signature: str = Field(..., description="Hex-encoded Ed25519 signature")


class ForkEvidenceResponse(BaseModel):
    """Response body when fork is detected."""

    fork_detected: bool = True
    shard_id: str
    seq: int
    local_header_hash: str
    remote_header_hash: str
    detected_at: str


@router.post("/sign-header", response_model=SignHeaderResponse)
async def sign_header(
    request: SignHeaderRequest,
    _api_key: RequireIngestScope,
    db: DBSession,
) -> SignHeaderResponse:
    """Sign a shard header on behalf of this Guardian node.

    This endpoint:
    1. Verifies the request domain matches the federation vote domain
    2. Checks if the shard_root matches the local node's current committed root
    3. If roots match, signs and returns the signature
    4. If roots differ, returns a 409 Conflict with fork evidence

    Args:
        request: The FederationVoteMessage and header to sign.

    Returns:
        NodeSignature with this node's signature.

    Raises:
        HTTPException 503: If Guardian replication is not enabled.
        HTTPException 409: If a fork is detected (root mismatch).
        HTTPException 500: If signing fails.
    """
    if not _guardian_enabled():
        raise HTTPException(
            status_code=503,
            detail="Guardian replication is not enabled on this node",
        )

    registry = _get_guardian_registry()
    if registry is None:
        raise HTTPException(
            status_code=503,
            detail="Guardian registry not configured",
        )

    local_node_id = _get_local_node_id(registry)
    if local_node_id is None:
        raise HTTPException(
            status_code=503,
            detail="Local node not found in Guardian registry",
        )

    signing_key = _get_local_signing_key()
    if signing_key is None:
        raise HTTPException(
            status_code=503,
            detail="Local signing key not configured",
        )

    # Verify domain tag
    if request.domain != FEDERATION_DOMAIN_TAG:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain tag: expected {FEDERATION_DOMAIN_TAG}",
        )

    header = request.header
    if "header_hash" not in header:
        raise HTTPException(
            status_code=400,
            detail="Header must include header_hash",
        )

    # Verify the shard_root in the request matches the header_hash
    if request.shard_root != header.get("header_hash"):
        raise HTTPException(
            status_code=400,
            detail="shard_root does not match header.header_hash",
        )

    # Fork detection: compare the incoming root_hash against the most recent
    # locally committed Merkle root for this shard.  If they differ we have
    # evidence of a split ledger and must refuse to co-sign.
    incoming_root = header.get("root_hash")
    if incoming_root is not None:
        result = await db.execute(
            select(DocCommit.merkle_root)
            .where(DocCommit.shard_id == request.shard_id)
            .order_by(DocCommit.epoch_timestamp.desc())
            .limit(1)
        )
        local_root = result.scalar_one_or_none()
        if local_root is not None and local_root != incoming_root:
            logger.warning(
                "Fork detected for shard %s at seq %d: local=%s remote=%s",
                request.shard_id,
                request.entry_seq,
                local_root,
                incoming_root,
            )
            raise HTTPException(
                status_code=409,
                detail=ForkEvidenceResponse(
                    shard_id=request.shard_id,
                    seq=request.entry_seq,
                    local_header_hash=local_root,
                    remote_header_hash=incoming_root,
                    detected_at=current_timestamp(),
                ).model_dump(),
            )

    # Build the canonical vote message for this node
    try:
        vote_msg = _build_federation_vote_message(header, local_node_id, registry)
    except (KeyError, ValueError) as exc:
        logger.warning("Invalid header for federation vote: %s", exc)
        raise HTTPException(
            status_code=400,
            detail="Invalid header for federation vote.",
        ) from exc

    # Sign the vote message
    try:
        vote_hash = hash_bytes(serialize_vote_message(vote_msg))
        signature = signing_key.sign(vote_hash).signature.hex()
    except Exception as exc:
        logger.exception("Failed to sign federation vote")
        raise HTTPException(
            status_code=500,
            detail="Failed to sign federation vote",
        ) from exc

    return SignHeaderResponse(
        node_id=local_node_id,
        signature=signature,
    )


@router.get("/status")
async def federation_status() -> dict[str, Any]:
    """Get the status of Guardian replication on this node.

    Returns:
        Status information including whether Guardian mode is enabled,
        the local node ID, and registry information.
    """
    if not _guardian_enabled():
        return {
            "guardian_enabled": False,
            "message": "Guardian replication is disabled",
        }

    registry = _get_guardian_registry()
    if registry is None:
        return {
            "guardian_enabled": True,
            "registry_loaded": False,
            "message": "Guardian registry not loaded",
        }

    local_node_id = _get_local_node_id(registry)

    return {
        "guardian_enabled": True,
        "registry_loaded": True,
        "local_node_id": local_node_id,
        "active_nodes": len(registry.active_nodes()),
        "quorum_threshold": registry.quorum_threshold(),
        "epoch": registry.epoch,
    }
