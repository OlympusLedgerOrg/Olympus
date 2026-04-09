"""
Pydantic v2 schemas for document commit and verify endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DocCommitRequest(BaseModel):
    """Request body for POST /doc/commit."""

    doc_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="BLAKE3 hex hash of the document (64 lowercase hex characters).",
    )
    request_id: str | None = Field(
        None,
        description=(
            "UUID of an existing public records request (from POST /requests or GET /requests). "
            "Links this document commit to that request. Returns 404 if the UUID is not found."
        ),
    )
    embargo_until: datetime | None = Field(None, description="Optional embargo expiry timestamp.")
    is_multi_recipient: bool = Field(
        False, description="True if multiple recipients share this commit."
    )


class DocCommitResponse(BaseModel):
    """Response body for POST /doc/commit."""

    commit_id: str
    doc_hash: str
    epoch: datetime
    shard_id: str
    merkle_root: str | None


class DocVerifyRequest(BaseModel):
    """Request body for POST /doc/verify.

    At least one of ``commit_id`` or ``doc_hash`` must be provided.
    """

    commit_id: str | None = Field(
        None,
        pattern=r"^0x[0-9a-f]{64}$",
        description="Hex commit identifier (0x + 64 hex characters).",
    )
    doc_hash: str | None = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="BLAKE3 hex hash to look up (64 lowercase hex characters).",
    )


class DocVerifyResponse(BaseModel):
    """Response body for POST /doc/verify."""

    verified: bool
    commit: DocCommitResponse | None = None
    merkle_proof: list[dict] | None = None
    zk_proof: dict | None = None
