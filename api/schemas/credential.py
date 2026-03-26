"""
Pydantic v2 schemas for key-credential endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CredentialCreate(BaseModel):
    """Request body for POST /key/credential."""

    holder_key: str = Field(..., min_length=1, max_length=512)
    credential_type: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    issuer: str = Field(..., min_length=1, max_length=500)


class CredentialResponse(BaseModel):
    """Response representation of a key credential."""

    id: str
    holder_key: str
    credential_type: str
    issued_at: datetime
    revoked_at: datetime | None
    issuer: str
    sbt_nontransferable: bool
    commit_id: str
    revocation_commit_id: str | None = None

    model_config = {"from_attributes": True}
