"""
Pydantic v2 schemas for key-credential endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CredentialCreate(BaseModel):
    """Request body for POST /key/credential."""

    holder_key: str
    credential_type: str
    issuer: str


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

    model_config = {"from_attributes": True}
