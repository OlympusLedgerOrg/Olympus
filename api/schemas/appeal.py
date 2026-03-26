"""
Pydantic v2 schemas for appeal endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AppealCreate(BaseModel):
    """Request body for POST /appeals."""

    request_id: str = Field(..., min_length=1, max_length=100)
    grounds: str = Field(..., min_length=1, max_length=100, description="AppealGrounds enum value.")
    statement: str = Field(..., min_length=1, max_length=10000)


class AppealResponse(BaseModel):
    """Response representation of an appeal."""

    id: str
    request_id: str
    grounds: str
    statement: str
    filed_at: datetime
    status: str
    commit_hash: str

    model_config = {"from_attributes": True}
