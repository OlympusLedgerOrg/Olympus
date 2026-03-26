"""
Pydantic v2 schemas for agency endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AgencyBase(BaseModel):
    """Shared fields for agency read/write."""

    name: str = Field(..., min_length=1, max_length=200)
    short_name: str = Field("", max_length=100)
    level: str = Field("STATE", max_length=50)
    category: str = Field("", max_length=100)


class AgencyCreate(AgencyBase):
    """Request body for creating an agency."""


class AgencyResponse(AgencyBase):
    """Response representation of an agency."""

    id: str
    avg_response_days: float | None = None
    compliance_rate: float | None = None

    model_config = {"from_attributes": True}
