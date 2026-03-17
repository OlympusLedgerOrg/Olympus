"""
Pydantic v2 schemas for agency endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel


class AgencyBase(BaseModel):
    """Shared fields for agency read/write."""

    name: str
    short_name: str = ""
    level: str = "STATE"
    category: str = ""


class AgencyCreate(AgencyBase):
    """Request body for creating an agency."""


class AgencyResponse(AgencyBase):
    """Response representation of an agency."""

    id: str
    avg_response_days: float | None = None
    compliance_rate: float | None = None

    model_config = {"from_attributes": True}
