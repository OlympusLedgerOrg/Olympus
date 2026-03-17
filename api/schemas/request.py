"""
Pydantic v2 schemas for public-records request endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RequestCreate(BaseModel):
    """Request body for POST /requests."""

    subject: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    agency_id: str | None = None
    request_type: str = "NC_PUBLIC_RECORDS"
    date_from: datetime | None = None
    date_to: datetime | None = None
    response_format: str = "electronic"
    fee_waiver_basis: str | None = None
    priority: str = "STANDARD"


class RequestStatusUpdate(BaseModel):
    """Request body for PATCH /requests/{display_id}/status."""

    status: str
    note: str | None = None


class RequestResponse(BaseModel):
    """Full response representation of a public-records request."""

    id: str
    display_id: str
    subject: str
    description: str
    agency_id: str | None
    request_type: str
    status: str
    date_from: datetime | None
    date_to: datetime | None
    response_format: str
    fee_waiver_basis: str | None
    priority: str
    filed_at: datetime
    deadline: datetime | None
    fulfilled_at: datetime | None
    commit_hash: str
    shard_id: str

    model_config = {"from_attributes": True}
