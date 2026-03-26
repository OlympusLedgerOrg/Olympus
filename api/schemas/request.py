"""
Pydantic v2 schemas for public-records request endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from api.models.request import RequestStatus


class RequestCreate(BaseModel):
    """Request body for POST /requests."""

    subject: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=10000)
    agency_id: str | None = Field(None, max_length=100)
    request_type: str = Field("NC_PUBLIC_RECORDS", max_length=50)
    date_from: datetime | None = None
    date_to: datetime | None = None
    response_format: str = Field("electronic", max_length=128)
    fee_waiver_basis: str | None = Field(None, max_length=2000)
    priority: str = Field("STANDARD", max_length=50)


class RequestStatusUpdate(BaseModel):
    """Request body for PATCH /requests/{display_id}/status."""

    status: RequestStatus
    note: str | None = Field(None, max_length=2000)


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
