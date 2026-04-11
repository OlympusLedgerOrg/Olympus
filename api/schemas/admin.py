"""
Pydantic v2 schemas for admin endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class PlatformStatsResponse(BaseModel):
    """Aggregated platform metrics returned by ``GET /api/admin/stats``."""

    mrr: float
    total_revenue: float
    user_count: int
    conversion_rate: float


class CustomerResponse(BaseModel):
    """Customer record returned by ``GET /api/admin/customers``."""

    id: str
    email: str
    role: str
    plan: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CustomerListResponse(BaseModel):
    """Paginated list of customers returned by ``GET /api/admin/customers``."""

    items: list[CustomerResponse]
    page: int
    per_page: int
    total: int
