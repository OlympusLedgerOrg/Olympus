"""
Admin RBAC endpoints — platform statistics and customer management.

All endpoints require an API key with the ``"admin"`` scope.  The
``check_admin`` dependency enforces this before any route handler runs.

Routes:
    GET /api/admin/stats      — aggregated revenue and user metrics
    GET /api/admin/customers  — paginated customer list (newest first)
    GET /api/admin/customers/export — CSV download of all customers
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from api.auth import RateLimit, require_api_key_with_scope
from api.deps import DBSession
from api.models.purchase import Purchase
from api.models.user import User
from api.schemas.admin import CustomerListResponse, CustomerResponse, PlatformStatsResponse


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Reusable dependency — validates API key carries the "admin" scope.
RequireAdminScope = Annotated[object, Depends(require_api_key_with_scope("admin"))]


@router.get("/stats", response_model=PlatformStatsResponse)
async def get_platform_stats(
    db: DBSession,
    _admin: RequireAdminScope,
    _rl: RateLimit,
) -> PlatformStatsResponse:
    """Return aggregated platform metrics.

    MRR is computed dynamically as the average purchase price multiplied by the
    number of paid subscribers.  When no purchases exist yet the average
    defaults to zero, yielding an MRR of zero.

    Args:
        db: Injected async database session.

    Returns:
        MRR, total revenue, user count, and conversion rate.
    """
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users: int = total_users_result.scalar_one()

    total_revenue_result = await db.execute(select(func.coalesce(func.sum(Purchase.price), 0)))
    total_revenue: float = total_revenue_result.scalar_one()

    active_subs_result = await db.execute(
        select(func.count(User.id)).where(User.plan != "free")
    )
    active_subscriptions: int = active_subs_result.scalar_one()

    avg_price_result = await db.execute(
        select(func.coalesce(func.avg(Purchase.price), 0))
    )
    avg_price: float = avg_price_result.scalar_one()

    conversion_rate = (
        (active_subscriptions / total_users * 100) if total_users > 0 else 0.0
    )

    return PlatformStatsResponse(
        mrr=active_subscriptions * avg_price,
        total_revenue=total_revenue,
        user_count=total_users,
        conversion_rate=conversion_rate,
    )


@router.get("/customers", response_model=CustomerListResponse)
async def list_customers(
    db: DBSession,
    _admin: RequireAdminScope,
    _rl: RateLimit,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> CustomerListResponse:
    """Return a paginated list of customers ordered by creation date (newest first).

    Args:
        db: Injected async database session.
        page: Page number (1-indexed).
        per_page: Page size (1–100, default 20).

    Returns:
        Paginated customer list with total count.
    """
    count_result = await db.execute(select(func.count(User.id)))
    total: int = count_result.scalar_one()

    q = (
        select(User)
        .order_by(User.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    result = await db.execute(q)

    return CustomerListResponse(
        items=[CustomerResponse.model_validate(u) for u in result.scalars().all()],
        page=page,
        per_page=per_page,
        total=total,
    )


@router.get("/customers/export")
async def export_customers_csv(
    db: DBSession,
    _admin: RequireAdminScope,
    _rl: RateLimit,
) -> StreamingResponse:
    """Export all customers as a CSV file.

    Args:
        db: Injected async database session.

    Returns:
        Streaming CSV response with ``Content-Disposition: attachment``.
    """
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "email", "role", "plan", "created_at"])
    for u in users:
        created = u.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        writer.writerow([u.id, u.email, u.role, u.plan, created.isoformat()])
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=customers.csv"},
    )
