"""
Admin RBAC endpoints — platform statistics and customer management.

All endpoints require an API key with the ``"admin"`` scope.  The
``check_admin`` dependency enforces this before any route handler runs.

Routes:
    GET /api/admin/stats      — aggregated revenue and user metrics
    GET /api/admin/customers  — paginated customer list (newest first)
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from api.auth import RateLimit, require_api_key_with_scope
from api.deps import DBSession
from api.models.purchase import Purchase
from api.models.user import User
from api.schemas.admin import CustomerResponse, PlatformStatsResponse


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Reusable dependency — validates API key carries the "admin" scope.
RequireAdminScope = Annotated[object, Depends(require_api_key_with_scope("admin"))]

# Average revenue per paid subscription, used for MRR approximation.
_AVG_SUBSCRIPTION_PRICE = 500


@router.get("/stats", response_model=PlatformStatsResponse)
async def get_platform_stats(
    db: DBSession,
    _admin: RequireAdminScope,
    _rl: RateLimit,
) -> PlatformStatsResponse:
    """Return aggregated platform metrics.

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

    conversion_rate = (
        (active_subscriptions / total_users * 100) if total_users > 0 else 0.0
    )

    return PlatformStatsResponse(
        mrr=active_subscriptions * _AVG_SUBSCRIPTION_PRICE,
        total_revenue=total_revenue,
        user_count=total_users,
        conversion_rate=conversion_rate,
    )


@router.get("/customers", response_model=list[CustomerResponse])
async def list_customers(
    db: DBSession,
    _admin: RequireAdminScope,
    _rl: RateLimit,
) -> list[CustomerResponse]:
    """Return all customers ordered by creation date (newest first).

    Args:
        db: Injected async database session.

    Returns:
        List of customer records.
    """
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())
