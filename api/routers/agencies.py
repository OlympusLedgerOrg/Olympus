"""
Agency CRUD endpoints.

GET /agencies        — list agencies with response-rate statistics
GET /agencies/{id}   — agency detail with linked requests
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from api.auth import RateLimit, RequireAPIKey
from api.deps import DBSession
from api.models.agency import Agency
from api.schemas.agency import AgencyCreate, AgencyResponse


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agencies", tags=["agencies"])


def _escape_like(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.post("", response_model=AgencyResponse, status_code=status.HTTP_201_CREATED)
async def create_agency(body: AgencyCreate, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit):
    """Create a new agency record.

    Args:
        body: Agency creation payload.
        db: Injected async database session.

    Returns:
        Created agency.
    """
    agency = Agency(
        name=body.name,
        short_name=body.short_name,
        level=body.level,
        category=body.category,
    )
    db.add(agency)
    await db.commit()
    await db.refresh(agency)
    return agency


@router.get("", response_model=list[AgencyResponse])
async def list_agencies(
    db: DBSession,
    _rl: RateLimit,
    level: str | None = Query(None),
    search: str | None = Query(None),
):
    """Return a list of agencies with computed statistics.

    Args:
        db: Injected async database session.
        level: Optional jurisdictional level filter.
        search: Optional name search.

    Returns:
        List of agencies.
    """
    q = select(Agency)
    if level:
        q = q.where(Agency.level == level)
    if search:
        q = q.where(Agency.name.ilike(f"%{_escape_like(search)}%"))

    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/{agency_id}", response_model=AgencyResponse)
async def get_agency(agency_id: str, db: DBSession, _rl: RateLimit):
    """Return full details of an agency.

    Args:
        agency_id: UUID of the agency.
        db: Injected async database session.

    Returns:
        Agency detail.

    Raises:
        HTTPException 404: If the agency is not found.
    """
    result = await db.execute(select(Agency).where(Agency.id == agency_id))
    agency = result.scalars().first()
    if not agency:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": f"Agency {agency_id!r} not found.", "code": "AGENCY_NOT_FOUND"},
        )
    return agency
