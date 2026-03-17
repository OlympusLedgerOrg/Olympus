"""
Public-records request CRUD endpoints.

POST   /requests                         — file a new request
GET    /requests                         — paginated list with optional filters
GET    /requests/{display_id}            — full request detail
PATCH  /requests/{display_id}/status    — update status and anchor to ledger
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from api.deps import DBSession
from api.models.request import PublicRecordsRequest, RequestStatus
from api.schemas.request import RequestCreate, RequestResponse, RequestStatusUpdate
from api.services.deadline import compute_deadline, is_overdue
from api.services.hasher import hash_request
from api.services.shard import DEFAULT_SHARD_ID


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/requests", tags=["requests"])


async def _next_display_id(db) -> str:
    """Generate the next sequential display ID (e.g. ``"OLY-0042"``)."""
    result = await db.execute(select(func.count()).select_from(PublicRecordsRequest))
    count = (result.scalar() or 0) + 1
    return f"OLY-{count:04d}"


@router.post("", response_model=RequestResponse, status_code=status.HTTP_201_CREATED)
async def file_request(body: RequestCreate, db: DBSession):
    """File a new public-records or FOIA request.

    Computes a SHA-256 commit hash over the canonical request content,
    assigns the request to the default ledger shard, and calculates the
    statutory deadline.

    Args:
        body: Request payload.
        db: Injected async database session.

    Returns:
        Created request with commit_hash, display_id, and deadline.
    """
    filed_at = datetime.now(timezone.utc)
    agency_name = body.agency_id or ""
    commit_hash = hash_request(body.subject, body.description, agency_name, filed_at)
    deadline = compute_deadline(filed_at, body.request_type)
    display_id = await _next_display_id(db)

    req = PublicRecordsRequest(
        display_id=display_id,
        subject=body.subject,
        description=body.description,
        agency_id=body.agency_id,
        request_type=body.request_type,
        status=RequestStatus.PENDING.value,
        date_from=body.date_from,
        date_to=body.date_to,
        response_format=body.response_format,
        fee_waiver_basis=body.fee_waiver_basis,
        priority=body.priority,
        filed_at=filed_at,
        deadline=deadline,
        commit_hash=commit_hash,
        shard_id=DEFAULT_SHARD_ID,
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    logger.info("Filed request %s (commit=%s)", req.display_id, commit_hash)
    return req


@router.get("", response_model=list[RequestResponse])
async def list_requests(
    db: DBSession,
    status: str | None = Query(None),
    agency_id: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    """Return a paginated list of public-records requests.

    Args:
        db: Injected async database session.
        status: Optional status filter.
        agency_id: Optional agency UUID filter.
        search: Optional full-text search on subject.
        page: Page number (1-indexed).
        per_page: Page size.

    Returns:
        List of matching request summaries.
    """
    q = select(PublicRecordsRequest)
    if status:
        q = q.where(PublicRecordsRequest.status == status)
    if agency_id:
        q = q.where(PublicRecordsRequest.agency_id == agency_id)
    if search:
        q = q.where(PublicRecordsRequest.subject.ilike(f"%{search}%"))
    q = q.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(q)
    requests = list(result.scalars().all())

    # Auto-transition overdue requests
    for req in requests:
        if is_overdue(req):
            req.status = RequestStatus.OVERDUE.value
    if any(is_overdue(r) for r in requests):
        await db.commit()

    return requests


@router.get("/{display_id}", response_model=RequestResponse)
async def get_request(display_id: str, db: DBSession):
    """Return full details of a public-records request.

    Args:
        display_id: Human-readable identifier, e.g. ``"OLY-0042"``.
        db: Injected async database session.

    Returns:
        Full request detail.

    Raises:
        HTTPException 404: If the request is not found.
    """
    result = await db.execute(
        select(PublicRecordsRequest).where(PublicRecordsRequest.display_id == display_id)
    )
    req = result.scalars().first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": f"Request {display_id!r} not found.", "code": "REQUEST_NOT_FOUND"},
        )

    # Check for overdue transition
    if is_overdue(req):
        req.status = RequestStatus.OVERDUE.value
        await db.commit()

    return req


@router.patch("/{display_id}/status", response_model=RequestResponse)
async def update_request_status(display_id: str, body: RequestStatusUpdate, db: DBSession):
    """Update the status of a request and anchor the change to the ledger.

    Args:
        display_id: Human-readable identifier of the request.
        body: New status and optional note.
        db: Injected async database session.

    Returns:
        Updated request.

    Raises:
        HTTPException 404: If the request is not found.
    """
    result = await db.execute(
        select(PublicRecordsRequest).where(PublicRecordsRequest.display_id == display_id)
    )
    req = result.scalars().first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": f"Request {display_id!r} not found.", "code": "REQUEST_NOT_FOUND"},
        )

    req.status = body.status
    if body.status == RequestStatus.FULFILLED.value:
        req.fulfilled_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(req)
    logger.info("Updated request %s to status %s", display_id, body.status)
    return req
