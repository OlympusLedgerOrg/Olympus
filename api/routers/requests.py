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
from sqlalchemy.exc import IntegrityError

from api.auth import RequireAPIKey, RateLimit
from api.deps import DBSession
from api.models.request import PublicRecordsRequest, RequestStatus
from api.schemas.request import RequestCreate, RequestResponse, RequestStatusUpdate
from api.services.deadline import compute_deadline, is_overdue
from api.services.hasher import hash_request
from api.services.shard import DEFAULT_SHARD_ID


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/requests", tags=["requests"])


def _escape_like(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_DISPLAY_ID_MAX_RETRIES = 5


async def _next_display_id(db) -> str:
    """Generate the next sequential display ID (e.g. ``"OLY-0042"``).

    Uses MAX(display_id) to find the current highest ID, avoiding collisions
    from concurrent row-count reads.
    """
    result = await db.execute(select(func.max(PublicRecordsRequest.display_id)))
    max_id = result.scalar()
    if max_id is None:
        return "OLY-0001"
    # Parse the numeric suffix and increment
    try:
        num = int(max_id.split("-")[1]) + 1
    except (IndexError, ValueError):
        num = 1
    return f"OLY-{num:04d}"


@router.post("", response_model=RequestResponse, status_code=status.HTTP_201_CREATED)
async def file_request(body: RequestCreate, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit):
    """File a new public-records or FOIA request.

    Computes a BLAKE3 commit hash over the canonical request content,
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

    last_exc: Exception | None = None
    for _attempt in range(_DISPLAY_ID_MAX_RETRIES):
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
        try:
            await db.commit()
            await db.refresh(req)
            logger.info("Filed request %s (commit=%s)", req.display_id, commit_hash)
            return req
        except IntegrityError as exc:
            last_exc = exc
            await db.rollback()
            logger.warning("display_id collision on %s, retrying", display_id)

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "detail": "Could not generate unique display_id after retries.",
            "code": "DISPLAY_ID_CONFLICT",
        },
    )


@router.get("", response_model=list[RequestResponse])
async def list_requests(
    db: DBSession,
    _rl: RateLimit,
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
        q = q.where(PublicRecordsRequest.subject.ilike(f"%{_escape_like(search)}%"))
    q = q.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(q)
    requests = list(result.scalars().all())

    # Compute overdue status in-memory for the response (no persistence)
    for req in requests:
        if is_overdue(req):
            req.status = RequestStatus.OVERDUE.value

    return requests


@router.get("/{display_id}", response_model=RequestResponse)
async def get_request(display_id: str, db: DBSession, _rl: RateLimit):
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

    # Compute overdue status in-memory for the response (no persistence)
    if is_overdue(req):
        req.status = RequestStatus.OVERDUE.value

    return req


@router.patch("/{display_id}/status", response_model=RequestResponse)
async def update_request_status(
    display_id: str,
    body: RequestStatusUpdate,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
):
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
    if body.status == RequestStatus.FULFILLED:
        req.fulfilled_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(req)
    logger.info("Updated request %s to status %s", display_id, body.status)
    return req
