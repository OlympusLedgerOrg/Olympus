"""
Appeal endpoints.

POST /appeals   — file an appeal
GET  /appeals   — list all appeals
GET  /appeals/{id} — single appeal detail
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from api.auth import RequireAPIKey, RateLimit
from api.deps import DBSession
from api.models.appeal import Appeal, AppealStatus
from api.models.request import PublicRecordsRequest, RequestStatus
from api.schemas.appeal import AppealCreate, AppealResponse
from protocol.hashes import hash_bytes


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/appeals", tags=["appeals"])


def _hash_appeal(request_id: str, grounds: str, statement: str, filed_at: datetime) -> str:
    """Compute a deterministic BLAKE3 hash of the appeal content."""
    canonical = json.dumps(
        {
            "filed_at": filed_at.isoformat(),
            "grounds": grounds,
            "request_id": request_id,
            "statement": statement,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hash_bytes(canonical.encode("utf-8")).hex()


@router.post("", response_model=AppealResponse, status_code=status.HTTP_201_CREATED)
async def file_appeal(body: AppealCreate, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit):
    """File an appeal against an agency response.

    Rejects the appeal if the underlying request has already been fulfilled.
    Sets the request status to APPEALED on success.

    Args:
        body: Appeal payload.
        db: Injected async database session.

    Returns:
        Created appeal record.

    Raises:
        HTTPException 404: If the request is not found.
        HTTPException 409: If the request has already been fulfilled.
    """
    result = await db.execute(
        select(PublicRecordsRequest).where(PublicRecordsRequest.id == body.request_id)
    )
    req = result.scalars().first()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Request not found.", "code": "REQUEST_NOT_FOUND"},
        )
    if req.status == RequestStatus.FULFILLED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "Cannot appeal a fulfilled request.", "code": "REQUEST_FULFILLED"},
        )
    if req.status == RequestStatus.APPEALED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "An appeal has already been filed for this request.", "code": "APPEAL_EXISTS"},
        )

    filed_at = datetime.now(timezone.utc)
    commit_hash = _hash_appeal(body.request_id, body.grounds, body.statement, filed_at)

    appeal = Appeal(
        request_id=body.request_id,
        grounds=body.grounds,
        statement=body.statement,
        filed_at=filed_at,
        status=AppealStatus.UNDER_REVIEW.value,
        commit_hash=commit_hash,
    )
    db.add(appeal)
    req.status = RequestStatus.APPEALED.value
    await db.commit()
    await db.refresh(appeal)
    logger.info("Filed appeal %s for request %s", appeal.id, body.request_id)
    return appeal


@router.get("", response_model=list[AppealResponse])
async def list_appeals(db: DBSession, _rl: RateLimit):
    """Return all appeals.

    Args:
        db: Injected async database session.

    Returns:
        List of all appeal records.
    """
    result = await db.execute(select(Appeal))
    return list(result.scalars().all())


@router.get("/{appeal_id}", response_model=AppealResponse)
async def get_appeal(appeal_id: str, db: DBSession, _rl: RateLimit):
    """Return a single appeal by ID.

    Args:
        appeal_id: UUID of the appeal.
        db: Injected async database session.

    Returns:
        Appeal detail.

    Raises:
        HTTPException 404: If the appeal is not found.
    """
    result = await db.execute(select(Appeal).where(Appeal.id == appeal_id))
    appeal = result.scalars().first()
    if not appeal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Appeal not found.", "code": "APPEAL_NOT_FOUND"},
        )
    return appeal
