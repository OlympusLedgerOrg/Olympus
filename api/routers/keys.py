"""
Key credential endpoints (SBT-style, non-transferable).

POST   /key/credential       — issue a new credential anchored to the ledger
DELETE /key/credential/{id}  — revoke a credential
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from api.auth import RateLimit, RequireAPIKey, reload_keys
from api.deps import DBSession
from api.models.credential import KeyCredential
from api.schemas.credential import CredentialCreate, CredentialResponse
from api.services.hasher import generate_commit_id


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/key", tags=["keys"])


@router.post("/credential", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def issue_credential(
    body: CredentialCreate, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit
):
    """Issue a new SBT-style non-transferable credential.

    Anchors the credential issuance to the ledger via a generated commit_id.

    Args:
        body: Credential creation payload.
        db: Injected async database session.

    Returns:
        Created credential record.
    """
    commit_id = generate_commit_id()
    cred = KeyCredential(
        holder_key=body.holder_key,
        credential_type=body.credential_type,
        issuer=body.issuer,
        issued_at=datetime.now(timezone.utc),
        sbt_nontransferable=True,
        commit_id=commit_id,
    )
    db.add(cred)
    await db.commit()
    await db.refresh(cred)
    logger.info("Issued credential %s for holder=%s", cred.id, body.holder_key)
    return cred


@router.delete("/credential/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_credential(
    credential_id: str, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit
):
    """Revoke a credential by setting its revoked_at timestamp.

    The credential record is retained for audit purposes; Olympus is an
    append-only ledger and does not hard-delete records.

    Args:
        credential_id: UUID of the credential to revoke.
        db: Injected async database session.

    Raises:
        HTTPException 404: If the credential is not found.
        HTTPException 409: If the credential has already been revoked.
    """
    result = await db.execute(select(KeyCredential).where(KeyCredential.id == credential_id))
    cred = result.scalars().first()
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )
    if cred.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "Credential already revoked.", "code": "ALREADY_REVOKED"},
        )

    cred.revoked_at = datetime.now(timezone.utc)
    cred.revocation_commit_id = generate_commit_id()  # Anchor the revocation event
    await db.commit()
    logger.info("Revoked credential %s", credential_id)


@router.post("/admin/reload-keys", status_code=status.HTTP_200_OK)
async def admin_reload_keys(request: Request) -> dict[str, object]:
    """Force a hot reload of FOIA API keys from the environment.

    Protected by a separate ``OLYMPUS_ADMIN_KEY`` secret.  This endpoint
    allows key rotation and revocation without restarting the API process.

    Raises:
        HTTPException 401: If ``OLYMPUS_ADMIN_KEY`` is not set or doesn't match.
        HTTPException 503: If ``OLYMPUS_ADMIN_KEY`` is not configured.
    """
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"detail": "Admin key reload not configured.", "code": "ADMIN_NOT_CONFIGURED"},
        )
    provided = request.headers.get("x-admin-key", "")
    import hmac as _hmac  # noqa: PLC0415

    if not _hmac.compare_digest(provided, admin_key):
        logger.warning(
            "Admin key reload rejected from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid admin key.", "code": "ADMIN_AUTH_INVALID"},
        )
    count = reload_keys()
    logger.info("Admin-triggered key reload: %d key(s) now active", count)
    return {"reloaded": True, "key_count": count}
