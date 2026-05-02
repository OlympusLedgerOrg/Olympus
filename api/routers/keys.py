"""
Key credential endpoints (SBT-style, non-transferable).

POST   /key/credential       — issue a new credential anchored to the ledger
DELETE /key/credential/{id}  — revoke a credential
"""

from __future__ import annotations

import hmac as _hmac
import json
import logging
import os
import secrets
from datetime import datetime, timezone

from protocol.hashes import hash_bytes as _hash_bytes
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from api.auth import RateLimit, RequireAPIKey, reload_keys
from api.deps import DBSession
from api.models.credential import KeyCredential
from api.schemas.credential import CredentialCreate, CredentialResponse
from api.services.hasher import generate_commit_id
from protocol.log_sanitization import sanitize_for_log


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
    logger.info(
        "Issued credential %s for holder=%s",
        sanitize_for_log(str(cred.id)),
        sanitize_for_log(body.holder_key),
    )
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
    logger.info("Revoked credential %s", sanitize_for_log(str(credential_id)))


_VALID_SCOPES = {"read", "write", "ingest", "commit", "verify", "admin"}


class GenerateKeyRequest(BaseModel):
    name: str
    scopes: list[str] = ["ingest", "verify"]
    expires_at: str = "2099-01-01T00:00:00Z"

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, v: list[str]) -> list[str]:
        unknown = set(v) - _VALID_SCOPES
        if unknown:
            raise ValueError(f"unknown scopes: {', '.join(sorted(unknown))}")
        return v

    @field_validator("expires_at")
    @classmethod
    def _check_expires(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("expires_at must be ISO 8601, e.g. 2027-01-01T00:00:00Z")
        return v


class GenerateKeyResponse(BaseModel):
    raw_key: str
    key_hash: str
    key_id: str
    scopes: list[str]
    expires_at: str
    env_entry: str


@router.post("/admin/generate", response_model=GenerateKeyResponse, status_code=status.HTTP_201_CREATED)
async def admin_generate_key(request: Request, body: GenerateKeyRequest) -> GenerateKeyResponse:
    """Generate a new API key and return the raw key + env-var JSON entry.

    Protected by ``X-Admin-Key``. The raw key is returned once — the caller
    must store it. The ``env_entry`` field is the JSON blob to add to
    ``OLYMPUS_API_KEYS_JSON`` in your .env file, then call reload-keys.
    """
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin key not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        )
    provided = request.headers.get("x-admin-key", "")
    if not _hmac.compare_digest(provided, admin_key):
        logger.warning(
            "Admin generate-key rejected from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin key.")

    raw_key = secrets.token_hex(32)
    key_hash = _hash_bytes(raw_key.encode()).hex()
    entry = {
        "key_hash": key_hash,
        "key_id": body.name,
        "scopes": body.scopes,
        "expires_at": body.expires_at,
    }
    logger.info("Admin generated API key key_id=%s scopes=%s", sanitize_for_log(body.name), body.scopes)
    return GenerateKeyResponse(
        raw_key=raw_key,
        key_hash=key_hash,
        key_id=body.name,
        scopes=body.scopes,
        expires_at=body.expires_at,
        env_entry=json.dumps(entry),
    )


@router.post("/admin/reload-keys", status_code=status.HTTP_200_OK)
async def admin_reload_keys(request: Request, _rl: RateLimit) -> dict[str, object]:
    """Force a hot reload of FOIA API keys from the environment.

    Protected by a separate ``OLYMPUS_ADMIN_KEY`` secret.  This endpoint
    allows key rotation and revocation without restarting the API process.

    Raises:
        HTTPException 401: If the provided ``X-Admin-Key`` header is missing or wrong.
        HTTPException 503: If ``OLYMPUS_ADMIN_KEY`` is not configured on the server.
    """
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin key reload not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        )
    provided = request.headers.get("x-admin-key", "")
    if not _hmac.compare_digest(provided, admin_key):
        logger.warning(
            "Admin key reload rejected from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key.",
        )
    count = reload_keys()
    logger.info("Admin-triggered key reload: %d key(s) now active", count)
    return {"reloaded": True, "key_count": count}
