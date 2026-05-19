"""
Operator identity and API key management.

POST  /auth/operator/bootstrap  — first-boot: create first operator + mint key
GET   /auth/operator/me         — current operator identity + key info
POST  /auth/operator/keys       — mint an additional key for this operator

The chain this implements:

    Ed25519 identity (Operator.ed25519_public_key)
        ↓
    SBT/role (Operator.credential_id → KeyCredential)
        ↓
    API key minted for that operator (ApiKey.operator_id)
        ↓
    API requests authorised by key scope

Bootstrap flow (first boot only):

    1.  ``make dev`` prints OLYMPUS_BOOTSTRAP_KEY to stdout (dev auto-gen).
    2.  ``POST /auth/operator/bootstrap`` with ``X-Bootstrap-Key`` header.
    3.  Server verifies key, checks no operators exist, creates Operator + ApiKey.
    4.  Response contains the raw API key — copy it immediately.
    5.  Use the new key for all subsequent requests; bootstrap key is now inert.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request, status
from sqlalchemy import func, select

from api.auth import RateLimit, RequireAPIKey, _hash_key
from api.deps import DBSession
from api.models.api_key import ApiKey
from api.models.operator import Operator
from api.schemas.operator import (
    OPERATOR_DEFAULT_SCOPES,
    OperatorBootstrapRequest,
    OperatorBootstrapResponse,
    OperatorKeyMintRequest,
    OperatorKeyResponse,
    OperatorMeResponse,
    OperatorResponse,
)
from protocol.log_sanitization import sanitize_for_log


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/operator", tags=["operator"])

_BOOTSTRAP_EXPIRY = "2099-01-01T00:00:00Z"


# ── helpers ───────────────────────────────────────────────────────────────────


def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_expiry(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into a naive UTC datetime.

    Inputs with an explicit offset (e.g. ``2026-01-01T00:00:00+05:00``) are
    converted to the equivalent UTC instant before tzinfo is stripped; otherwise
    a 5h offset would silently mean a 5h shift in stored expiry.  Timezone-naive
    inputs are rejected so the caller is never quietly trusted on locality.
    """
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("expires_at must include a timezone offset (e.g. 'Z').")
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"detail": f"Invalid expires_at: {value}", "code": "INVALID_EXPIRY"},
        ) from exc


def _mint_key(
    *,
    operator_id: str,
    ed25519_public_key: str,
    credential_id: str | None,
    name: str,
    scopes: list[str],
    expires_at: datetime,
) -> tuple[str, ApiKey]:
    """Create a raw key + ApiKey record.  Raw key is returned once."""
    raw = secrets.token_hex(32)
    key_hash = _hash_key(raw)
    record = ApiKey(
        id=str(uuid.uuid4()),
        user_id=None,  # operator keys are not user-account-bound
        operator_id=operator_id,
        ed25519_public_key=ed25519_public_key,
        credential_id=credential_id,
        key_hash=key_hash,
        name=name,
        scopes=json.dumps(scopes),
        expires_at=expires_at,
        created_at=_naive_utc(),
    )
    return raw, record


def _check_bootstrap_key(x_bootstrap_key: str | None) -> None:
    """Verify the bootstrap key or allow without one in dev mode."""
    expected = os.environ.get("OLYMPUS_BOOTSTRAP_KEY", "")

    # Dev mode: allow without a key (the server printed one at startup anyway).
    if os.environ.get("OLYMPUS_ENV", "production") == "development":
        if not expected:
            return  # auto-generated bootstrap; any value (or none) is fine in dev
        # If a key IS set even in dev, still verify it for consistency.
        if x_bootstrap_key and secrets.compare_digest(x_bootstrap_key, expected):
            return
        if not x_bootstrap_key:
            return  # dev: tolerate missing header
        # Wrong key in dev — still reject to catch copy-paste errors
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid bootstrap key.", "code": "BOOTSTRAP_INVALID"},
        )

    # Production: key must be set and must match.
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "detail": (
                    "Bootstrap is not configured.  Set OLYMPUS_BOOTSTRAP_KEY in the environment."
                ),
                "code": "BOOTSTRAP_NOT_CONFIGURED",
            },
        )
    if not x_bootstrap_key or not secrets.compare_digest(x_bootstrap_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid bootstrap key.", "code": "BOOTSTRAP_INVALID"},
        )


# ── endpoints ─────────────────────────────────────────────────────────────────


@router.post(
    "/bootstrap",
    response_model=OperatorBootstrapResponse,
    status_code=status.HTTP_201_CREATED,
    summary="First-boot: create the first operator identity and mint an API key",
)
async def bootstrap_operator(
    body: OperatorBootstrapRequest,
    db: DBSession,
    _rl: RateLimit,
    x_bootstrap_key: str | None = Header(None, alias="x-bootstrap-key"),
) -> OperatorBootstrapResponse:
    """Create the first Operator identity and return a minted API key.

    This endpoint:
    - Is only callable when **no operators exist yet** (first-boot guard).
    - Requires ``X-Bootstrap-Key`` matching ``OLYMPUS_BOOTSTRAP_KEY``.
      In ``OLYMPUS_ENV=development`` the header is optional (bootstrap key
      is printed to the console at startup).
    - Creates an ``Operator`` record binding the Ed25519 public key to a role.
    - Mints a full-scope API key bound to that operator.
    - Returns the raw API key **once** — store it immediately.

    After the first operator is created, subsequent operators should be added
    by an authenticated admin via ``POST /auth/operator/keys``.
    """
    _check_bootstrap_key(x_bootstrap_key)

    # First-boot guard: reject if any operator already exists.
    count_result = await db.execute(select(func.count()).select_from(Operator))
    if (count_result.scalar() or 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    "An operator already exists.  "
                    "Bootstrap is only permitted on first boot.  "
                    "Use POST /auth/operator/keys to mint additional keys."
                ),
                "code": "BOOTSTRAP_ALREADY_DONE",
            },
        )

    # Reject duplicate public key (shouldn't happen on first boot, but be safe).
    existing = await db.execute(
        select(Operator).where(Operator.ed25519_public_key == body.ed25519_public_key)
    )
    if existing.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": "An operator with this Ed25519 public key already exists.",
                "code": "OPERATOR_KEY_CONFLICT",
            },
        )

    now = _naive_utc()
    operator = Operator(
        id=str(uuid.uuid4()),
        ed25519_public_key=body.ed25519_public_key,
        credential_id=None,  # SBT issued separately via POST /key/credential
        role=body.role,
        label=body.label,
        created_at=now,
    )
    db.add(operator)
    await db.flush()  # obtain operator.id before key creation

    expires_at = _parse_expiry(_BOOTSTRAP_EXPIRY)
    raw_key, key_record = _mint_key(
        operator_id=operator.id,
        ed25519_public_key=body.ed25519_public_key,
        credential_id=None,
        name=body.key_name,
        scopes=list(OPERATOR_DEFAULT_SCOPES),
        expires_at=expires_at,
    )
    db.add(key_record)
    await db.commit()
    await db.refresh(operator)

    logger.info(
        "Bootstrap: operator created operator_id=%s role=%s ed25519=%s",
        sanitize_for_log(operator.id),
        sanitize_for_log(operator.role),
        sanitize_for_log(body.ed25519_public_key[:16] + "..."),
    )

    return OperatorBootstrapResponse(
        operator=OperatorResponse.model_validate(operator),
        api_key=raw_key,
        key_id=key_record.id,
        scopes=list(OPERATOR_DEFAULT_SCOPES),
        expires_at=_BOOTSTRAP_EXPIRY,
        message=(
            "Operator created.  "
            "Save the api_key — it will not be shown again.  "
            "Issue an SBT credential via POST /key/credential to activate the role."
        ),
    )


@router.get(
    "/me",
    response_model=OperatorMeResponse,
    summary="Current operator identity and key metadata",
)
async def operator_me(
    request: Request,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> OperatorMeResponse:
    """Return the operator identity and key stats for the authenticated caller.

    Requires an operator-bound API key (created via bootstrap or mint-key).
    Returns 404 if the key is not operator-bound (legacy user key).
    """
    if not api_key.operator_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "detail": (
                    "This API key is not bound to an operator identity.  "
                    "Use POST /auth/operator/bootstrap to create an operator."
                ),
                "code": "NOT_OPERATOR_KEY",
            },
        )

    op_result = await db.execute(select(Operator).where(Operator.id == api_key.operator_id))
    operator = op_result.scalars().first()
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Operator not found.", "code": "OPERATOR_NOT_FOUND"},
        )

    # Count active keys for this operator
    count_result = await db.execute(
        select(func.count())
        .select_from(ApiKey)
        .where(ApiKey.operator_id == operator.id)
        .where(ApiKey.revoked_at.is_(None))
    )
    active_key_count = count_result.scalar() or 0

    # Fetch the current key record for name/scopes
    key_result = await db.execute(select(ApiKey).where(ApiKey.id == api_key.key_id))
    key_record = key_result.scalars().first()
    current_scopes = json.loads(key_record.scopes) if key_record else list(api_key.scopes)
    current_name = key_record.name if key_record else api_key.key_id

    return OperatorMeResponse(
        operator=OperatorResponse.model_validate(operator),
        current_key_id=api_key.key_id,
        current_key_name=current_name,
        current_key_scopes=current_scopes,
        active_key_count=active_key_count,
    )


@router.post(
    "/keys",
    response_model=OperatorKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Mint an additional API key for this operator",
)
async def mint_operator_key(
    body: OperatorKeyMintRequest,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> OperatorKeyResponse:
    """Mint a new API key bound to the same operator identity as the caller.

    Requires an operator-bound API key.  The new key inherits the same
    ``operator_id`` and ``ed25519_public_key`` so it carries the same
    cryptographic identity.

    You can use this to rotate keys (mint new → revoke old) without losing
    the operator's SBT/role association.
    """
    if not api_key.operator_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Only operator-bound keys may mint additional operator keys.",
                "code": "NOT_OPERATOR_KEY",
            },
        )

    # Verify the operator is still active
    op_result = await db.execute(select(Operator).where(Operator.id == api_key.operator_id))
    operator = op_result.scalars().first()
    if operator is None or operator.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"detail": "Operator is revoked or not found.", "code": "OPERATOR_REVOKED"},
        )

    # Enforce scope subset: new key may not exceed the caller's own scopes.
    caller_key_result = await db.execute(select(ApiKey).where(ApiKey.id == api_key.key_id))
    caller_key = caller_key_result.scalars().first()
    caller_scopes: set[str] = (
        set(json.loads(caller_key.scopes)) if caller_key else set(api_key.scopes)
    )
    requested_scopes = set(body.scopes)
    forbidden = requested_scopes - caller_scopes
    if forbidden:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": f"Requested scopes exceed caller's own scopes: {sorted(forbidden)}",
                "code": "SCOPE_ESCALATION",
            },
        )

    expires_at = _parse_expiry(body.expires_at)
    raw_key, key_record = _mint_key(
        operator_id=operator.id,
        ed25519_public_key=operator.ed25519_public_key,
        credential_id=operator.credential_id,
        name=body.name,
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(key_record)
    await db.commit()

    logger.info(
        "Operator key minted: operator_id=%s key_id=%s name=%s",
        sanitize_for_log(operator.id),
        sanitize_for_log(key_record.id),
        sanitize_for_log(body.name),
    )

    return OperatorKeyResponse(
        api_key=raw_key,
        key_id=key_record.id,
        operator_id=operator.id,
        ed25519_public_key=operator.ed25519_public_key,
        name=body.name,
        scopes=body.scopes,
        expires_at=body.expires_at,
        message="New key minted.  Save the api_key — it will not be shown again.",
    )
