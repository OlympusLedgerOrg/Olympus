"""
User authentication and API key management.

POST  /auth/register       — create account + first API key
POST  /auth/login          — password → list of active API keys
POST  /auth/keys           — generate additional API key (requires auth)
GET   /auth/keys           — list caller's active keys
DELETE /auth/keys/{key_id} — revoke a key
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from api.auth import RateLimit, _extract_key, _hash_key
from api.deps import DBSession
from api.models.api_key import ApiKey
from api.models.user import User
from protocol.log_sanitization import sanitize_for_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_DEFAULT_SCOPES = ["ingest", "verify"]
_DEFAULT_EXPIRY = "2099-01-01T00:00:00Z"

# Scopes a new user is allowed to self-assign at registration. Privileged
# scopes (e.g. "admin", "write") must be granted out-of-band via the admin
# tooling and cannot be obtained simply by sending them in /auth/register.
_SELF_SERVICE_SCOPES = {"ingest", "verify", "read", "commit"}
# Superset of all known scope strings — used to reject typos / unknown values.
_VALID_SCOPES = {"read", "write", "ingest", "commit", "verify", "admin"}

# scrypt params — tuned for ~100ms on modest hardware
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 32


# ── password helpers ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_hex, dk_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p))
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ── key helpers ───────────────────────────────────────────────────────────────

def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_api_key(user_id: str, name: str, scopes: list[str], expires_at: datetime) -> tuple[str, ApiKey]:
    raw = secrets.token_hex(32)
    key_hash = _hash_key(raw)
    record = ApiKey(
        id=str(uuid.uuid4()),
        user_id=user_id,
        key_hash=key_hash,
        name=name,
        scopes=json.dumps(scopes),
        expires_at=expires_at.replace(tzinfo=None),
        created_at=_naive_utc(),
    )
    return raw, record


def _parse_expires(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid expires_at: {s!r}")


def _validate_scopes(requested: list[str], allowed: set[str], *, context: str) -> list[str]:
    """Validate scopes against the global allowlist and a caller-specific subset.

    Args:
        requested: Scopes the caller asked to assign to a new key.
        allowed:   Scopes the caller is permitted to grant in this context.
        context:   Short string used in error messages (e.g. "register", "create_key").

    Returns:
        A de-duplicated list of validated scopes (input order preserved).

    Raises:
        HTTPException 400: An unknown scope string was supplied.
        HTTPException 403: A known scope was requested that the caller cannot grant.
    """
    seen: set[str] = set()
    deduped: list[str] = []
    for s in requested:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    unknown = seen - _VALID_SCOPES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scope(s) in {context}: {', '.join(sorted(unknown))}",
        )
    forbidden = seen - allowed
    if forbidden:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Scope(s) not permitted in {context}: {', '.join(sorted(forbidden))}. "
                f"Allowed: {', '.join(sorted(allowed))}."
            ),
        )
    return deduped


# ── schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = "default"
    scopes: list[str] = _DEFAULT_SCOPES
    expires_at: str = _DEFAULT_EXPIRY


class LoginRequest(BaseModel):
    email: str
    password: str


class KeyCreateRequest(BaseModel):
    name: str = "default"
    scopes: list[str] = _DEFAULT_SCOPES
    expires_at: str = _DEFAULT_EXPIRY


class KeyInfo(BaseModel):
    id: str
    name: str
    scopes: list[str]
    expires_at: str
    created_at: str
    revoked: bool


class RegisterResponse(BaseModel):
    user_id: str
    email: str
    api_key: str
    key_id: str
    scopes: list[str]


class LoginResponse(BaseModel):
    user_id: str
    email: str
    keys: list[KeyInfo]


class KeyCreateResponse(BaseModel):
    api_key: str
    key_id: str
    name: str
    scopes: list[str]
    expires_at: str


# ── routes ────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: DBSession, _rl: RateLimit) -> RegisterResponse:
    """Create a new user account and issue a first API key."""
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalars().first():
        raise HTTPException(status_code=409, detail="Email already registered.")

    if len(body.password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters.")

    # Self-service registration may only assign non-privileged scopes.
    scopes = _validate_scopes(body.scopes, _SELF_SERVICE_SCOPES, context="register")

    user = User(
        id=str(uuid.uuid4()),
        email=body.email,
        password_hash=_hash_password(body.password),
        created_at=_naive_utc(),
    )
    db.add(user)
    await db.flush()

    expires = _parse_expires(body.expires_at)
    raw_key, key_record = _make_api_key(user.id, body.name, scopes, expires)
    db.add(key_record)
    await db.commit()

    logger.info("Registered user %s", sanitize_for_log(body.email))
    return RegisterResponse(
        user_id=user.id,
        email=user.email,
        api_key=raw_key,
        key_id=key_record.id,
        scopes=scopes,
    )


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, db: DBSession, _rl: RateLimit) -> LoginResponse:
    """Verify password and return the user's active API keys."""
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalars().first()

    # Always run verify to prevent timing oracle on email enumeration
    stored_hash = user.password_hash if user else f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${'00'*32}${'00'*32}"
    if not _verify_password(body.password, stored_hash) or not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    now = _naive_utc()
    keys_result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == user.id)
        .where(ApiKey.revoked_at.is_(None))
        .where(ApiKey.expires_at > now)
    )
    keys = keys_result.scalars().all()

    return LoginResponse(
        user_id=user.id,
        email=user.email,
        keys=[
            KeyInfo(
                id=k.id,
                name=k.name,
                scopes=json.loads(k.scopes),
                expires_at=k.expires_at.isoformat(),
                created_at=k.created_at.isoformat(),
                revoked=k.revoked_at is not None,
            )
            for k in keys
        ],
    )


@router.post("/keys", response_model=KeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_key(body: KeyCreateRequest, request: Request, db: DBSession, _rl: RateLimit) -> KeyCreateResponse:
    """Generate an additional API key for the authenticated user.

    The new key's scopes must be a subset of the caller's current key scopes
    (and members of the global allowlist) to prevent privilege escalation via
    self-minted keys.
    """
    user, caller_key = await _require_db_user_and_key(request, db)
    try:
        caller_scopes = set(json.loads(caller_key.scopes))
    except (TypeError, ValueError):
        caller_scopes = set()
    scopes = _validate_scopes(body.scopes, caller_scopes, context="create_key")
    expires = _parse_expires(body.expires_at)
    raw_key, key_record = _make_api_key(user.id, body.name, scopes, expires)
    db.add(key_record)
    await db.commit()
    return KeyCreateResponse(
        api_key=raw_key,
        key_id=key_record.id,
        name=key_record.name,
        scopes=scopes,
        expires_at=key_record.expires_at.isoformat(),
    )


@router.get("/keys", response_model=list[KeyInfo])
async def list_keys(request: Request, db: DBSession, _rl: RateLimit) -> list[KeyInfo]:
    """List active API keys for the authenticated user."""
    user = await _require_db_user(request, db)
    now = _naive_utc()
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == user.id)
        .where(ApiKey.revoked_at.is_(None))
        .where(ApiKey.expires_at > now)
    )
    return [
        KeyInfo(
            id=k.id,
            name=k.name,
            scopes=json.loads(k.scopes),
            expires_at=k.expires_at.isoformat(),
            created_at=k.created_at.isoformat(),
            revoked=False,
        )
        for k in result.scalars().all()
    ]


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(key_id: str, request: Request, db: DBSession, _rl: RateLimit) -> None:
    """Revoke one of the authenticated user's API keys."""
    user = await _require_db_user(request, db)
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id).where(ApiKey.user_id == user.id)
    )
    key = result.scalars().first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found.")
    if key.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Key already revoked.")
    key.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("Revoked key %s for user %s", sanitize_for_log(key_id), sanitize_for_log(user.id))


# ── internal helper ───────────────────────────────────────────────────────────

async def _require_db_user(request: Request, db: DBSession) -> User:
    """Look up the user who owns the incoming API key."""
    user, _ = await _require_db_user_and_key(request, db)
    return user


async def _require_db_user_and_key(request: Request, db: DBSession) -> tuple[User, ApiKey]:
    """Look up the user who owns the incoming API key, returning both records."""
    raw_key = _extract_key(request)
    key_hash = _hash_key(raw_key)
    now = _naive_utc()
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.key_hash == key_hash)
        .where(ApiKey.revoked_at.is_(None))
        .where(ApiKey.expires_at > now)
    )
    key_record = result.scalars().first()
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or expired API key.")
    user_result = await db.execute(select(User).where(User.id == key_record.user_id))
    user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired API key.")
    return user, key_record
