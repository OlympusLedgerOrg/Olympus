"""
API key authentication for the Olympus FOIA backend.

Write endpoints (POST, PATCH, DELETE) require a valid API key.
Read endpoints (GET) are public — this is a transparency system.

API keys are stored as BLAKE3 hashes in the OLYMPUS_FOIA_API_KEYS environment
variable (JSON array). Raw keys are never stored.

Usage in routers:
    from api.auth import require_api_key

    @router.post("/something")
    async def create_thing(api_key: RequireAPIKey, db: DBSession):
        ...
"""

from __future__ import annotations

import hmac as _hmac_module  # used ONLY for hmac.compare_digest (timing-safe comparison)
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from time import monotonic
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from protocol.hashes import hash_bytes

logger = logging.getLogger(__name__)

_keys_loaded = False
_key_store: dict[str, _APIKeyRecord] = {}


@dataclass
class _APIKeyRecord:
    """Internal record for a hashed API key."""

    key_id: str
    key_hash: str
    scopes: set[str]
    expires_at: datetime


def _hash_key(raw_key: str) -> str:
    """BLAKE3 hash of raw API key material."""
    return hash_bytes(raw_key.encode("utf-8")).hex()


def _load_keys() -> None:
    """Load API keys from OLYMPUS_FOIA_API_KEYS on first call."""
    global _keys_loaded
    if _keys_loaded:
        return
    _keys_loaded = True

    raw = os.environ.get("OLYMPUS_FOIA_API_KEYS", "[]")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("OLYMPUS_FOIA_API_KEYS must be valid JSON") from exc

    for entry in entries:
        key_hash = entry.get("key_hash")
        if not key_hash:
            raise ValueError(
                "Each entry in OLYMPUS_FOIA_API_KEYS must have a 'key_hash' field "
                "(hex-encoded BLAKE3 hash of the raw API key)."
            )
        key_id = entry.get("key_id", "default")
        scopes = set(entry.get("scopes", ["read", "write"]))
        expires_at_str = entry.get("expires_at", "2099-01-01T00:00:00Z")
        try:
            expires_at = datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            ).astimezone(UTC)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"Invalid expires_at for key {key_id}: {expires_at_str}") from exc
        _key_store[key_hash] = _APIKeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
    if _key_store:
        logger.info("Loaded %d FOIA API key(s)", len(_key_store))


def _extract_key(request: Request) -> str:
    """Extract API key from X-API-Key header or Authorization: Bearer token."""
    header = request.headers.get("x-api-key")
    if header:
        return header
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"detail": "API key required. Provide via X-API-Key header or Authorization: Bearer.", "code": "AUTH_REQUIRED"},
    )


def _constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe string equality check.

    Wraps :func:`hmac.compare_digest` — this is a **constant-time
    comparison**, not an HMAC/MAC computation.  All cryptographic hashing
    in Olympus uses BLAKE3; this wrapper exists only to prevent timing
    oracle attacks on hash comparisons.
    """
    return _hmac_module.compare_digest(a, b)


def _constant_time_lookup(key_hash: str) -> _APIKeyRecord | None:
    """Constant-time key lookup to prevent timing oracle attacks."""
    found: _APIKeyRecord | None = None
    for stored_hash, record in _key_store.items():
        if _constant_time_equals(stored_hash, key_hash):
            found = record
    return found


async def require_api_key(request: Request) -> _APIKeyRecord:
    """FastAPI dependency — validates API key on write endpoints.

    Raises:
        HTTPException 401: Missing, invalid, or expired key.
        HTTPException 403: Key lacks 'write' scope.
    """
    _load_keys()

    # If no keys are configured, auth is disabled (dev mode)
    if not _key_store:
        return _APIKeyRecord(key_id="dev", key_hash="", scopes={"read", "write"}, expires_at=datetime(2099, 1, 1, tzinfo=UTC))

    raw_key = _extract_key(request)
    key_hash = _hash_key(raw_key)
    record = _constant_time_lookup(key_hash)

    if record is None:
        logger.warning("Invalid API key attempt from %s", request.client.host if request.client else "unknown")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid API key.", "code": "AUTH_INVALID"},
        )

    if datetime.now(UTC) >= record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "API key expired.", "code": "AUTH_EXPIRED"},
        )

    if "write" not in record.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"detail": "API key lacks 'write' scope.", "code": "AUTH_SCOPE"},
        )

    return record


# Typed dependency for use in route signatures
RequireAPIKey = Annotated[_APIKeyRecord, Depends(require_api_key)]


# ── Per-IP Rate Limiting ──


@dataclass
class _TokenBucket:
    """Simple token-bucket rate limiter."""

    capacity: float
    refill_rate: float
    tokens: float
    last_refill: float

    def consume(self) -> bool:
        now = monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.refill_rate)
        self.last_refill = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


# Configurable via environment
_RATE_LIMIT_CAPACITY = float(os.environ.get("OLYMPUS_FOIA_RATE_LIMIT_CAPACITY", "60"))
_RATE_LIMIT_REFILL = float(os.environ.get("OLYMPUS_FOIA_RATE_LIMIT_REFILL", "1.0"))
_RATE_LIMIT_MAX_BUCKETS = 10_000

_ip_buckets: OrderedDict[str, _TokenBucket] = OrderedDict()
_bucket_lock = Lock()


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For behind a proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    """FastAPI dependency — per-IP token-bucket rate limiter.

    Raises:
        HTTPException 429: If the IP has exceeded its rate limit.
    """
    ip = _get_client_ip(request)
    with _bucket_lock:
        bucket = _ip_buckets.get(ip)
        if bucket is not None:
            _ip_buckets.move_to_end(ip)
        else:
            while len(_ip_buckets) >= _RATE_LIMIT_MAX_BUCKETS:
                _ip_buckets.popitem(last=False)
            bucket = _TokenBucket(
                capacity=_RATE_LIMIT_CAPACITY,
                refill_rate=_RATE_LIMIT_REFILL,
                tokens=_RATE_LIMIT_CAPACITY,
                last_refill=monotonic(),
            )
            _ip_buckets[ip] = bucket

        if not bucket.consume():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"detail": "Rate limit exceeded.", "code": "RATE_LIMITED"},
            )


RateLimit = Annotated[None, Depends(rate_limit)]
