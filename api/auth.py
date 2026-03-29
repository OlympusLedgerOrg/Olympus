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
import ipaddress
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import Annotated, Protocol, runtime_checkable

from fastapi import Depends, HTTPException, Request, status

from api.config import get_settings
from protocol.hashes import hash_bytes


logger = logging.getLogger(__name__)

_keys_loaded = False
_key_store: dict[str, _APIKeyRecord] = {}
_load_keys_lock = Lock()


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
    """Load API keys from OLYMPUS_FOIA_API_KEYS on first call.

    Thread-safe: a module-level lock prevents duplicate initialisation when
    multiple threads (e.g. Gunicorn threaded workers) call this concurrently.
    """
    global _keys_loaded
    with _load_keys_lock:
        if _keys_loaded:
            return
        _keys_loaded = True
        _load_keys_locked()


def _load_keys_locked() -> None:
    """Internal: load keys from env into _key_store. Must be called with _load_keys_lock held."""
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
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
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


def reload_keys() -> int:
    """Force a reload of API keys from OLYMPUS_FOIA_API_KEYS.

    Clears the current key store and re-reads from the environment variable.
    Returns the number of keys loaded after the reload.

    This allows hot key rotation and revocation without restarting the process.
    The reload is protected by the same lock as the initial load.
    """
    global _keys_loaded
    with _load_keys_lock:
        _key_store.clear()
        _keys_loaded = True
        _load_keys_locked()
    logger.info("API keys reloaded: %d key(s) active", len(_key_store))
    return len(_key_store)


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
        detail={
            "detail": "API key required. Provide via X-API-Key header or Authorization: Bearer.",
            "code": "AUTH_REQUIRED",
        },
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

    # If no keys are configured, allow dev-mode bypass ONLY in development.
    # In production (or any non-development environment) this is a fatal
    # misconfiguration — refuse to serve write requests.
    if not _key_store:
        _env = os.environ.get("OLYMPUS_ENV", "production")
        if _env == "development":
            logger.warning("No API keys configured — dev-mode auth bypass active")
            return _APIKeyRecord(
                key_id="dev",
                key_hash="",
                scopes={"read", "write"},
                expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            )
        logger.error(
            "OLYMPUS_FOIA_API_KEYS is empty and OLYMPUS_ENV != 'development'. "
            "Refusing unauthenticated write access. Configure API keys or set "
            "OLYMPUS_ENV=development for local testing."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "detail": "Authentication not configured. Contact the system administrator.",
                "code": "AUTH_NOT_CONFIGURED",
            },
        )

    raw_key = _extract_key(request)
    key_hash = _hash_key(raw_key)
    record = _constant_time_lookup(key_hash)

    if record is None:
        logger.warning(
            "Invalid API key attempt from %s", request.client.host if request.client else "unknown"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid API key.", "code": "AUTH_INVALID"},
        )

    if datetime.now(timezone.utc) >= record.expires_at:
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


# ── Rate Limit Backend Abstraction (M5) ──


@runtime_checkable
class RateLimitBackend(Protocol):
    """Interface for rate limit bucket storage."""

    def get(self, key: str) -> _TokenBucket | None:
        """Retrieve a rate limit bucket by key."""
        ...

    def set(self, key: str, bucket: _TokenBucket) -> None:
        """Store a rate limit bucket by key."""
        ...


class MemoryRateLimitBackend:
    """In-process memory rate limit backend (default).

    Stores buckets in an :class:`OrderedDict` with LRU eviction.
    Note: each worker process maintains its own bucket store, so the
    effective rate limit in multi-worker deployments is ``N * limit``
    for ``N`` workers.
    """

    def __init__(self, max_buckets: int = _RATE_LIMIT_MAX_BUCKETS) -> None:
        self._buckets: OrderedDict[str, _TokenBucket] = OrderedDict()
        self._lock = Lock()
        self._max_buckets = max_buckets

    def get(self, key: str) -> _TokenBucket | None:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                self._buckets.move_to_end(key)
            return bucket

    def set(self, key: str, bucket: _TokenBucket) -> None:
        with self._lock:
            self._buckets[key] = bucket
            self._buckets.move_to_end(key)
            while len(self._buckets) > self._max_buckets:
                self._buckets.popitem(last=False)

    @property
    def bucket_count(self) -> int:
        """Return the number of stored buckets (useful for testing)."""
        with self._lock:
            return len(self._buckets)


class RedisRateLimitBackend:
    """Redis-backed rate limit backend (stub).

    Provides a clear migration path for multi-worker deployments.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url

    def get(self, key: str) -> _TokenBucket | None:
        raise NotImplementedError(
            "Redis rate limit backend not yet implemented. Contributions welcome."
        )

    def set(self, key: str, bucket: _TokenBucket) -> None:
        raise NotImplementedError(
            "Redis rate limit backend not yet implemented. Contributions welcome."
        )


def _create_rate_limit_backend() -> MemoryRateLimitBackend | RedisRateLimitBackend:
    """Instantiate the configured rate limit backend."""
    settings = get_settings()
    backend_type = settings.rate_limit_backend.lower()

    if backend_type == "redis":
        if not settings.rate_limit_redis_url:
            raise ValueError("RATE_LIMIT_REDIS_URL must be set when RATE_LIMIT_BACKEND=redis")
        return RedisRateLimitBackend(settings.rate_limit_redis_url)

    if backend_type != "memory":
        raise ValueError(
            f"Unknown RATE_LIMIT_BACKEND: {backend_type!r}. Options: 'memory', 'redis'"
        )

    # Warn if memory backend is used with multiple workers
    workers = os.environ.get("WEB_CONCURRENCY", "")
    try:
        if workers and int(workers) > 1:
            logger.warning(
                "RATE_LIMIT_BACKEND=memory with WEB_CONCURRENCY=%s — "
                "rate limits are per-process; effective limit is %s× configured value. "
                "Consider switching to RATE_LIMIT_BACKEND=redis for shared state.",
                workers,
                workers,
            )
    except ValueError:
        pass

    return MemoryRateLimitBackend()


_rate_limit_backend: MemoryRateLimitBackend | RedisRateLimitBackend | None = None


def _get_backend() -> MemoryRateLimitBackend | RedisRateLimitBackend:
    """Lazy-initialise and return the rate limit backend singleton."""
    global _rate_limit_backend
    if _rate_limit_backend is None:
        _rate_limit_backend = _create_rate_limit_backend()
    return _rate_limit_backend


# ── IP Validation Helpers (H2) ──


def _is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    """Return True if *ip* falls within any of the given IP ranges.

    Each entry in *ranges* may be a single IP (``"10.0.0.1"``) or a CIDR
    network (``"172.16.0.0/12"``).  Mirrors the pattern used in
    ``api/ingest.py`` for trusted proxy validation.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in ranges:
        try:
            network = ipaddress.ip_network(r, strict=False)
            if addr in network:
                return True
        except ValueError:
            continue
    return False


def _get_client_ip(request: Request) -> str:
    """Extract client IP, only trusting ``X-Forwarded-For`` from known proxies.

    Only parses the ``X-Forwarded-For`` header when the direct peer IP is
    within the configured trusted proxy ranges (``OLYMPUS_TRUSTED_PROXY_IPS``).
    This prevents IP-spoofing attacks where a malicious client sets a fake
    header to bypass rate limiting and avoids bucket-eviction DoS via forged IPs.
    """
    peer_ip = request.client.host if request.client else "unknown"
    settings = get_settings()
    trusted = settings.trusted_proxy_ips

    if trusted and _ip_in_ranges(peer_ip, trusted):
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
            if _is_valid_ip(client_ip):
                return client_ip

    return peer_ip


async def rate_limit(request: Request) -> None:
    """FastAPI dependency — per-IP token-bucket rate limiter.

    Raises:
        HTTPException 429: If the IP has exceeded its rate limit.
    """
    ip = _get_client_ip(request)
    backend = _get_backend()
    bucket = backend.get(ip)

    if bucket is None:
        bucket = _TokenBucket(
            capacity=_RATE_LIMIT_CAPACITY,
            refill_rate=_RATE_LIMIT_REFILL,
            tokens=_RATE_LIMIT_CAPACITY,
            last_refill=monotonic(),
        )

    if not bucket.consume():
        backend.set(ip, bucket)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"detail": "Rate limit exceeded.", "code": "RATE_LIMITED"},
        )

    backend.set(ip, bucket)


RateLimit = Annotated[None, Depends(rate_limit)]


def _reset_rate_limit_backend_for_tests() -> None:  # pragma: no cover — test utility
    """Reset the rate limit backend singleton (test helper)."""
    global _rate_limit_backend
    _rate_limit_backend = None
