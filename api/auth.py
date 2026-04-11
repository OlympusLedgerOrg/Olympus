"""
API key authentication for the Olympus FOIA backend.

Write endpoints (POST, PATCH, DELETE) require a valid API key.
Read endpoints (GET) and verification endpoints are public — this is a
transparency system. Verification is a read-semantic operation regardless
of the HTTP method used.

API keys are loaded from OLYMPUS_API_KEYS_JSON (preferred) or OLYMPUS_FOIA_API_KEYS
(fallback) environment variable. Both should contain a JSON array. Raw keys are
never stored — only BLAKE3 hashes.

This module provides a unified authentication mechanism for all Olympus endpoints,
ensuring that key revocation works consistently across all routers.

Usage in routers:
    from api.auth import require_api_key, RequireIngestScope

    @router.post("/something")
    async def create_thing(api_key: RequireAPIKey, db: DBSession):
        ...

    @router.post("/ingest/records")
    async def ingest_records(api_key: RequireIngestScope):
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
from typing import Annotated, Any, Protocol, runtime_checkable

from fastapi import Depends, HTTPException, Request, status

from api.config import get_settings
from protocol.hashes import hash_bytes


logger = logging.getLogger(__name__)

_keys_loaded = False
_key_store: dict[str, _APIKeyRecord] = {}
_load_keys_lock = Lock()

# ── Module-level dev auth bypass detection ──
# Emit a one-time startup warning when the dev auth bypass is active so
# operators notice immediately if OLYMPUS_ALLOW_DEV_AUTH leaks to a
# non-development environment.
_env = os.environ.get("OLYMPUS_ENV", "production")
_allow_dev_auth = os.environ.get("OLYMPUS_ALLOW_DEV_AUTH") == "1"
if _env == "development" and _allow_dev_auth:
    logger.warning("DEV AUTH BYPASS ACTIVE — never enable OLYMPUS_ALLOW_DEV_AUTH=1 in production")
elif _allow_dev_auth:
    logger.error(
        "OLYMPUS_ALLOW_DEV_AUTH=1 is set but OLYMPUS_ENV=%s (not 'development'). "
        "The dev auth bypass is NOT active, but this flag should be removed "
        "from non-development environments.",
        _env,
    )


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
        _load_keys_locked()
        _keys_loaded = True


def _load_keys_locked() -> None:
    """Internal: load keys from env into _key_store. Must be called with _load_keys_lock held."""
    _load_keys_into(_key_store)


def _load_keys_into(target: dict[str, _APIKeyRecord]) -> None:
    """Parse API keys from environment and populate *target*.

    Checks OLYMPUS_API_KEYS_JSON first, then falls back to OLYMPUS_FOIA_API_KEYS
    so operators only need to configure one variable. This unified loading
    ensures that all authentication paths (FOIA routers and ingest endpoints)
    share the same canonical key store.

    Raises:
        ValueError: On JSON parse error or missing required fields.
    """
    # Prefer OLYMPUS_API_KEYS_JSON; fall back to OLYMPUS_FOIA_API_KEYS for consolidated config
    raw = os.environ.get("OLYMPUS_API_KEYS_JSON") or os.environ.get("OLYMPUS_FOIA_API_KEYS", "[]")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "OLYMPUS_API_KEYS_JSON (or OLYMPUS_FOIA_API_KEYS) must be valid JSON"
        ) from exc

    for entry in entries:
        key_hash = entry.get("key_hash")
        if not key_hash:
            raise ValueError(
                "Each entry in API keys config must have a 'key_hash' field "
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
        target[key_hash] = _APIKeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
    if target:
        logger.info("Loaded %d FOIA API key(s)", len(target))


def reload_keys() -> int:
    """Force a reload of API keys from environment.

    Checks OLYMPUS_API_KEYS_JSON first, then falls back to OLYMPUS_FOIA_API_KEYS.

    Loads keys into a temporary store first, then atomically replaces the
    live store only on success.  If loading fails, the existing keys remain
    active and the error is propagated to the caller.

    Returns the number of keys loaded after the reload.

    This allows hot key rotation and revocation without restarting the process.
    The reload is protected by the same lock as the initial load.
    """
    global _keys_loaded
    with _load_keys_lock:
        # Load into a temporary store so that a parse error does not leave
        # the live key store empty (clear-then-fail would lock out all callers).
        _tmp_store: dict[str, _APIKeyRecord] = {}
        _load_keys_into(_tmp_store)
        # Swap atomically only after successful load.
        _key_store.clear()
        _key_store.update(_tmp_store)
        _keys_loaded = True
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


def _constant_time_lookup(key_hash: str) -> tuple[_APIKeyRecord | None, bool]:
    """Constant-time key lookup to prevent timing oracle attacks.

    Returns:
        A tuple of ``(record, expired)`` where *record* is the matching
        :class:`_APIKeyRecord` or ``None``, and *expired* indicates whether the
        matched key has passed its expiration time.  The expiration check is
        performed inside the same constant-time loop so that an attacker cannot
        distinguish "valid key, not expired" from "valid key, expired" via
        response timing (RT-L2).
    """
    now = datetime.now(timezone.utc)
    found: _APIKeyRecord | None = None
    expired = False
    for stored_hash, record in _key_store.items():
        if _constant_time_equals(stored_hash, key_hash):
            found = record
            expired = now >= record.expires_at
    return found, expired


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
        if _env == "development" and _allow_dev_auth:
            logger.critical("No API keys configured — dev-mode auth bypass active")
            return _APIKeyRecord(
                key_id="dev",
                key_hash="",
                scopes={"read", "write"},
                expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            )
        logger.critical(
            "Authentication not configured. Refusing unauthenticated write access. "
            "Configure API keys or set OLYMPUS_ENV=development and "
            "OLYMPUS_ALLOW_DEV_AUTH=1 for local testing."
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
    record, expired = _constant_time_lookup(key_hash)

    if record is None:
        logger.warning(
            "Invalid API key attempt from %s", request.client.host if request.client else "unknown"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"detail": "Invalid API key.", "code": "AUTH_INVALID"},
        )

    if expired:
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


def require_api_key_with_scope(required_scope: str) -> Any:
    """Factory for creating scope-specific API key dependencies.

    This provides a unified authentication mechanism that replaces the duplicate
    auth logic that was previously in api/ingest.py. All authentication now flows
    through the same key store, ensuring that key revocation works consistently
    across all endpoints.

    Args:
        required_scope: The scope that the API key must have (e.g., 'write', 'ingest',
            'commit', 'verify').

    Returns:
        A FastAPI dependency function that validates API keys and checks the
        required scope.

    Usage:
        @router.post("/endpoint")
        async def my_endpoint(api_key: Annotated[_APIKeyRecord, Depends(require_api_key_with_scope("ingest"))]):
            ...
    """

    async def _require_scoped_key(request: Request) -> _APIKeyRecord:
        _load_keys()

        # If no keys are configured, allow dev-mode bypass ONLY in development.
        if not _key_store:
            if _env == "development" and _allow_dev_auth:
                logger.critical("No API keys configured — dev-mode auth bypass active")
                return _APIKeyRecord(
                    key_id="dev",
                    key_hash="",
                    scopes={"read", "write", "ingest", "commit", "verify"},
                    expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
                )
            logger.critical(
                "Authentication not configured. Refusing unauthenticated access. "
                "Configure API keys or set OLYMPUS_ENV=development and "
                "OLYMPUS_ALLOW_DEV_AUTH=1 for local testing."
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
        record, expired = _constant_time_lookup(key_hash)
        client_ip = _get_client_ip(request)

        if record is None:
            logger.warning(
                "Invalid API key attempt from %s (scope=%s)",
                client_ip,
                required_scope,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"detail": "Invalid API key.", "code": "AUTH_INVALID"},
            )

        if expired:
            logger.warning(
                "Expired API key attempt from %s (key_id=%s, scope=%s)",
                client_ip,
                record.key_id,
                required_scope,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"detail": "API key expired.", "code": "AUTH_EXPIRED"},
            )

        if required_scope not in record.scopes:
            logger.warning(
                "Scope denied for key %s from %s (required=%s, has=%s)",
                record.key_id,
                client_ip,
                required_scope,
                record.scopes,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "detail": f"API key lacks required scope: {required_scope}",
                    "code": "AUTH_SCOPE",
                },
            )

        return record

    return _require_scoped_key


# Pre-built dependencies for common ingest scopes
RequireIngestScope = Annotated[_APIKeyRecord, Depends(require_api_key_with_scope("ingest"))]
RequireCommitScope = Annotated[_APIKeyRecord, Depends(require_api_key_with_scope("commit"))]
RequireVerifyScope = Annotated[_APIKeyRecord, Depends(require_api_key_with_scope("verify"))]


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

    def consume_atomic(self, key: str, capacity: float, refill_rate: float) -> bool:
        """Atomically get-consume-set a rate limit bucket.

        Holds the lock across the entire get → consume → set sequence to
        prevent TOCTOU races where two concurrent requests both read the
        same token count and both succeed (H-4 in security audit).

        Returns True if the request is allowed, False if rate-limited.
        """
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                self._buckets.move_to_end(key)
            else:
                bucket = _TokenBucket(
                    capacity=capacity,
                    refill_rate=refill_rate,
                    tokens=capacity,
                    last_refill=monotonic(),
                )

            allowed = bucket.consume()

            self._buckets[key] = bucket
            self._buckets.move_to_end(key)
            while len(self._buckets) > self._max_buckets:
                self._buckets.popitem(last=False)

            return allowed

    @property
    def bucket_count(self) -> int:
        """Return the number of stored buckets (useful for testing)."""
        with self._lock:
            return len(self._buckets)


class RedisRateLimitBackend:
    """Redis-backed rate limit backend for multi-worker deployments.

    Stores token-bucket state in Redis hashes with automatic TTL expiry.
    Uses a Lua script for atomic consume operations to prevent TOCTOU races
    across workers.  The ``redis`` package is imported lazily so it remains
    an optional dependency.
    """

    _KEY_PREFIX = "olympus:rl:"
    _MIN_TTL_SECONDS = 60

    # Lua script: atomic token-bucket consume.
    # KEYS[1] = bucket hash key
    # ARGV[1] = capacity, ARGV[2] = refill_rate, ARGV[3] = now (unix ts), ARGV[4] = ttl
    _LUA_CONSUME = """\
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local tokens = tonumber(redis.call('HGET', key, 'tokens'))
local last_refill = tonumber(redis.call('HGET', key, 'last_refill'))

if tokens == nil or last_refill == nil then
    tokens = capacity
    last_refill = now
end

local elapsed = math.max(now - last_refill, 0)
tokens = math.min(capacity, tokens + elapsed * refill_rate)
last_refill = now

if tokens < 1.0 then
    redis.call('HSET', key, 'tokens', tostring(tokens),
               'last_refill', tostring(last_refill),
               'capacity', tostring(capacity),
               'refill_rate', tostring(refill_rate))
    redis.call('EXPIRE', key, ttl)
    return 0
end

tokens = tokens - 1.0
redis.call('HSET', key, 'tokens', tostring(tokens),
           'last_refill', tostring(last_refill),
           'capacity', tostring(capacity),
           'refill_rate', tostring(refill_rate))
redis.call('EXPIRE', key, ttl)
return 1
"""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: Any = None
        self._consume_script: Any = None

    def _get_client(self) -> Any:
        """Return (and lazily create) the Redis client."""
        if self._client is None:
            try:
                import redis  # noqa: PLC0415 — lazy optional import
            except ImportError:
                raise ImportError(
                    "The 'redis' package is required for RedisRateLimitBackend. "
                    "Install it with: pip install redis"
                ) from None
            self._client = redis.Redis.from_url(self._redis_url, decode_responses=True)
        return self._client

    def _prefixed(self, key: str) -> str:
        return f"{self._KEY_PREFIX}{key}"

    def _ttl_for(self, capacity: float, refill_rate: float) -> int:
        """Compute a reasonable TTL: time to fully refill × 2, min 60s."""
        if refill_rate <= 0:
            return self._MIN_TTL_SECONDS
        return max(int(capacity / refill_rate * 2), self._MIN_TTL_SECONDS)

    _MICROSECONDS_PER_SECOND = 1_000_000

    def _now_unix(self) -> float:
        """Get current time from Redis server for cross-worker consistency."""
        sec, usec = self._get_client().time()
        return float(sec) + float(usec) / self._MICROSECONDS_PER_SECOND

    def get(self, key: str) -> _TokenBucket | None:
        """Retrieve a token bucket from Redis."""
        data = self._get_client().hgetall(self._prefixed(key))
        if not data:
            return None
        try:
            return _TokenBucket(
                capacity=float(data["capacity"]),
                refill_rate=float(data["refill_rate"]),
                tokens=float(data["tokens"]),
                last_refill=float(data["last_refill"]),
            )
        except (KeyError, ValueError):
            return None

    def set(self, key: str, bucket: _TokenBucket) -> None:
        """Store a token bucket in Redis with TTL."""
        rkey = self._prefixed(key)
        client = self._get_client()
        client.hset(
            rkey,
            mapping={
                "tokens": str(bucket.tokens),
                "last_refill": str(bucket.last_refill),
                "capacity": str(bucket.capacity),
                "refill_rate": str(bucket.refill_rate),
            },
        )
        ttl = self._ttl_for(bucket.capacity, bucket.refill_rate)
        client.expire(rkey, ttl)

    def consume_atomic(self, key: str, capacity: float, refill_rate: float) -> bool:
        """Atomically consume a token via Lua script.

        The Lua script runs on the Redis server as a single atomic
        operation, preventing TOCTOU races across multiple workers.

        Returns True if the request is allowed, False if rate-limited.
        """
        client = self._get_client()
        if self._consume_script is None:
            self._consume_script = client.register_script(self._LUA_CONSUME)
        now = self._now_unix()
        ttl = self._ttl_for(capacity, refill_rate)
        result = self._consume_script(
            keys=[self._prefixed(key)],
            args=[str(capacity), str(refill_rate), str(now), str(ttl)],
        )
        return int(result) == 1

    @property
    def bucket_count(self) -> int:
        """Return an estimate of stored rate-limit keys."""
        client = self._get_client()
        count = 0
        cursor: int = 0
        while True:
            cursor, keys = client.scan(cursor=cursor, match=f"{self._KEY_PREFIX}*", count=500)
            count += len(keys)
            if int(cursor) == 0:
                break
        return count


def _create_rate_limit_backend() -> MemoryRateLimitBackend | RedisRateLimitBackend:
    """Instantiate the rate limit backend for the current configuration.

    Supports ``'memory'`` (default, in-process) and ``'redis'`` (shared
    across workers) backends.

    H-2 Fix: In production mode with multiple workers and memory backend,
    startup is blocked because the rate limiter would be essentially non-functional
    (each worker maintains independent buckets, so effective limit is N× configured).

    Raises:
        ValueError: If ``RATE_LIMIT_BACKEND`` is an unknown value, or if
            ``'redis'`` is selected but no ``RATE_LIMIT_REDIS_URL`` is set.
        RuntimeError: If in production mode with WEB_CONCURRENCY > 1 and
            RATE_LIMIT_BACKEND=memory.
    """
    settings = get_settings()
    backend_type = settings.rate_limit_backend.lower()

    if backend_type == "redis":
        if not settings.rate_limit_redis_url:
            raise ValueError(
                "RATE_LIMIT_BACKEND=redis requires RATE_LIMIT_REDIS_URL to be set "
                "(e.g. 'redis://localhost:6379/0')."
            )
        return RedisRateLimitBackend(settings.rate_limit_redis_url)

    if backend_type != "memory":
        raise ValueError(
            f"Unknown RATE_LIMIT_BACKEND: {backend_type!r}. Options: 'memory', 'redis'"
        )

    # H-2 Fix: Block startup if memory backend with multiple workers in production.
    # The memory backend is per-process, so with N workers the effective rate limit
    # is N× the configured value — essentially making rate limiting non-functional.
    env = os.environ.get("OLYMPUS_ENV", "production")
    workers_str = os.environ.get("WEB_CONCURRENCY", "")
    try:
        workers = int(workers_str) if workers_str else 1
    except ValueError:
        workers = 1

    if workers > 1 and env == "production":
        raise RuntimeError(
            f"RATE_LIMIT_BACKEND=memory is not effective with WEB_CONCURRENCY={workers}. "
            "Each worker maintains independent rate limit buckets, so the effective limit "
            f"would be {workers}× the configured value. "
            "Options: (1) Set WEB_CONCURRENCY=1, (2) Use a distributed rate limiter "
            "(RATE_LIMIT_BACKEND=redis), or (3) Set OLYMPUS_ENV=development "
            "to disable this check for local testing."
        )

    if workers > 1:
        # Non-production with multiple workers: warn but allow
        logger.warning(
            "RATE_LIMIT_BACKEND=memory with WEB_CONCURRENCY=%s — "
            "rate limits are per-process; effective limit is %s× configured value. "
            "Consider switching to RATE_LIMIT_BACKEND=redis.",
            workers,
            workers,
        )

    return MemoryRateLimitBackend()


_rate_limit_backend: MemoryRateLimitBackend | RedisRateLimitBackend | None = None


def _get_backend() -> MemoryRateLimitBackend | RedisRateLimitBackend:
    """Lazy-initialise and return the rate limit backend singleton."""
    global _rate_limit_backend
    if _rate_limit_backend is None:
        _rate_limit_backend = _create_rate_limit_backend()
    return _rate_limit_backend


# ── IP Validation Helpers (H2) ──

# Module-level flag set by _assert_xff_default_deny() at startup.
# When True, _get_client_ip() ignores X-Forwarded-For unconditionally.
_xff_disabled: bool = False


def _assert_xff_default_deny() -> None:
    """Disable XFF processing at startup when no trusted proxies are configured.

    When ``OLYMPUS_TRUSTED_PROXY_IPS`` is empty or unset there is no
    trustworthy proxy to read the ``X-Forwarded-For`` header from.  Setting
    the module-level ``_xff_disabled`` flag here (rather than re-checking on
    every request) makes the invariant explicit, is logged once at startup,
    and eliminates the per-request overhead of iterating an empty list.
    """
    global _xff_disabled
    settings = get_settings()
    if not settings.trusted_proxy_ips:
        _xff_disabled = True
        logger.info(
            "OLYMPUS_TRUSTED_PROXY_IPS is not configured — "
            "X-Forwarded-For processing is disabled. "
            "All client IPs are taken from the direct connection peer. "
            "Set OLYMPUS_TRUSTED_PROXY_IPS to enable XFF-based IP extraction."
        )


def _is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _normalize_ip(ip: str) -> str:
    """Normalize IPv4-mapped IPv6 addresses to plain IPv4.

    Ensures that ::ffff:1.2.3.4 and 1.2.3.4 map to the same rate-limit
    bucket key, preventing double-bucket bypass.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
    except ValueError:
        pass
    return ip


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    """Return True if *ip* falls within any of the given IP ranges.

    Each entry in *ranges* may be a single IP (``"10.0.0.1"``) or a CIDR
    network (``"172.16.0.0/12"``).  Mirrors the pattern used in
    ``api/ingest.py`` for trusted proxy validation.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
    except ValueError:
        return False
    for r in ranges:
        try:
            network = ipaddress.ip_network(r, strict=False)
            if (
                isinstance(network, ipaddress.IPv6Network)
                and network.network_address.ipv4_mapped is not None
            ):
                mapped_network_address = network.network_address.ipv4_mapped
                prefixlen = max(network.prefixlen - 96, 0)
                network = ipaddress.ip_network(
                    f"{mapped_network_address}/{prefixlen}", strict=False
                )
            if addr in network:
                return True
        except ValueError:
            continue
    return False


def _is_overly_broad_proxy_range(range_expr: str) -> bool:
    """Return True for CIDRs that trust all IPv4/IPv6 addresses."""
    try:
        network = ipaddress.ip_network(range_expr, strict=False)
    except ValueError:
        logger.warning("Ignoring invalid trusted proxy CIDR/IP expression: %s", range_expr)
        return False
    return network.prefixlen == 0


def _get_client_ip(request: Request) -> str:
    """Extract client IP, only trusting ``X-Forwarded-For`` from known proxies.

    Only parses the ``X-Forwarded-For`` header when the direct peer IP is
    within the configured trusted proxy ranges (``OLYMPUS_TRUSTED_PROXY_IPS``).
    This prevents IP-spoofing attacks where a malicious client sets a fake
    header to bypass rate limiting and avoids bucket-eviction DoS via forged IPs.

    When ``_xff_disabled`` is True (set by :func:`_assert_xff_default_deny` at
    startup), the header is ignored entirely and the direct peer IP is returned.
    """
    peer_ip = request.client.host if request.client else "unknown"
    if _xff_disabled:
        return _normalize_ip(peer_ip)
    settings = get_settings()
    trusted = settings.trusted_proxy_ips

    if any(_is_overly_broad_proxy_range(proxy_range) for proxy_range in trusted):
        logger.error(
            "Ignoring X-Forwarded-For because OLYMPUS_TRUSTED_PROXY_IPS contains an overly "
            "broad range (0.0.0.0/0 or ::/0), which allows client IP spoofing."
        )
        return _normalize_ip(peer_ip)

    if trusted and _ip_in_ranges(peer_ip, trusted):
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
            if _is_valid_ip(client_ip):
                return _normalize_ip(client_ip)

    return _normalize_ip(peer_ip)


async def rate_limit(request: Request) -> None:
    """FastAPI dependency — per-IP token-bucket rate limiter.

    Raises:
        HTTPException 429: If the IP has exceeded its rate limit.
    """
    ip = _get_client_ip(request)
    backend = _get_backend()

    # Use atomic consume if available (MemoryRateLimitBackend) to prevent
    # TOCTOU races where concurrent requests both read the same token count.
    if hasattr(backend, "consume_atomic"):
        if not backend.consume_atomic(ip, _RATE_LIMIT_CAPACITY, _RATE_LIMIT_REFILL):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"detail": "Rate limit exceeded.", "code": "RATE_LIMITED"},
            )
        return

    # Fallback for other backends (e.g. Redis) that may not have consume_atomic
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


# ── Test Utilities ──


def _reset_auth_state_for_tests() -> None:  # pragma: no cover — test utility
    """Reset the API key store and reload state (test helper).

    This allows tests to start with a clean authentication state.
    """
    global _keys_loaded
    with _load_keys_lock:
        _key_store.clear()
        _keys_loaded = False


def _register_api_key_for_tests(
    api_key: str, key_id: str, scopes: set[str], expires_at: str
) -> None:  # pragma: no cover — test utility
    """Register an API key for testing purposes.

    This registers a raw API key (which will be hashed) into the unified key store.
    Use this in tests to set up authentication without environment variables.

    Args:
        api_key: The raw API key string.
        key_id: Identifier for the key.
        scopes: Set of scopes the key should have (e.g., {'read', 'write', 'ingest'}).
        expires_at: ISO 8601 expiration timestamp.
    """
    global _keys_loaded
    with _load_keys_lock:
        key_hash = _hash_key(api_key)
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
        except ValueError as exc:
            raise ValueError(f"Invalid expires_at: {expires_at}") from exc
        _key_store[key_hash] = _APIKeyRecord(
            key_id=key_id,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires,
        )
        _keys_loaded = True
