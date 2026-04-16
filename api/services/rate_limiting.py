"""
Rate limiting for the Olympus ingest API.

This module provides rate limiting that integrates with the unified auth backend
from api.auth. Rate limits are applied per API key and per IP address for
ingest, commit, and verify operations.

H-3 Fix: This module delegates to the shared auth backend to ensure that
ingest and auth rate limiting share a single bucket store, eliminating the
dual-system vulnerability where separate rate limit stores could be exploited.
"""

from __future__ import annotations

import asyncio
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request

from api.auth import (
    _get_backend as _get_rate_limit_backend,
    _get_client_ip,
    _reset_rate_limit_backend_for_tests,
    _TokenBucket as _AuthTokenBucket,
)
from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.timestamps import current_timestamp


if TYPE_CHECKING:
    from protocol.ledger import Ledger, LedgerEntry


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rate limit policy configuration
# ---------------------------------------------------------------------------

# Default rate limits: (bucket_capacity, refill_tokens_per_second)
# These can be overridden per-action via _rate_limit_policy dict.
DEFAULT_RATE_LIMITS: dict[str, tuple[float, float]] = {
    "ingest": (100.0, 10.0),  # 100 burst, 10/sec refill
    "commit": (50.0, 5.0),  # 50 burst, 5/sec refill
    "verify": (200.0, 20.0),  # 200 burst, 20/sec refill
}

# Active rate limit policy (can be modified for tests)
_rate_limit_policy: dict[str, tuple[float, float]] = dict(DEFAULT_RATE_LIMITS)


def set_rate_limit_for_tests(action: str, capacity: float, refill_rate_per_second: float) -> None:
    """Override rate-limit policy for tests.

    Args:
        action: The action to set limits for (e.g., 'ingest', 'commit', 'verify').
        capacity: Maximum tokens in the bucket.
        refill_rate_per_second: Tokens added per second.
    """
    _rate_limit_policy[action] = (capacity, refill_rate_per_second)
    # H-3: Reset the shared auth backend so stale buckets don't survive
    _reset_rate_limit_backend_for_tests()


def reset_rate_limits_for_tests() -> None:
    """Reset rate limit policy to defaults and clear backend state."""
    global _rate_limit_policy
    _rate_limit_policy = dict(DEFAULT_RATE_LIMITS)
    _reset_rate_limit_backend_for_tests()


def consume_rate_limit(subject_type: str, subject: str, action: str) -> bool:
    """Consume a token for the given subject/action.

    H-3 Fix: Delegates to the shared auth backend (api.auth._get_backend)
    so that ingest and auth rate limiting share a single bucket store,
    eliminating the dual-system vulnerability.

    Args:
        subject_type: Type of subject ('api_key' or 'ip').
        subject: The subject identifier (key_id or IP address).
        action: The action being rate limited.

    Returns:
        True if the request is allowed, False if rate limited.
    """
    capacity, refill = _rate_limit_policy.get(
        action, DEFAULT_RATE_LIMITS.get(action, (100.0, 10.0))
    )

    # Use the *shared* auth backend instead of a separate ingest-local
    # bucket store. Composite key ensures action/subject isolation
    # within the single backend.
    backend = _get_rate_limit_backend()
    composite_key = f"ingest:{action}:{subject_type}:{subject}"

    # Use atomic consume to prevent TOCTOU races where concurrent requests
    # both read the same token count and both succeed.
    if hasattr(backend, "consume_atomic"):
        return backend.consume_atomic(composite_key, capacity, refill)

    # Fallback for backends without consume_atomic (e.g. Redis)
    bucket = backend.get(composite_key)

    if bucket is None:
        bucket = _AuthTokenBucket(
            capacity=capacity,
            refill_rate=refill,
            tokens=capacity,
            last_refill=monotonic(),
        )

    allowed = bucket.consume()
    backend.set(composite_key, bucket)
    return allowed


async def apply_rate_limits(
    request: Request,
    api_key_id: str,
    action: str,
    write_ledger: Ledger | None = None,
) -> None:
    """Apply rate limiting for API key and IP after authentication.

    This function is called after successful authentication to enforce
    per-key and per-IP rate limits for ingest operations.

    Rate limit checks are offloaded to a thread pool executor to avoid
    blocking the async event loop.

    Args:
        request: The incoming HTTP request.
        api_key_id: The authenticated API key ID.
        action: The action being performed (e.g., 'ingest', 'commit', 'verify').
        write_ledger: Optional ledger for audit events.

    Raises:
        HTTPException 429: If rate limit is exceeded.
    """
    client_ip = _get_client_ip(request)
    loop = asyncio.get_running_loop()

    # Run both rate-limit checks concurrently to halve DB latency
    key_allowed, ip_allowed = await asyncio.gather(
        loop.run_in_executor(None, consume_rate_limit, "api_key", api_key_id, action),
        loop.run_in_executor(None, consume_rate_limit, "ip", client_ip, action),
    )

    if not key_allowed:
        logger.warning(
            "rate_limit_hit",
            # Redact key_id to avoid logging sensitive API key identifiers
            extra={"dimension": "api_key", "key_id": "<redacted>", "action": action},
        )
        if write_ledger is not None:
            _append_security_audit_event(
                write_ledger,
                "rate_limit_hit",
                {
                    "dimension": "api_key",
                    "key_id": api_key_id,
                    "client_ip": client_ip,
                    "action": action,
                },
            )
        raise HTTPException(status_code=429, detail="Rate limit exceeded for API key")

    if not ip_allowed:
        logger.warning(
            "rate_limit_hit",
            extra={"dimension": "ip", "client_ip": client_ip, "action": action},
        )
        if write_ledger is not None:
            _append_security_audit_event(
                write_ledger,
                "rate_limit_hit",
                {"dimension": "ip", "key_id": api_key_id, "client_ip": client_ip, "action": action},
            )
        raise HTTPException(status_code=429, detail="Rate limit exceeded for IP address")


# ---------------------------------------------------------------------------
# Security audit logging
# ---------------------------------------------------------------------------


def _append_security_audit_event(
    write_ledger: Ledger, event: str, details: dict[str, Any]
) -> LedgerEntry:
    """Append a security audit event to the append-only ledger.

    Args:
        write_ledger: The ledger to append to.
        event: Event name (e.g., 'rate_limit_hit', 'api_key_registered').
        details: Event details dict.

    Returns:
        The created LedgerEntry.
    """
    payload = {
        "event": event,
        "timestamp": current_timestamp(),
        "details": details,
    }
    payload_hash = hash_bytes(document_to_bytes(canonicalize_document(payload))).hex()
    return write_ledger.append(
        record_hash=payload_hash,
        shard_id="audit.security",
        shard_root=payload_hash,
        canonicalization=canonicalization_provenance("application/json", CANONICAL_VERSION),
    )
