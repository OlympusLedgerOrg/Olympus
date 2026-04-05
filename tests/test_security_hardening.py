"""
Tests for Phase 3 & 4 security hardening.

Covers:
- H2: _get_client_ip() only trusts X-Forwarded-For from trusted proxies
- H3: Spoofed XFF from untrusted peers create exactly one rate-limit bucket
- M2: RequestStatusUpdate rejects arbitrary status strings
- M3: CredentialCreate enforces field length and pattern constraints
- H5: Upload size limit enforcement
- M10: Magic-byte MIME validation
- M11: huge_tree removal from lxml parser
"""

from __future__ import annotations

import json
import unittest.mock
from types import SimpleNamespace

import pytest

from api.auth import (
    MemoryRateLimitBackend,
    _get_client_ip,
    _ip_in_ranges,
    _is_overly_broad_proxy_range,
    _is_valid_ip,
    _normalize_ip,
    _TokenBucket,
)


# ── H2: _get_client_ip helpers ──────────────────────────────────────────────


class TestIsValidIp:
    """Unit tests for _is_valid_ip."""

    def test_valid_ipv4(self):
        assert _is_valid_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _is_valid_ip("::1") is True

    def test_invalid_ip(self):
        assert _is_valid_ip("not-an-ip") is False

    def test_empty_string(self):
        assert _is_valid_ip("") is False

    def test_cidr_not_valid_as_ip(self):
        assert _is_valid_ip("10.0.0.0/8") is False


# ── M1: IPv4-mapped IPv6 normalization ───────────────────────────────────────


class TestNormalizeIp:
    """Unit tests for _normalize_ip."""

    def test_ipv4_mapped_ipv6_normalized_to_ipv4(self):
        assert _normalize_ip("::ffff:1.2.3.4") == "1.2.3.4"

    def test_plain_ipv4_unchanged(self):
        assert _normalize_ip("1.2.3.4") == "1.2.3.4"

    def test_plain_ipv6_unchanged(self):
        assert _normalize_ip("::1") == "::1"

    def test_invalid_ip_returned_unchanged(self):
        assert _normalize_ip("not-an-ip") == "not-an-ip"

    def test_get_client_ip_same_bucket_for_mapped_and_plain(self):
        """::ffff:10.0.0.1 and 10.0.0.1 should resolve to the same bucket key."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = []
            req_mapped = unittest.mock.MagicMock()
            req_mapped.client.host = "::ffff:10.0.0.1"
            req_mapped.headers = {}
            req_plain = unittest.mock.MagicMock()
            req_plain.client.host = "10.0.0.1"
            req_plain.headers = {}
            assert _get_client_ip(req_mapped) == _get_client_ip(req_plain)


class TestIpInRanges:
    """Unit tests for _ip_in_ranges."""

    def test_single_ip_match(self):
        assert _ip_in_ranges("10.0.0.1", ["10.0.0.1"]) is True

    def test_single_ip_no_match(self):
        assert _ip_in_ranges("10.0.0.2", ["10.0.0.1"]) is False

    def test_cidr_match(self):
        assert _ip_in_ranges("172.16.5.10", ["172.16.0.0/12"]) is True

    def test_cidr_no_match(self):
        assert _ip_in_ranges("192.168.1.1", ["172.16.0.0/12"]) is False

    def test_multiple_ranges(self):
        ranges = ["10.0.0.0/8", "172.16.0.0/12"]
        assert _ip_in_ranges("10.1.2.3", ranges) is True
        assert _ip_in_ranges("172.20.0.1", ranges) is True
        assert _ip_in_ranges("192.168.1.1", ranges) is False

    def test_invalid_ip_returns_false(self):
        assert _ip_in_ranges("not-an-ip", ["10.0.0.0/8"]) is False

    def test_invalid_range_skipped(self):
        # Invalid range entries are silently skipped
        assert _ip_in_ranges("10.0.0.1", ["bad-range", "10.0.0.0/8"]) is True

    def test_ipv4_mapped_ipv6_matches_ipv4_range(self):
        assert _ip_in_ranges("::ffff:127.0.0.1", ["127.0.0.0/8"]) is True


class TestTrustedProxyRangeValidation:
    """Unit tests for overly broad trusted-proxy CIDR detection."""

    def test_rejects_ipv4_any(self):
        assert _is_overly_broad_proxy_range("0.0.0.0/0") is True

    def test_rejects_ipv6_any(self):
        assert _is_overly_broad_proxy_range("::/0") is True

    def test_accepts_narrow_ranges(self):
        assert _is_overly_broad_proxy_range("10.0.0.0/8") is False
        assert _is_overly_broad_proxy_range("2001:db8::/32") is False


class TestGetClientIp:
    """Unit tests for _get_client_ip with trusted proxy validation."""

    def _make_request(self, peer_ip: str, xff: str | None = None):
        """Create a mock Request with the given peer IP and optional XFF header."""
        request = unittest.mock.MagicMock()
        request.client.host = peer_ip
        headers = {}
        if xff is not None:
            headers["x-forwarded-for"] = xff
        request.headers = headers
        return request

    def test_no_xff_returns_peer_ip(self):
        """Without X-Forwarded-For, always return peer IP."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = ["10.0.0.1"]
            request = self._make_request("192.168.1.1")
            assert _get_client_ip(request) == "192.168.1.1"

    def test_xff_from_untrusted_peer_ignored(self):
        """XFF from an untrusted peer IP should be ignored."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = ["10.0.0.1"]
            request = self._make_request("192.168.1.1", xff="1.2.3.4")
            assert _get_client_ip(request) == "192.168.1.1"

    def test_xff_from_trusted_peer_used(self):
        """XFF from a trusted proxy should return the client IP."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = ["10.0.0.1"]
            request = self._make_request("10.0.0.1", xff="203.0.113.50, 10.0.0.1")
            assert _get_client_ip(request) == "203.0.113.50"

    def test_xff_invalid_ip_from_trusted_peer_returns_peer(self):
        """If XFF contains an invalid IP, fall back to peer IP."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = ["10.0.0.1"]
            request = self._make_request("10.0.0.1", xff="not-valid")
            assert _get_client_ip(request) == "10.0.0.1"

    def test_no_trusted_proxies_configured(self):
        """With empty trusted proxy list, XFF is always ignored."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = []
            request = self._make_request("192.168.1.1", xff="1.2.3.4")
            assert _get_client_ip(request) == "192.168.1.1"

    def test_overly_broad_trusted_proxy_range_ignores_xff(self):
        """If trusted proxy range is global, fail closed to direct peer IP."""
        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = ["0.0.0.0/0"]
            request = self._make_request("198.51.100.10", xff="203.0.113.50, 198.51.100.10")
            assert _get_client_ip(request) == "198.51.100.10"


# ── H3: Bucket eviction DoS prevention ──────────────────────────────────────


class TestBucketEvictionDoS:
    """Verify that spoofed XFF from untrusted peers does not create many buckets."""

    def test_100_spoofed_xff_create_one_bucket(self):
        """100 requests with different XFF values from an untrusted peer
        should create exactly one bucket (keyed to the peer IP)."""
        backend = MemoryRateLimitBackend()

        with unittest.mock.patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.trusted_proxy_ips = []

            for i in range(100):
                request = unittest.mock.MagicMock()
                request.client.host = "192.168.1.100"
                request.headers = {"x-forwarded-for": f"10.0.0.{i}"}
                ip = _get_client_ip(request)

                bucket = backend.get(ip)
                if bucket is None:
                    from time import monotonic

                    bucket = _TokenBucket(
                        capacity=60.0, refill_rate=1.0, tokens=60.0, last_refill=monotonic()
                    )
                bucket.consume()
                backend.set(ip, bucket)

        # Only one bucket should exist — keyed to peer IP "192.168.1.100"
        assert backend.bucket_count == 1


# ── M5: Rate limit backend abstraction ──────────────────────────────────────


class TestRateLimitBackend:
    """Unit tests for MemoryRateLimitBackend."""

    def test_get_nonexistent_returns_none(self):
        backend = MemoryRateLimitBackend()
        assert backend.get("unknown") is None

    def test_set_and_get(self):
        from time import monotonic

        backend = MemoryRateLimitBackend()
        bucket = _TokenBucket(capacity=10, refill_rate=1, tokens=10, last_refill=monotonic())
        backend.set("ip1", bucket)
        assert backend.get("ip1") is bucket

    def test_eviction_on_overflow(self):
        from time import monotonic

        backend = MemoryRateLimitBackend(max_buckets=3)
        for i in range(5):
            bucket = _TokenBucket(capacity=10, refill_rate=1, tokens=10, last_refill=monotonic())
            backend.set(f"ip{i}", bucket)
        assert backend.bucket_count == 3
        # Oldest keys (ip0, ip1) should be evicted
        assert backend.get("ip0") is None
        assert backend.get("ip1") is None

    def test_redis_backend_raises_not_implemented(self):
        from api.auth import RedisRateLimitBackend

        backend = RedisRateLimitBackend("redis://localhost")
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            backend.get("key")
        with pytest.raises(NotImplementedError, match="not yet implemented"):
            from time import monotonic

            bucket = _TokenBucket(capacity=10, refill_rate=1, tokens=10, last_refill=monotonic())
            backend.set("key", bucket)

    def test_backend_factory_rejects_redis_configuration(self):
        from api.auth import _create_rate_limit_backend

        with unittest.mock.patch(
            "api.auth.get_settings",
            return_value=SimpleNamespace(rate_limit_backend="redis"),
        ):
            with pytest.raises(ValueError, match="Redis rate limit backend is not yet implemented"):
                _create_rate_limit_backend()

    def test_consume_atomic_prevents_double_consume(self):
        """Two threads with capacity=1 and refill=0 must allow exactly one request.

        Regression test for H-4 (TOCTOU race in rate limiter).  Without
        consume_atomic(), both threads could read tokens=1, both succeed,
        and both write tokens=0 — allowing two requests through.
        """
        import threading

        backend = MemoryRateLimitBackend()
        results: list[bool] = []
        barrier = threading.Barrier(2)

        def try_consume() -> None:
            barrier.wait()  # Synchronize both threads to maximize race window
            allowed = backend.consume_atomic("race-ip", capacity=1.0, refill_rate=0.0)
            results.append(allowed)

        t1 = threading.Thread(target=try_consume)
        t2 = threading.Thread(target=try_consume)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not t1.is_alive(), "Thread 1 timed out"
        assert not t2.is_alive(), "Thread 2 timed out"
        assert len(results) == 2
        assert results.count(True) == 1, (
            f"Expected exactly 1 allowed request, got {results.count(True)} (results={results})"
        )


@pytest.mark.asyncio
async def test_reload_keys_auth_independent_of_json_entry_order(
    monkeypatch: pytest.MonkeyPatch,
):
    """Reloaded API keys authenticate identically regardless of JSON entry order."""
    import api.auth as auth_module
    from protocol.hashes import hash_bytes

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)

    first_key = "first-key"
    second_key = "second-key"
    second_key_hash = hash_bytes(second_key.encode("utf-8")).hex()
    entries = [
        {"key_hash": hash_bytes(first_key.encode("utf-8")).hex(), "key_id": "first"},
        {"key_hash": second_key_hash, "key_id": "second"},
    ]

    request = unittest.mock.MagicMock()
    request.headers = {"x-api-key": second_key}
    request.client.host = "127.0.0.1"

    try:
        for ordered_entries in (entries, list(reversed(entries))):
            auth_module._keys_loaded = False
            auth_module._key_store.clear()
            monkeypatch.setenv("OLYMPUS_FOIA_API_KEYS", json.dumps(ordered_entries))
            auth_module.reload_keys()

            record = await auth_module.require_api_key(request)
            assert record.key_id == "second"
            assert record.key_hash == second_key_hash
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)


# ── M2: RequestStatusUpdate enum validation ─────────────────────────────────


class TestRequestStatusValidation:
    """Verify that RequestStatusUpdate rejects arbitrary status strings."""

    def test_valid_status_accepted(self):
        from api.schemas.request import RequestStatusUpdate

        update = RequestStatusUpdate(status="PENDING")
        assert update.status.value == "PENDING"

    def test_invalid_status_rejected(self):
        from pydantic import ValidationError

        from api.schemas.request import RequestStatusUpdate

        with pytest.raises(ValidationError):
            RequestStatusUpdate(status="arbitrary_value")


# ── M3: CredentialCreate field constraints ──────────────────────────────────


class TestCredentialCreateConstraints:
    """Verify that CredentialCreate enforces field constraints."""

    def test_valid_credential(self):
        from api.schemas.credential import CredentialCreate

        cred = CredentialCreate(
            holder_key="abc123",
            credential_type="journalist",
            issuer="NC DOJ",
        )
        assert cred.holder_key == "abc123"

    def test_empty_holder_key_rejected(self):
        from pydantic import ValidationError

        from api.schemas.credential import CredentialCreate

        with pytest.raises(ValidationError):
            CredentialCreate(holder_key="", credential_type="journalist", issuer="NC DOJ")

    def test_credential_type_rejects_special_chars(self):
        from pydantic import ValidationError

        from api.schemas.credential import CredentialCreate

        with pytest.raises(ValidationError):
            CredentialCreate(
                holder_key="abc",
                credential_type="invalid type!",
                issuer="NC DOJ",
            )

    def test_credential_type_max_length(self):
        from pydantic import ValidationError

        from api.schemas.credential import CredentialCreate

        with pytest.raises(ValidationError):
            CredentialCreate(
                holder_key="abc",
                credential_type="a" * 65,
                issuer="NC DOJ",
            )


# ── M14: Schema length constraints ─────────────────────────────────────────


class TestSchemaLengthConstraints:
    """Verify that schema fields have length constraints."""

    def test_agency_name_max_length(self):
        from pydantic import ValidationError

        from api.schemas.agency import AgencyCreate

        with pytest.raises(ValidationError):
            AgencyCreate(name="x" * 201)

    def test_agency_name_min_length(self):
        from pydantic import ValidationError

        from api.schemas.agency import AgencyCreate

        with pytest.raises(ValidationError):
            AgencyCreate(name="")

    def test_appeal_statement_max_length(self):
        from pydantic import ValidationError

        from api.schemas.appeal import AppealCreate

        with pytest.raises(ValidationError):
            AppealCreate(
                request_id="req-1",
                grounds="EXCESSIVE_REDACTION",
                statement="x" * 10001,
            )

    def test_request_description_max_length(self):
        from pydantic import ValidationError

        from api.schemas.request import RequestCreate

        with pytest.raises(ValidationError):
            RequestCreate(subject="test", description="x" * 10001)
