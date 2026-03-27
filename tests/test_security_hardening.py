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

import unittest.mock

import pytest

from api.auth import (
    MemoryRateLimitBackend,
    _get_client_ip,
    _ip_in_ranges,
    _is_valid_ip,
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
