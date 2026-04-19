"""
Tests for api.auth — API key authentication, scope enforcement, and rate limiting.

Covers:
- _hash_key() determinism
- _APIKeyRecord creation
- Key loading from environment (_load_keys_into)
- Key extraction from requests (_extract_key)
- require_api_key() — valid key, invalid key, expired key, missing scope
- require_api_key_with_scope() — scope enforcement
- _TokenBucket — consumption, refill, exhaustion
- MemoryRateLimitBackend — get/set, LRU eviction, consume_atomic
- rate_limit() — per-IP token bucket
- IP helpers — _is_valid_ip, _normalize_ip, _ip_in_ranges
- reload_keys() — hot key rotation
- _register_api_key_for_tests / _reset_auth_state_for_tests

Does NOT depend on live DB or Redis; all tests use in-memory fixtures.
"""

from __future__ import annotations

import os
from time import monotonic
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.auth import (
    MemoryRateLimitBackend,
    RedisRateLimitBackend,
    _APIKeyRecord,
    _constant_time_equals,
    _hash_key,
    _ip_in_ranges,
    _is_valid_ip,
    _load_keys_into,
    _normalize_ip,
    _register_api_key_for_tests,
    _reset_auth_state_for_tests,
    _reset_rate_limit_backend_for_tests,
    _TokenBucket,
    require_api_key,
    require_api_key_with_scope,
)


@pytest.fixture(autouse=True)
def _clean_auth_state():
    """Reset auth state before/after each test."""
    _reset_auth_state_for_tests()
    _reset_rate_limit_backend_for_tests()
    yield
    _reset_auth_state_for_tests()
    _reset_rate_limit_backend_for_tests()


# ------------------------------------------------------------------ #
# _hash_key
# ------------------------------------------------------------------ #


class TestHashKey:
    def test_deterministic(self) -> None:
        assert _hash_key("test-key-123") == _hash_key("test-key-123")

    def test_different_keys_different_hashes(self) -> None:
        assert _hash_key("key-a") != _hash_key("key-b")

    def test_returns_hex_string(self) -> None:
        h = _hash_key("my-api-key")
        assert isinstance(h, str)
        assert len(h) == 64
        bytes.fromhex(h)


# ------------------------------------------------------------------ #
# _load_keys_into
# ------------------------------------------------------------------ #


class TestLoadKeysInto:
    def test_load_from_env(self) -> None:
        key_hash = _hash_key("raw-key")
        env_json = f'[{{"key_hash": "{key_hash}", "key_id": "test", "scopes": ["read", "write"]}}]'
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": env_json}):
            store: dict[str, _APIKeyRecord] = {}
            _load_keys_into(store)
            assert key_hash in store
            assert store[key_hash].key_id == "test"
            assert store[key_hash].scopes == {"read", "write"}

    def test_fallback_to_foia_env(self) -> None:
        key_hash = _hash_key("foia-key")
        env_json = f'[{{"key_hash": "{key_hash}", "key_id": "foia"}}]'
        with patch.dict(
            os.environ,
            {"OLYMPUS_FOIA_API_KEYS": env_json},
            clear=False,
        ):
            os.environ.pop("OLYMPUS_API_KEYS_JSON", None)
            store: dict[str, _APIKeyRecord] = {}
            _load_keys_into(store)
            assert key_hash in store

    def test_invalid_json_raises(self) -> None:
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": "not-json"}):
            with pytest.raises(ValueError, match="valid JSON"):
                _load_keys_into({})

    def test_missing_key_hash_raises(self) -> None:
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": '[{"key_id": "test"}]'}):
            with pytest.raises(ValueError, match="key_hash"):
                _load_keys_into({})

    def test_custom_expiration(self) -> None:
        key_hash = _hash_key("exp-key")
        env_json = f'[{{"key_hash": "{key_hash}", "expires_at": "2030-06-01T00:00:00Z"}}]'
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": env_json}):
            store: dict[str, _APIKeyRecord] = {}
            _load_keys_into(store)
            assert store[key_hash].expires_at.year == 2030

    def test_default_scopes(self) -> None:
        key_hash = _hash_key("default-scope")
        env_json = f'[{{"key_hash": "{key_hash}"}}]'
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": env_json}):
            store: dict[str, _APIKeyRecord] = {}
            _load_keys_into(store)
            assert store[key_hash].scopes == {"read", "write"}

    def test_empty_array(self) -> None:
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": "[]"}):
            store: dict[str, _APIKeyRecord] = {}
            _load_keys_into(store)
            assert len(store) == 0


# ------------------------------------------------------------------ #
# _constant_time_equals
# ------------------------------------------------------------------ #


class TestConstantTimeEquals:
    def test_equal_strings(self) -> None:
        assert _constant_time_equals("abc", "abc")

    def test_unequal_strings(self) -> None:
        assert not _constant_time_equals("abc", "def")

    def test_empty_strings(self) -> None:
        assert _constant_time_equals("", "")


# ------------------------------------------------------------------ #
# require_api_key
# ------------------------------------------------------------------ #


class TestRequireApiKey:
    @pytest.mark.asyncio
    async def test_valid_key(self) -> None:
        raw_key = "valid-test-key-12345"
        _register_api_key_for_tests(
            raw_key, key_id="test", scopes={"read", "write"}, expires_at="2099-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {"x-api-key": raw_key}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        record = await require_api_key(request)
        assert record.key_id == "test"

    @pytest.mark.asyncio
    async def test_invalid_key(self) -> None:
        _register_api_key_for_tests(
            "good-key", key_id="test", scopes={"write"}, expires_at="2099-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {"x-api-key": "bad-key"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_key(self) -> None:
        raw_key = "expired-key"
        _register_api_key_for_tests(
            raw_key, key_id="exp", scopes={"write"}, expires_at="2000-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {"x-api-key": raw_key}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_write_scope(self) -> None:
        raw_key = "read-only-key"
        _register_api_key_for_tests(
            raw_key, key_id="ro", scopes={"read"}, expires_at="2099-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {"x-api-key": raw_key}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(request)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_header(self) -> None:
        _register_api_key_for_tests(
            "some-key", key_id="test", scopes={"write"}, expires_at="2099-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {}
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_bearer_token_extraction(self) -> None:
        raw_key = "bearer-key-xyz"
        _register_api_key_for_tests(
            raw_key, key_id="bearer", scopes={"write"}, expires_at="2099-01-01T00:00:00Z"
        )
        request = MagicMock()
        request.headers = {"authorization": f"Bearer {raw_key}"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        record = await require_api_key(request)
        assert record.key_id == "bearer"


# ------------------------------------------------------------------ #
# require_api_key_with_scope
# ------------------------------------------------------------------ #


class TestRequireApiKeyWithScope:
    @pytest.mark.asyncio
    async def test_valid_scope(self) -> None:
        raw_key = "ingest-key"
        _register_api_key_for_tests(
            raw_key, key_id="ingest", scopes={"ingest"}, expires_at="2099-01-01T00:00:00Z"
        )
        dep = require_api_key_with_scope("ingest")
        request = MagicMock()
        request.headers = {"x-api-key": raw_key}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        record = await dep(request)
        assert record.key_id == "ingest"

    @pytest.mark.asyncio
    async def test_missing_scope(self) -> None:
        raw_key = "read-key"
        _register_api_key_for_tests(
            raw_key, key_id="reader", scopes={"read"}, expires_at="2099-01-01T00:00:00Z"
        )
        dep = require_api_key_with_scope("ingest")
        request = MagicMock()
        request.headers = {"x-api-key": raw_key}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        with pytest.raises(HTTPException) as exc_info:
            await dep(request)
        assert exc_info.value.status_code == 403


# ------------------------------------------------------------------ #
# _TokenBucket
# ------------------------------------------------------------------ #


class TestTokenBucket:
    def test_consume_full_bucket(self) -> None:
        bucket = _TokenBucket(capacity=5.0, refill_rate=0.0, tokens=5.0, last_refill=monotonic())
        assert bucket.consume()
        assert bucket.consume()

    def test_bucket_exhaustion(self) -> None:
        bucket = _TokenBucket(capacity=1.0, refill_rate=0.0, tokens=1.0, last_refill=monotonic())
        assert bucket.consume()
        assert not bucket.consume()

    def test_refill(self) -> None:
        now = monotonic()
        bucket = _TokenBucket(capacity=5.0, refill_rate=100.0, tokens=0.0, last_refill=now - 1.0)
        # After 1 second at rate 100/s, should have 5 tokens (capped)
        assert bucket.consume()

    def test_subtoken_refill_does_not_grant_request(self) -> None:
        bucket = _TokenBucket(capacity=1.0, refill_rate=10.0, tokens=0, last_refill=100.0)
        with patch("api.auth.monotonic", return_value=100.099):
            assert not bucket.consume()


# ------------------------------------------------------------------ #
# MemoryRateLimitBackend
# ------------------------------------------------------------------ #


class TestMemoryRateLimitBackend:
    def test_get_returns_none_for_missing(self) -> None:
        backend = MemoryRateLimitBackend()
        assert backend.get("nonexistent") is None

    def test_set_and_get(self) -> None:
        backend = MemoryRateLimitBackend()
        bucket = _TokenBucket(capacity=10.0, refill_rate=1.0, tokens=10.0, last_refill=monotonic())
        backend.set("key1", bucket)
        assert backend.get("key1") is bucket

    def test_lru_eviction(self) -> None:
        backend = MemoryRateLimitBackend(max_buckets=2)
        b1 = _TokenBucket(capacity=1.0, refill_rate=1.0, tokens=1.0, last_refill=monotonic())
        b2 = _TokenBucket(capacity=1.0, refill_rate=1.0, tokens=1.0, last_refill=monotonic())
        b3 = _TokenBucket(capacity=1.0, refill_rate=1.0, tokens=1.0, last_refill=monotonic())
        backend.set("k1", b1)
        backend.set("k2", b2)
        backend.set("k3", b3)
        # k1 should have been evicted
        assert backend.get("k1") is None
        assert backend.get("k2") is not None
        assert backend.get("k3") is not None

    def test_consume_atomic_creates_bucket(self) -> None:
        backend = MemoryRateLimitBackend()
        assert backend.consume_atomic("ip1", 10.0, 1.0)
        assert backend.bucket_count == 1

    def test_consume_atomic_exhausts(self) -> None:
        backend = MemoryRateLimitBackend()
        # First consume — creates full bucket
        assert backend.consume_atomic("ip1", 1.0, 0.0)
        # Second consume — should fail (capacity 1, refill 0)
        assert not backend.consume_atomic("ip1", 1.0, 0.0)

    def test_bucket_count(self) -> None:
        backend = MemoryRateLimitBackend()
        assert backend.bucket_count == 0
        b = _TokenBucket(capacity=1.0, refill_rate=1.0, tokens=1.0, last_refill=monotonic())
        backend.set("k", b)
        assert backend.bucket_count == 1


# ------------------------------------------------------------------ #
# RedisRateLimitBackend (stub)
# ------------------------------------------------------------------ #


class TestRedisRateLimitBackend:
    def test_get_raises_without_redis(self) -> None:
        backend = RedisRateLimitBackend("redis://localhost")
        with pytest.raises(ImportError, match="redis"):
            backend.get("key")

    def test_set_raises_without_redis(self) -> None:
        backend = RedisRateLimitBackend("redis://localhost")
        b = _TokenBucket(capacity=1.0, refill_rate=1.0, tokens=1.0, last_refill=monotonic())
        with pytest.raises(ImportError, match="redis"):
            backend.set("key", b)


# ------------------------------------------------------------------ #
# IP helpers
# ------------------------------------------------------------------ #


class TestIPHelpers:
    def test_valid_ipv4(self) -> None:
        assert _is_valid_ip("127.0.0.1")

    def test_valid_ipv6(self) -> None:
        assert _is_valid_ip("::1")

    def test_invalid_ip(self) -> None:
        assert not _is_valid_ip("not-an-ip")

    def test_normalize_plain_ipv4(self) -> None:
        assert _normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_normalize_mapped_ipv6(self) -> None:
        assert _normalize_ip("::ffff:192.168.1.1") == "192.168.1.1"

    def test_ip_in_single_range(self) -> None:
        assert _ip_in_ranges("10.0.0.1", ["10.0.0.0/8"])

    def test_ip_not_in_range(self) -> None:
        assert not _ip_in_ranges("192.168.1.1", ["10.0.0.0/8"])

    def test_ip_in_exact_match(self) -> None:
        assert _ip_in_ranges("10.0.0.5", ["10.0.0.5"])

    def test_invalid_ip_returns_false(self) -> None:
        assert not _ip_in_ranges("not-an-ip", ["10.0.0.0/8"])


# ------------------------------------------------------------------ #
# reload_keys
# ------------------------------------------------------------------ #


class TestReloadKeys:
    def test_reload_returns_count(self) -> None:
        from api.auth import reload_keys

        key_hash = _hash_key("reload-key")
        env_json = f'[{{"key_hash": "{key_hash}", "key_id": "reloaded"}}]'
        with patch.dict(os.environ, {"OLYMPUS_API_KEYS_JSON": env_json}):
            count = reload_keys()
            assert count == 1
