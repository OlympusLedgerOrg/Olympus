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

    def test_fractional_elapsed_accumulates_across_calls(self) -> None:
        bucket = _TokenBucket(capacity=2.0, refill_rate=0.5, tokens=0, last_refill=100.0)
        with patch("api.auth.monotonic", return_value=101.0):
            assert not bucket.consume()
        with patch("api.auth.monotonic", return_value=102.0):
            assert bucket.consume()


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

    # ── mocked-Redis tests (no live Redis needed) ──────────────────── #

    def _make_mock_redis_client(self, lua_result: int = 1) -> MagicMock:
        """Return a mock redis.Redis client.

        The mock:
        - ``time()`` returns a fixed server timestamp.
        - ``register_script()`` returns a callable that always returns *lua_result*
          (1 = allowed, 0 = rate-limited).
        - ``hgetall()`` returns an empty dict (bucket not found → fresh bucket).
        """
        mock_client = MagicMock()
        mock_client.time.return_value = (1_700_000_000, 0)  # fixed unix ts
        mock_script = MagicMock(return_value=lua_result)
        mock_client.register_script.return_value = mock_script
        mock_client.hgetall.return_value = {}
        return mock_client

    def _patch_redis_client(self, backend: RedisRateLimitBackend, mock_client: MagicMock) -> None:
        """Inject the mock client directly into a backend instance."""
        backend._client = mock_client  # type: ignore[attr-defined]

    def test_consume_atomic_allowed(self) -> None:
        """consume_atomic returns True when Lua script returns 1."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = self._make_mock_redis_client(lua_result=1)
        self._patch_redis_client(backend, mock_client)

        assert backend.consume_atomic("127.0.0.1", 10.0, 1.0) is True

    def test_consume_atomic_denied(self) -> None:
        """consume_atomic returns False when Lua script returns 0 (bucket empty)."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = self._make_mock_redis_client(lua_result=0)
        self._patch_redis_client(backend, mock_client)

        assert backend.consume_atomic("127.0.0.1", 10.0, 1.0) is False

    def test_consume_atomic_invokes_lua_with_correct_key(self) -> None:
        """Lua script is called with the prefixed Redis key."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = self._make_mock_redis_client(lua_result=1)
        self._patch_redis_client(backend, mock_client)

        backend.consume_atomic("10.0.0.1", 5.0, 0.5)

        mock_script = mock_client.register_script.return_value
        call_kwargs = mock_script.call_args
        keys_arg = call_kwargs[1]["keys"] if call_kwargs[1] else call_kwargs[0][0]
        assert keys_arg == ["olympus:rl:10.0.0.1"]

    def test_cross_worker_shared_counter(self) -> None:
        """Two backend instances sharing the same Redis client share the same bucket.

        This is the core multi-worker invariant: worker A and worker B both call
        consume_atomic for the same IP and the Lua script is invoked on the same
        Redis key, not two independent in-process counters.
        """
        # Shared mock represents a single Redis server seen by both workers.
        shared_redis = MagicMock()
        shared_redis.time.return_value = (1_700_000_000, 0)

        call_count = {"n": 0}

        def lua_side_effect(**kwargs: object) -> int:
            # Returns 1 (allowed) for the first call, 0 (denied) for the second.
            call_count["n"] += 1
            return 1 if call_count["n"] == 1 else 0

        mock_script = MagicMock(side_effect=lua_side_effect)
        shared_redis.register_script.return_value = mock_script

        # Two "worker" backend instances, both injected with the same Redis client.
        worker_a = RedisRateLimitBackend("redis://localhost")
        worker_b = RedisRateLimitBackend("redis://localhost")
        worker_a._client = shared_redis  # type: ignore[attr-defined]
        worker_b._client = shared_redis  # type: ignore[attr-defined]

        # First request (worker A): allowed.
        assert worker_a.consume_atomic("1.2.3.4", 1.0, 0.0) is True
        # Second request (worker B, same IP, same bucket): denied — counter shared.
        assert worker_b.consume_atomic("1.2.3.4", 1.0, 0.0) is False

        # Both calls hit the same Lua script (same Redis key), proving shared state.
        assert mock_script.call_count == 2
        for call in mock_script.call_args_list:
            keys_arg = call[1]["keys"] if call[1] else call[0][0]
            assert keys_arg == ["olympus:rl:1.2.3.4"]

    def test_get_parses_hash_fields(self) -> None:
        """get() reconstructs a _TokenBucket from Redis hash fields."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = MagicMock()
        mock_client.hgetall.return_value = {
            "tokens": "5",
            "last_refill": "1700000000.0",
            "capacity": "10.0",
            "refill_rate": "1.0",
        }
        backend._client = mock_client  # type: ignore[attr-defined]

        bucket = backend.get("some-ip")
        assert bucket is not None
        assert bucket.tokens == 5
        assert bucket.capacity == 10.0
        assert bucket.refill_rate == 1.0

    def test_get_returns_none_for_missing_key(self) -> None:
        """get() returns None when the Redis key does not exist."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = MagicMock()
        mock_client.hgetall.return_value = {}
        backend._client = mock_client  # type: ignore[attr-defined]

        assert backend.get("missing-ip") is None

    def test_set_stores_all_fields_with_ttl(self) -> None:
        """set() writes all four bucket fields and calls EXPIRE."""
        backend = RedisRateLimitBackend("redis://localhost")
        mock_client = MagicMock()
        backend._client = mock_client  # type: ignore[attr-defined]

        bucket = _TokenBucket(capacity=10.0, refill_rate=1.0, tokens=7, last_refill=1_700_000_000.0)
        backend.set("192.168.0.1", bucket)

        mock_client.hset.assert_called_once()
        call_kwargs = mock_client.hset.call_args[1]
        mapping = call_kwargs["mapping"]
        assert mapping["tokens"] == "7"
        assert mapping["capacity"] == "10.0"
        assert mapping["refill_rate"] == "1.0"
        mock_client.expire.assert_called_once()
        # TTL should be at least 60s (minimum) and positive.
        ttl_arg = mock_client.expire.call_args[0][1]
        assert ttl_arg >= 60


# ------------------------------------------------------------------ #
# _create_rate_limit_backend
# ------------------------------------------------------------------ #


class TestCreateRateLimitBackend:
    """Tests for the backend factory — env-var driven selection."""

    def test_memory_backend_selected_by_default(self) -> None:
        from api.auth import _create_rate_limit_backend

        with patch.dict(os.environ, {"RATE_LIMIT_BACKEND": "memory"}, clear=False):
            with patch("api.auth.get_settings") as mock_settings:
                mock_settings.return_value.rate_limit_backend = "memory"
                mock_settings.return_value.rate_limit_redis_url = ""
                backend = _create_rate_limit_backend()
        assert isinstance(backend, MemoryRateLimitBackend)

    def test_redis_backend_selected_when_configured(self) -> None:
        from api.auth import _create_rate_limit_backend

        with patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.rate_limit_backend = "redis"
            mock_settings.return_value.rate_limit_redis_url = "redis://localhost:6379/0"
            backend = _create_rate_limit_backend()
        assert isinstance(backend, RedisRateLimitBackend)

    def test_redis_without_url_raises(self) -> None:
        from api.auth import _create_rate_limit_backend

        with patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.rate_limit_backend = "redis"
            mock_settings.return_value.rate_limit_redis_url = ""
            with pytest.raises(ValueError, match="RATE_LIMIT_REDIS_URL"):
                _create_rate_limit_backend()

    def test_unknown_backend_raises(self) -> None:
        from api.auth import _create_rate_limit_backend

        with patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.rate_limit_backend = "memcached"
            mock_settings.return_value.rate_limit_redis_url = ""
            with pytest.raises(ValueError, match="Unknown RATE_LIMIT_BACKEND"):
                _create_rate_limit_backend()

    def test_multiworker_memory_production_raises(self) -> None:
        """WEB_CONCURRENCY>1 + memory + production must hard-fail at startup."""
        from api.auth import _create_rate_limit_backend

        with patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.rate_limit_backend = "memory"
            mock_settings.return_value.rate_limit_redis_url = ""
            with patch.dict(
                os.environ,
                {"WEB_CONCURRENCY": "4", "OLYMPUS_ENV": "production"},
                clear=False,
            ):
                with pytest.raises(RuntimeError, match="WEB_CONCURRENCY=4"):
                    _create_rate_limit_backend()

    def test_multiworker_memory_dev_warns_but_allows(self) -> None:
        """WEB_CONCURRENCY>1 + memory + development should warn but not raise."""

        from api.auth import _create_rate_limit_backend

        with patch("api.auth.get_settings") as mock_settings:
            mock_settings.return_value.rate_limit_backend = "memory"
            mock_settings.return_value.rate_limit_redis_url = ""
            with patch.dict(
                os.environ,
                {"WEB_CONCURRENCY": "4", "OLYMPUS_ENV": "development"},
                clear=False,
            ):
                with patch("api.auth.logger") as mock_logger:
                    backend = _create_rate_limit_backend()
                    mock_logger.warning.assert_called_once()
                    warning_msg = mock_logger.warning.call_args[0][0]
                    assert "memory" in warning_msg.lower() or "per-process" in warning_msg.lower()
        assert isinstance(backend, MemoryRateLimitBackend)


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
