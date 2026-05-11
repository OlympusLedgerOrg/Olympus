"""Unit tests for internal helper functions in api/routers/witness.py.

These tests exercise _env_flag_enabled, _load_federation_registry, and
_resolve_node_pubkey directly without going through the FastAPI ASGI stack,
so that coverage.py can track their execution reliably.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import nacl.signing
import pytest
import pytest_asyncio

import api.routers.witness as witness_module
from api.routers.witness import (
    _env_flag_enabled,
    _load_federation_registry,
    _resolve_node_pubkey,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_registry(path: Path, pubkey_hex: str, endpoint: str = "node.example.com") -> None:
    """Write a minimal valid federation registry JSON file."""
    data = {
        "nodes": [
            {
                "node_id": "test-node-1",
                "pubkey": pubkey_hex,
                "endpoint": endpoint,
                "operator": "Test Operator",
                "jurisdiction": "US",
                "status": "active",
            }
        ],
        "epoch": 1,
    }
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture(autouse=True)
def _reset_registry_cache():
    """Reset the module-level registry cache before and after each test."""
    witness_module._registry_cache = None
    yield
    witness_module._registry_cache = None


# ---------------------------------------------------------------------------
# _env_flag_enabled
# ---------------------------------------------------------------------------


class TestEnvFlagEnabled:
    def test_true_values(self, monkeypatch):
        for val in ("1", "true", "yes", "on", " 1 ", " TRUE ", "YES", "ON"):
            monkeypatch.setenv("_OLY_TEST_FLAG", val)
            assert _env_flag_enabled("_OLY_TEST_FLAG") is True, f"Expected True for {val!r}"

    def test_false_values(self, monkeypatch):
        for val in ("0", "false", "no", "off", "2", "enabled", ""):
            monkeypatch.setenv("_OLY_TEST_FLAG", val)
            assert _env_flag_enabled("_OLY_TEST_FLAG") is False, f"Expected False for {val!r}"

    def test_missing_env_var(self, monkeypatch):
        monkeypatch.delenv("_OLY_TEST_FLAG", raising=False)
        assert _env_flag_enabled("_OLY_TEST_FLAG") is False


# ---------------------------------------------------------------------------
# _load_federation_registry
# ---------------------------------------------------------------------------


class TestLoadFederationRegistry:
    def test_missing_file_returns_none(self):
        result = _load_federation_registry("/nonexistent/path/to/registry.json")
        assert result is None

    def test_valid_file_returns_registry(self, tmp_path):
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        registry_file = tmp_path / "registry.json"
        _write_registry(registry_file, pubkey_hex)

        result = _load_federation_registry(str(registry_file))
        assert result is not None
        assert len(result.nodes) == 1
        assert result.nodes[0].pubkey == bytes.fromhex(pubkey_hex)

    def test_invalid_json_returns_none(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT JSON {{{", encoding="utf-8")

        result = _load_federation_registry(str(bad_file))
        assert result is None

    def test_invalid_registry_structure_returns_none(self, tmp_path):
        """Registry JSON that parses but fails FederationRegistry validation returns None."""
        bad_file = tmp_path / "bad_structure.json"
        # Empty nodes list is not allowed
        bad_file.write_text(json.dumps({"nodes": [], "epoch": 0}), encoding="utf-8")

        result = _load_federation_registry(str(bad_file))
        assert result is None

    def test_cache_hit_skips_reload(self, tmp_path):
        """Second call with same path and mtime returns the cached registry."""
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        registry_file = tmp_path / "registry.json"
        _write_registry(registry_file, pubkey_hex)

        first = _load_federation_registry(str(registry_file))
        second = _load_federation_registry(str(registry_file))
        assert first is second  # same object from cache

    def test_cache_refreshes_on_mtime_change(self, tmp_path):
        """When the file's mtime changes, the registry is reloaded."""
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        registry_file = tmp_path / "registry.json"
        _write_registry(registry_file, pubkey_hex)

        first = _load_federation_registry(str(registry_file))

        # Write a different registry with a new pubkey
        signing_key2 = nacl.signing.SigningKey.generate()
        pubkey_hex2 = signing_key2.verify_key.encode().hex()
        _write_registry(registry_file, pubkey_hex2, endpoint="other.example.com")
        # Force a different mtime by bumping the file
        new_mtime = registry_file.stat().st_mtime + 1.0
        os.utime(str(registry_file), (new_mtime, new_mtime))

        second = _load_federation_registry(str(registry_file))
        assert second is not first
        assert second is not None
        assert second.nodes[0].endpoint == "other.example.com"


# ---------------------------------------------------------------------------
# _resolve_node_pubkey
# ---------------------------------------------------------------------------


class TestResolveNodePubkey:
    def test_env_registry_returns_pubkey(self, monkeypatch):
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.delenv("OLYMPUS_GUARDIAN_ENABLED", raising=False)
        monkeypatch.setenv(
            "OLYMPUS_WITNESS_REGISTRY", json.dumps({"my-node.example.com": pubkey_hex})
        )
        result = _resolve_node_pubkey("my-node.example.com")
        assert result == pubkey_hex

    def test_env_registry_unknown_origin_returns_none(self, monkeypatch):
        monkeypatch.delenv("OLYMPUS_GUARDIAN_ENABLED", raising=False)
        monkeypatch.setenv("OLYMPUS_WITNESS_REGISTRY", json.dumps({"other.example.com": "ab" * 32}))
        result = _resolve_node_pubkey("unknown.example.com")
        assert result is None

    def test_env_registry_invalid_json_returns_none(self, monkeypatch):
        monkeypatch.delenv("OLYMPUS_GUARDIAN_ENABLED", raising=False)
        monkeypatch.setenv("OLYMPUS_WITNESS_REGISTRY", "NOT VALID JSON {{")
        result = _resolve_node_pubkey("anything")
        assert result is None

    def test_guardian_enabled_node_found(self, monkeypatch, tmp_path):
        """When Guardian mode is active and the node is in the registry, return its pubkey."""
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        registry_file = tmp_path / "registry.json"
        _write_registry(registry_file, pubkey_hex, endpoint="guardian-node.example.com")

        monkeypatch.setenv("OLYMPUS_GUARDIAN_ENABLED", "1")
        monkeypatch.setenv("OLYMPUS_GUARDIAN_REGISTRY_PATH", str(registry_file))
        monkeypatch.delenv("OLYMPUS_WITNESS_REGISTRY", raising=False)

        result = _resolve_node_pubkey("guardian-node.example.com")
        assert result == pubkey_hex

    def test_guardian_enabled_node_not_found_falls_back_to_env(self, monkeypatch, tmp_path):
        """When Guardian is active but origin not in registry, fall back to env var."""
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        registry_file = tmp_path / "registry.json"
        _write_registry(registry_file, pubkey_hex, endpoint="known-node.example.com")

        fallback_key = nacl.signing.SigningKey.generate()
        fallback_pubkey_hex = fallback_key.verify_key.encode().hex()

        monkeypatch.setenv("OLYMPUS_GUARDIAN_ENABLED", "1")
        monkeypatch.setenv("OLYMPUS_GUARDIAN_REGISTRY_PATH", str(registry_file))
        monkeypatch.setenv(
            "OLYMPUS_WITNESS_REGISTRY",
            json.dumps({"fallback-node.example.com": fallback_pubkey_hex}),
        )

        result = _resolve_node_pubkey("fallback-node.example.com")
        assert result == fallback_pubkey_hex

    def test_guardian_enabled_missing_registry_logs_and_falls_back(
        self, monkeypatch
    ):
        """When Guardian is active but registry file is missing, logs warning and falls back."""
        signing_key = nacl.signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()

        monkeypatch.setenv("OLYMPUS_GUARDIAN_ENABLED", "1")
        monkeypatch.setenv("OLYMPUS_GUARDIAN_REGISTRY_PATH", "/no/such/registry.json")
        monkeypatch.setenv(
            "OLYMPUS_WITNESS_REGISTRY",
            json.dumps({"fallback.example.com": pubkey_hex}),
        )

        result = _resolve_node_pubkey("fallback.example.com")
        assert result == pubkey_hex

    def test_no_env_registry_configured_returns_none(self, monkeypatch):
        monkeypatch.delenv("OLYMPUS_GUARDIAN_ENABLED", raising=False)
        monkeypatch.delenv("OLYMPUS_WITNESS_REGISTRY", raising=False)
        result = _resolve_node_pubkey("nobody.example.com")
        assert result is None


# ---------------------------------------------------------------------------
# Direct endpoint call tests
#
# Coverage.py cannot track lines that follow an `await` expression inside a
# FastAPI ASGI handler when the handler is invoked through httpx ASGITransport
# (a known Python 3.12 + coverage.py limitation).  Calling the async endpoint
# functions directly with a real SQLAlchemy session bypasses the ASGI layer
# and allows coverage to observe those lines.
# ---------------------------------------------------------------------------


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture()
async def direct_db_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    from api.models import Base

    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def direct_session_factory(direct_db_engine):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    return async_sessionmaker(direct_db_engine, expire_on_commit=False, class_=AsyncSession)


class TestEndpointDirectCall:
    """Call async endpoint functions directly to exercise post-await lines."""

    @pytest.mark.asyncio
    async def test_get_latest_checkpoint_raises_404_when_empty(
        self, direct_session_factory
    ) -> None:
        from fastapi import HTTPException

        async with direct_session_factory() as db:
            with pytest.raises(HTTPException) as exc_info:
                await witness_module.get_latest_checkpoint(db)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_get_checkpoint_by_sequence_raises_404(
        self, direct_session_factory
    ) -> None:
        from fastapi import HTTPException

        async with direct_session_factory() as db:
            with pytest.raises(HTTPException) as exc_info:
                await witness_module.get_checkpoint_by_sequence(99999, db)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_list_checkpoints_returns_empty_list(
        self, direct_session_factory
    ) -> None:
        async with direct_session_factory() as db:
            result = await witness_module.list_checkpoints(db=db, limit=10, offset=0)
        assert result == []

    @pytest.mark.asyncio
    async def test_witness_health_returns_ok(self, direct_session_factory) -> None:
        async with direct_session_factory() as db:
            result = await witness_module.witness_health(db)
        assert result.status == "ok"
        assert result.observation_count >= 0

    @pytest.mark.asyncio
    async def test_get_gossip_state_returns_empty_list(
        self, direct_session_factory
    ) -> None:
        async with direct_session_factory() as db:
            result = await witness_module.get_gossip_state(db=db)
        assert result == []

    @pytest.mark.asyncio
    async def test_submit_observation_success_path(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """Exercise the full success path of submit_observation directly."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)

        ch = "cd" * 32
        origin = "direct-test-origin"
        seq = 777
        ts = current_timestamp()
        payload = hash_bytes(f"{origin}:{seq}:{ch}".encode())
        sig_hex = signing_key.sign(payload).signature.hex()

        request = WitnessAnnounceRequest(
            origin=origin,
            checkpoint=WitnessCheckpoint(
                sequence=seq, checkpoint_hash=ch, timestamp=ts
            ),
            nonce=uuid.uuid4().hex,
            node_signature=sig_hex,
        )
        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )

        async with direct_session_factory() as db:
            response = await witness_module.submit_observation(request, dev_key, db)
        assert response.origin == origin
        assert response.sequence == seq
        assert response.status == "recorded"

    @pytest.mark.asyncio
    async def test_submit_observation_duplicate_nonce_409(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """Submitting the same nonce twice raises HTTPException 409."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing
        from fastapi import HTTPException

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)

        nonce = uuid.uuid4().hex
        ch = "ef" * 32
        origin = "dup-nonce-origin"
        ts = current_timestamp()
        payload = hash_bytes(f"{origin}:1:{ch}".encode())
        sig_hex = signing_key.sign(payload).signature.hex()

        request1 = WitnessAnnounceRequest(
            origin=origin,
            checkpoint=WitnessCheckpoint(sequence=1, checkpoint_hash=ch, timestamp=ts),
            nonce=nonce,
            node_signature=sig_hex,
        )
        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )

        payload2 = hash_bytes(f"{origin}:2:{ch}".encode())
        sig_hex2 = signing_key.sign(payload2).signature.hex()
        request2 = WitnessAnnounceRequest(
            origin=origin,
            checkpoint=WitnessCheckpoint(sequence=2, checkpoint_hash=ch, timestamp=ts),
            nonce=nonce,  # same nonce!
            node_signature=sig_hex2,
        )

        async with direct_session_factory() as db:
            await witness_module.submit_observation(request1, dev_key, db)
        async with direct_session_factory() as db:
            with pytest.raises(HTTPException) as exc_info:
                await witness_module.submit_observation(request2, dev_key, db)
        assert exc_info.value.status_code == 409
        assert "nonce" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_submit_observation_duplicate_key_409(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """Submitting origin+sequence that already exists raises HTTPException 409."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing
        from fastapi import HTTPException

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)

        ch = "12" * 32
        origin = "dup-key-origin"
        ts = current_timestamp()
        payload = hash_bytes(f"{origin}:10:{ch}".encode())
        sig_hex = signing_key.sign(payload).signature.hex()

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )

        def _make_req(nonce: str) -> WitnessAnnounceRequest:
            return WitnessAnnounceRequest(
                origin=origin,
                checkpoint=WitnessCheckpoint(sequence=10, checkpoint_hash=ch, timestamp=ts),
                nonce=nonce,
                node_signature=sig_hex,
            )

        async with direct_session_factory() as db:
            await witness_module.submit_observation(_make_req(uuid.uuid4().hex), dev_key, db)
        async with direct_session_factory() as db:
            with pytest.raises(HTTPException) as exc_info:
                await witness_module.submit_observation(_make_req(uuid.uuid4().hex), dev_key, db)
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_get_latest_checkpoint_returns_row(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """get_latest_checkpoint returns the observation when one exists."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)

        ch = "aa" * 32
        origin = "latest-cp-origin"
        seq = 9001  # high enough to be the latest
        ts = current_timestamp()
        payload = hash_bytes(f"{origin}:{seq}:{ch}".encode())
        sig_hex = signing_key.sign(payload).signature.hex()

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        req = WitnessAnnounceRequest(
            origin=origin,
            checkpoint=WitnessCheckpoint(sequence=seq, checkpoint_hash=ch, timestamp=ts),
            nonce=uuid.uuid4().hex,
            node_signature=sig_hex,
        )
        async with direct_session_factory() as db:
            await witness_module.submit_observation(req, dev_key, db)

        async with direct_session_factory() as db:
            result = await witness_module.get_latest_checkpoint(db)
        assert result.checkpoint.sequence == seq

    @pytest.mark.asyncio
    async def test_get_checkpoint_by_sequence_returns_row(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """get_checkpoint_by_sequence returns the matching observation."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)

        ch = "bb" * 32
        origin = "seq-cp-origin"
        seq = 666
        ts = current_timestamp()
        payload = hash_bytes(f"{origin}:{seq}:{ch}".encode())
        sig_hex = signing_key.sign(payload).signature.hex()

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        req = WitnessAnnounceRequest(
            origin=origin,
            checkpoint=WitnessCheckpoint(sequence=seq, checkpoint_hash=ch, timestamp=ts),
            nonce=uuid.uuid4().hex,
            node_signature=sig_hex,
        )
        async with direct_session_factory() as db:
            await witness_module.submit_observation(req, dev_key, db)

        async with direct_session_factory() as db:
            result = await witness_module.get_checkpoint_by_sequence(seq, db)
        assert result.checkpoint.sequence == seq

    @pytest.mark.asyncio
    async def test_submit_observation_evicts_old_nonces(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """When nonce table is at capacity, oldest entries are evicted."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)
        # Reduce nonce capacity to 1 so the second submission triggers eviction.
        monkeypatch.setattr(witness_module, "_MAX_NONCE_ENTRIES", 1)

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )

        def _make_req(origin: str, seq: int, ts: str) -> WitnessAnnounceRequest:
            ch = "cc" * 32
            payload = hash_bytes(f"{origin}:{seq}:{ch}".encode())
            return WitnessAnnounceRequest(
                origin=origin,
                checkpoint=WitnessCheckpoint(sequence=seq, checkpoint_hash=ch, timestamp=ts),
                nonce=uuid.uuid4().hex,
                node_signature=signing_key.sign(payload).signature.hex(),
            )

        ts = current_timestamp()
        async with direct_session_factory() as db:
            await witness_module.submit_observation(_make_req("evict-nonce-a", 101, ts), dev_key, db)
        async with direct_session_factory() as db:
            resp = await witness_module.submit_observation(
                _make_req("evict-nonce-b", 102, ts), dev_key, db
            )
        assert resp.status == "recorded"

    @pytest.mark.asyncio
    async def test_submit_observation_evicts_old_observations(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """When observation table is at capacity, oldest entries are evicted."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        signing_key = _nacl_signing.SigningKey.generate()
        pubkey_hex = signing_key.verify_key.encode().hex()
        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", lambda o: pubkey_hex)
        # Reduce observation capacity to 1 so the second submission triggers eviction.
        monkeypatch.setattr(witness_module, "_MAX_OBSERVATIONS", 1)

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )

        def _make_req(origin: str, seq: int, ts: str) -> WitnessAnnounceRequest:
            ch = "dd" * 32
            payload = hash_bytes(f"{origin}:{seq}:{ch}".encode())
            return WitnessAnnounceRequest(
                origin=origin,
                checkpoint=WitnessCheckpoint(sequence=seq, checkpoint_hash=ch, timestamp=ts),
                nonce=uuid.uuid4().hex,
                node_signature=signing_key.sign(payload).signature.hex(),
            )

        ts = current_timestamp()
        async with direct_session_factory() as db:
            await witness_module.submit_observation(
                _make_req("evict-obs-a", 201, ts), dev_key, db
            )
        async with direct_session_factory() as db:
            resp = await witness_module.submit_observation(
                _make_req("evict-obs-b", 202, ts), dev_key, db
            )
        assert resp.status == "recorded"

    @pytest.mark.asyncio
    async def test_get_gossip_state_returns_conflicts(
        self, direct_session_factory, monkeypatch
    ) -> None:
        """get_gossip_state returns conflict entries when differing hashes exist."""
        import uuid
        from datetime import datetime, timezone

        import nacl.signing as _nacl_signing

        from api.auth import _APIKeyRecord
        from api.schemas.witness import WitnessAnnounceRequest, WitnessCheckpoint
        from protocol.hashes import hash_bytes
        from protocol.timestamps import current_timestamp

        # Use two different signing keys for two origins.
        key_a = _nacl_signing.SigningKey.generate()
        key_b = _nacl_signing.SigningKey.generate()
        pubkey_a = key_a.verify_key.encode().hex()
        pubkey_b = key_b.verify_key.encode().hex()

        origin_a = "gossip-origin-alpha"
        origin_b = "gossip-origin-beta"
        shared_seq = 900

        def _pubkey_for(origin: str) -> str:
            return pubkey_a if origin == origin_a else pubkey_b

        monkeypatch.setattr(witness_module, "_resolve_node_pubkey", _pubkey_for)

        dev_key = _APIKeyRecord(
            key_id="test",
            key_hash="",
            scopes={"read", "write"},
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        ts = current_timestamp()

        # Origin A and B report different hashes at the same sequence.
        ch_a = "11" * 32
        ch_b = "22" * 32

        payload_a = hash_bytes(f"{origin_a}:{shared_seq}:{ch_a}".encode())
        req_a = WitnessAnnounceRequest(
            origin=origin_a,
            checkpoint=WitnessCheckpoint(
                sequence=shared_seq, checkpoint_hash=ch_a, timestamp=ts
            ),
            nonce=uuid.uuid4().hex,
            node_signature=key_a.sign(payload_a).signature.hex(),
        )
        payload_b = hash_bytes(f"{origin_b}:{shared_seq}:{ch_b}".encode())
        req_b = WitnessAnnounceRequest(
            origin=origin_b,
            checkpoint=WitnessCheckpoint(
                sequence=shared_seq, checkpoint_hash=ch_b, timestamp=ts
            ),
            nonce=uuid.uuid4().hex,
            node_signature=key_b.sign(payload_b).signature.hex(),
        )

        async with direct_session_factory() as db:
            await witness_module.submit_observation(req_a, dev_key, db)
        async with direct_session_factory() as db:
            await witness_module.submit_observation(req_b, dev_key, db)

        async with direct_session_factory() as db:
            conflicts = await witness_module.get_gossip_state(db=db)

        assert any(c.sequence == shared_seq for c in conflicts)
        conflict = next(c for c in conflicts if c.sequence == shared_seq)
        assert set(conflict.conflicting_origins) == {origin_a, origin_b}
        assert conflict.hashes[origin_a] == ch_a
        assert conflict.hashes[origin_b] == ch_b
