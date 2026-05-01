"""Tests for api.routers.federation — Guardian replication API paths.

Covers the ``OLYMPUS_GUARDIAN_ENABLED=true`` branches that the existing
``test_guardian_replication.py`` tests do not reach via the API layer.

Authentication relies on the dev-mode bypass: conftest.py sets
``OLYMPUS_ENV=development`` and ``OLYMPUS_ALLOW_DEV_AUTH=1``, so any
request passes auth as long as no API keys are registered in the store.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = str(REPO_ROOT / "examples" / "federation_registry.json")

# Raw key bytes for node-1 in the test registry (pubkey 3e86f08f...).
# Derived via: get_signing_key_from_seed(bytes([1]) * 32)
# FOR TESTING ONLY — never use this key in production.
_NODE1_SIGNING_KEY_HEX = "b732501813e17933dea7f5269e97db58bf6757ce47f160681d8af7dc020b4128"

_GUARDIAN_ENV = {
    "OLYMPUS_GUARDIAN_ENABLED": "true",
    "OLYMPUS_GUARDIAN_REGISTRY_PATH": REGISTRY_PATH,
    "OLYMPUS_INGEST_SIGNING_KEY": _NODE1_SIGNING_KEY_HEX,
}

_VALID_HEADER = {
    "shard_id": "test.shard",
    "root_hash": "cc" * 32,
    "header_hash": "cc" * 32,
    "timestamp": "2026-04-14T12:00:00Z",
    "height": 1,
    "round": 0,
}

_VALID_SIGN_HEADER_BODY = {
    "domain": "OLY:FEDERATION-VOTE:V1",
    "node_id": "olympus-node-1",
    "event_id": "evt-001",
    "shard_id": "test.shard",
    "entry_seq": 1,
    "round_number": 0,
    "shard_root": "cc" * 32,
    "timestamp": "2026-04-14T12:00:00Z",
    "epoch": 1,
    "validator_set_hash": "dd" * 32,
    "header": _VALID_HEADER,
}


def _make_mock_db_session(local_root: str | None = None) -> AsyncMock:
    """Return an async DB session mock that returns ``local_root`` for Merkle root queries."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = local_root
    session.execute = AsyncMock(return_value=result_mock)
    return session


# ---------------------------------------------------------------------------
# GET /v1/federation/status
# ---------------------------------------------------------------------------


class TestFederationStatusEndpoint:
    def test_status_disabled(self) -> None:
        from api.main import app

        with patch.dict(os.environ, {"OLYMPUS_GUARDIAN_ENABLED": "false"}):
            with TestClient(app) as client:
                response = client.get("/v1/federation/status")
        assert response.status_code == 200
        data = response.json()
        assert data["guardian_enabled"] is False

    def test_status_enabled_registry_loaded(self) -> None:
        from api.main import app
        from api.routers import federation as fed_mod

        # Reset the registry cache to force a reload with the test env
        fed_mod._registry_cache = None

        with patch.dict(os.environ, _GUARDIAN_ENV):
            with TestClient(app) as client:
                response = client.get("/v1/federation/status")
        assert response.status_code == 200
        data = response.json()
        assert data["guardian_enabled"] is True
        assert data["registry_loaded"] is True
        assert isinstance(data["active_nodes"], int)
        assert data["active_nodes"] > 0
        # local_node_id should be resolved from the signing key
        assert data.get("local_node_id") == "olympus-node-1"

    def test_status_enabled_registry_missing(self) -> None:
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        env = {
            "OLYMPUS_GUARDIAN_ENABLED": "true",
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": "/nonexistent/path/registry.json",
            "OLYMPUS_INGEST_SIGNING_KEY": _NODE1_SIGNING_KEY_HEX,
        }
        with patch.dict(os.environ, env):
            with TestClient(app) as client:
                response = client.get("/v1/federation/status")
        assert response.status_code == 200
        data = response.json()
        assert data["guardian_enabled"] is True
        assert data["registry_loaded"] is False

    def test_status_enabled_no_signing_key(self) -> None:
        """local_node_id should be None when no signing key is configured."""
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        env = {
            "OLYMPUS_GUARDIAN_ENABLED": "true",
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": REGISTRY_PATH,
        }
        # Remove signing key from env
        with patch.dict(os.environ, env):
            os.environ.pop("OLYMPUS_INGEST_SIGNING_KEY", None)
            with TestClient(app) as client:
                response = client.get("/v1/federation/status")
        assert response.status_code == 200
        data = response.json()
        assert data["local_node_id"] is None


# ---------------------------------------------------------------------------
# POST /v1/federation/sign-header — 503 guard paths
# ---------------------------------------------------------------------------


class TestSignHeaderGuardPaths:
    def test_503_when_guardian_disabled(self) -> None:
        from api.main import app

        with patch.dict(os.environ, {"OLYMPUS_GUARDIAN_ENABLED": "false"}):
            with TestClient(app) as client:
                response = client.post("/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY)
        assert response.status_code == 503
        assert "Guardian replication is not enabled" in response.json()["detail"]

    def test_503_when_registry_missing(self) -> None:
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        env = {
            "OLYMPUS_GUARDIAN_ENABLED": "true",
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": "/nonexistent/path/registry.json",
            "OLYMPUS_INGEST_SIGNING_KEY": _NODE1_SIGNING_KEY_HEX,
        }
        with patch.dict(os.environ, env):
            with TestClient(app) as client:
                response = client.post("/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY)
        assert response.status_code == 503
        assert "registry" in response.json()["detail"].lower()

    def test_503_when_signing_key_missing(self) -> None:
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        env = {
            "OLYMPUS_GUARDIAN_ENABLED": "true",
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": REGISTRY_PATH,
        }
        with patch.dict(os.environ, env):
            os.environ.pop("OLYMPUS_INGEST_SIGNING_KEY", None)
            with TestClient(app) as client:
                response = client.post("/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY)
        assert response.status_code == 503
        assert "signing key" in response.json()["detail"].lower()

    def test_503_when_local_node_not_in_registry(self) -> None:
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        # Use a signing key that is NOT in the registry
        import nacl.signing

        foreign_key = nacl.signing.SigningKey.generate()
        foreign_key_hex = bytes(foreign_key).hex()

        env = {
            "OLYMPUS_GUARDIAN_ENABLED": "true",
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": REGISTRY_PATH,
            "OLYMPUS_INGEST_SIGNING_KEY": foreign_key_hex,
        }
        with patch.dict(os.environ, env):
            with TestClient(app) as client:
                response = client.post("/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY)
        assert response.status_code == 503
        assert "Local node not found" in response.json()["detail"]


# ---------------------------------------------------------------------------
# POST /v1/federation/sign-header — 400 validation paths
# ---------------------------------------------------------------------------


class TestSignHeaderValidationPaths:
    def _post(self, body: dict) -> tuple[int, dict]:
        from api.db import get_db
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        mock_session = _make_mock_db_session(local_root=None)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = override_get_db
        try:
            with patch.dict(os.environ, _GUARDIAN_ENV):
                with TestClient(app) as client:
                    response = client.post("/v1/federation/sign-header", json=body)
            return response.status_code, response.json()
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_400_wrong_domain_tag(self) -> None:
        body = {**_VALID_SIGN_HEADER_BODY, "domain": "WRONG:DOMAIN:V1"}
        status, data = self._post(body)
        assert status == 400
        assert "domain tag" in data["detail"].lower()

    def test_400_missing_header_hash(self) -> None:
        header_no_hash = {
            "shard_id": "test.shard",
            "root_hash": "cc" * 32,
            "timestamp": "2026-04-14T12:00:00Z",
        }
        body = {**_VALID_SIGN_HEADER_BODY, "header": header_no_hash}
        status, data = self._post(body)
        assert status == 400
        assert "header_hash" in data["detail"]

    def test_400_shard_root_mismatch_with_header_hash(self) -> None:
        body = {
            **_VALID_SIGN_HEADER_BODY,
            "shard_root": "aa" * 32,  # differs from header.header_hash = "cc"*32
        }
        status, data = self._post(body)
        assert status == 400
        assert "shard_root" in data["detail"]


# ---------------------------------------------------------------------------
# POST /v1/federation/sign-header — 409 fork detection
# ---------------------------------------------------------------------------


class TestSignHeaderForkDetection:
    def test_409_on_root_mismatch(self) -> None:
        """When local DB root differs from incoming root, return 409."""
        from api.db import get_db
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        local_root = "dd" * 32  # different from incoming "cc" * 32
        mock_session = _make_mock_db_session(local_root=local_root)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = override_get_db
        try:
            with patch.dict(os.environ, _GUARDIAN_ENV):
                with TestClient(app) as client:
                    response = client.post(
                        "/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY
                    )
            assert response.status_code == 409
            detail = response.json()["detail"]
            assert detail["fork_detected"] is True
            assert detail["shard_id"] == "test.shard"
            assert detail["local_header_hash"] == "dd" * 32
            assert detail["remote_header_hash"] == "cc" * 32
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_no_fork_when_roots_match(self) -> None:
        """When local DB root matches incoming root, signing proceeds."""
        from api.db import get_db
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        # Local root matches incoming root_hash
        matching_root = "cc" * 32
        mock_session = _make_mock_db_session(local_root=matching_root)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = override_get_db
        try:
            with patch.dict(os.environ, _GUARDIAN_ENV):
                with TestClient(app) as client:
                    response = client.post(
                        "/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY
                    )
            # Roots match, so no fork: signing must succeed
            assert response.status_code == 200
        finally:
            app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# POST /v1/federation/sign-header — successful signing
# ---------------------------------------------------------------------------


class TestSignHeaderSuccess:
    def test_200_returns_node_id_and_signature(self) -> None:
        from api.db import get_db
        from api.main import app
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        # DB returns None so no fork check triggers
        mock_session = _make_mock_db_session(local_root=None)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db] = override_get_db
        try:
            with patch.dict(os.environ, _GUARDIAN_ENV):
                with TestClient(app) as client:
                    response = client.post(
                        "/v1/federation/sign-header", json=_VALID_SIGN_HEADER_BODY
                    )
            assert response.status_code == 200
            data = response.json()
            assert data["node_id"] == "olympus-node-1"
            # Signature is a 128-char hex string (64 bytes Ed25519)
            assert len(data["signature"]) == 128
        finally:
            app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# _env_flag_enabled helper (private, tested via observable behaviour)
# ---------------------------------------------------------------------------


class TestEnvFlagEnabled:
    @pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE", "YES"])
    def test_truthy_values(self, val: str) -> None:
        from api.routers.federation import _env_flag_enabled

        with patch.dict(os.environ, {"TEST_FLAG": val}):
            assert _env_flag_enabled("TEST_FLAG") is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", ""])
    def test_falsy_values(self, val: str) -> None:
        from api.routers.federation import _env_flag_enabled

        with patch.dict(os.environ, {"TEST_FLAG": val}):
            assert _env_flag_enabled("TEST_FLAG") is False

    def test_missing_env_var(self) -> None:
        from api.routers.federation import _env_flag_enabled

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TEST_FLAG", None)
            assert _env_flag_enabled("TEST_FLAG") is False


# ---------------------------------------------------------------------------
# _get_local_signing_key helper
# ---------------------------------------------------------------------------


class TestGetLocalSigningKey:
    def test_returns_key_when_env_set(self) -> None:
        from api.routers.federation import _get_local_signing_key

        with patch.dict(os.environ, {"OLYMPUS_INGEST_SIGNING_KEY": _NODE1_SIGNING_KEY_HEX}):
            key = _get_local_signing_key()
        assert key is not None
        assert (
            key.verify_key.encode().hex()
            == "3e86f08f516951ff0c69815cfc4ed7cf1f0b44651aa5c7472f67623449c09425"
        )

    def test_returns_none_when_env_not_set(self) -> None:
        from api.routers.federation import _get_local_signing_key

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OLYMPUS_INGEST_SIGNING_KEY", None)
            key = _get_local_signing_key()
        assert key is None

    def test_returns_none_for_invalid_hex(self) -> None:
        from api.routers.federation import _get_local_signing_key

        with patch.dict(os.environ, {"OLYMPUS_INGEST_SIGNING_KEY": "not-hex"}):
            key = _get_local_signing_key()
        assert key is None

    def test_returns_none_for_wrong_length(self) -> None:
        from api.routers.federation import _get_local_signing_key

        with patch.dict(os.environ, {"OLYMPUS_INGEST_SIGNING_KEY": "deadbeef"}):
            key = _get_local_signing_key()
        assert key is None


# ---------------------------------------------------------------------------
# Registry caching (_get_guardian_registry)
# ---------------------------------------------------------------------------


class TestRegistryCaching:
    def test_cache_is_reused_on_second_call(self) -> None:
        from api.routers import federation as fed_mod

        fed_mod._registry_cache = None

        with patch.dict(os.environ, _GUARDIAN_ENV):
            r1 = fed_mod._get_guardian_registry()
            r2 = fed_mod._get_guardian_registry()
        assert r1 is r2  # Same object from cache

    def test_cache_invalidated_on_mtime_change(self, tmp_path: Path) -> None:
        """If registry file mtime changes the cache should be invalidated."""
        import json

        from api.routers import federation as fed_mod

        # Write a valid registry to a temp file
        registry_data = json.loads(Path(REGISTRY_PATH).read_text())
        registry_file = tmp_path / "registry.json"
        registry_file.write_text(json.dumps(registry_data))

        env = {
            **_GUARDIAN_ENV,
            "OLYMPUS_GUARDIAN_REGISTRY_PATH": str(registry_file),
        }
        fed_mod._registry_cache = None

        with patch.dict(os.environ, env):
            r1 = fed_mod._get_guardian_registry()
            # Advance mtime by 5 s — deterministic on all filesystem mtime resolutions
            current_mtime = registry_file.stat().st_mtime
            os.utime(registry_file, (current_mtime + 5, current_mtime + 5))
            r2 = fed_mod._get_guardian_registry()

        # Different object instances (cache was invalidated and reloaded)
        assert r1 is not r2
