"""
Tests for the DB-backed user auth endpoints introduced in PR #768.

Covers:
    - POST /auth/register â€” happy path, duplicate email, weak password,
      privileged-scope rejection.
    - POST /auth/login â€” happy path, invalid credentials.
    - POST /auth/keys, GET /auth/keys, DELETE /auth/keys/{id} â€” auth flow,
      subset-of-caller-scopes enforcement, listing, revocation, 401.
    - POST /key/admin/generate â€” missing admin key (503), wrong admin key
      (401), success path with response shape.
"""

from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import AsyncMock, patch

import nacl.signing
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.routers.keys import signing_key_binding_payload


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def fresh_db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def auth_client(fresh_db_engine):
    """HTTP client with the user_auth and keys routers wired to a fresh DB."""
    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )

    async def override_get_db():
        async with session_factory() as session:
            yield session

    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_ALLOW_DEV_AUTH": "1",
            "OLYMPUS_FOIA_API_KEYS": "[]",
            "OLYMPUS_ADMIN_KEY": "test-admin-secret",
            "OLYMPUS_RETURN_RECOVERY_TOKEN": "1",
        },
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


REG_BODY = {
    "email": "alice@example.com",
    "password": "supersecretpw1234",
    "name": "alice-key",
    "scopes": ["read", "verify"],
    "expires_at": "2099-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# /auth/register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_success(auth_client):
    resp = await auth_client.post("/auth/register", json=REG_BODY)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["email"] == REG_BODY["email"]
    assert data["scopes"] == ["read", "verify"]
    assert len(data["api_key"]) == 64  # 32 bytes hex
    assert data["user_id"]
    assert data["key_id"]


@pytest.mark.asyncio
async def test_register_duplicate_email_conflict(auth_client):
    # Bypass the per-IP 1/min registration limiter so this test exercises the
    # duplicate-email branch (409) directly rather than racing against the
    # rate-limit guardrail in registration_rate_limit().
    with patch("api.routers.user_auth.registration_rate_limit", new=AsyncMock(return_value=None)):
        first = await auth_client.post("/auth/register", json=REG_BODY)
        assert first.status_code == 201
        second = await auth_client.post("/auth/register", json=REG_BODY)
        assert second.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password_rejected(auth_client):
    body = {**REG_BODY, "password": "short"}
    resp = await auth_client.post("/auth/register", json=body)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_rejects_privileged_scope(auth_client):
    """Self-service registration must not allow callers to mint admin/write keys."""
    for bad_scope in ("admin", "write"):
        body = {**REG_BODY, "email": f"{bad_scope}@example.com", "scopes": ["ingest", bad_scope]}
        resp = await auth_client.post("/auth/register", json=body)
        assert resp.status_code == 403, resp.text
        assert bad_scope in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_rejects_unknown_scope(auth_client):
    body = {**REG_BODY, "scopes": ["ingest", "bogus"]}
    resp = await auth_client.post("/auth/register", json=body)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /auth/login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    resp = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": REG_BODY["password"]},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["email"] == REG_BODY["email"]
    assert len(data["keys"]) == 1
    assert data["keys"][0]["scopes"] == ["read", "verify"]


@pytest.mark.asyncio
async def test_login_wrong_password(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)
    resp = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": "wrong-password-xx"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_email(auth_client):
    resp = await auth_client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "anything12345"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /auth/reissue-key recovery path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reissue_defaults_to_read_verify_without_scope_escalation(auth_client):
    """Password-based recovery must not turn a default account into a write account."""
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201

    resp = await auth_client.post(
        "/auth/reissue-key",
        json={"email": REG_BODY["email"], "password": REG_BODY["password"]},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["read", "verify"]


@pytest.mark.asyncio
async def test_reissue_rejects_scopes_not_already_active_on_account(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)

    resp = await auth_client.post(
        "/auth/reissue-key",
        json={
            "email": REG_BODY["email"],
            "password": REG_BODY["password"],
            "scopes": ["ingest", "commit", "write"],
        },
    )
    assert resp.status_code == 403, resp.text
    assert "ingest" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reissue_allows_subset_of_existing_privileged_key(auth_client):
    body = {
        "email": "writer@example.com",
        "password": "supersecretpw1234",
        "scopes": ["read", "verify", "ingest", "commit"],
    }
    create = await auth_client.post(
        "/auth/admin/users",
        headers={"x-admin-key": "test-admin-secret"},
        json=body,
    )
    assert create.status_code == 201, create.text

    resp = await auth_client.post(
        "/auth/reissue-key",
        json={
            "email": body["email"],
            "password": body["password"],
            "scopes": ["verify", "ingest"],
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["verify", "ingest"]


@pytest.mark.asyncio
async def test_reissue_expired_existing_key_does_not_grant_privileged_scopes(auth_client):
    body = {
        "email": "expired-writer@example.com",
        "password": "supersecretpw1234",
        "scopes": ["read", "verify", "ingest"],
        "expires_at": "2000-01-01T00:00:00Z",
    }
    create = await auth_client.post(
        "/auth/admin/users",
        headers={"x-admin-key": "test-admin-secret"},
        json=body,
    )
    assert create.status_code == 201, create.text

    resp = await auth_client.post(
        "/auth/reissue-key",
        json={"email": body["email"], "password": body["password"], "scopes": ["ingest"]},
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_reissue_unknown_email_and_wrong_password_are_indistinguishable(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)

    wrong_password = await auth_client.post(
        "/auth/reissue-key",
        json={"email": REG_BODY["email"], "password": "wrong-password-xx"},
    )
    unknown_email = await auth_client.post(
        "/auth/reissue-key",
        json={"email": "nobody@example.com", "password": "wrong-password-xx"},
    )

    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


@pytest.mark.asyncio
async def test_reissue_rejects_extra_account_binding_fields_safely(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)

    resp = await auth_client.post(
        "/auth/reissue-key",
        json={
            "email": REG_BODY["email"],
            "password": REG_BODY["password"],
            "user_id": "00000000-0000-0000-0000-000000000000",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_reissue_cannot_overwrite_another_users_keys(auth_client):
    with patch("api.routers.user_auth.registration_rate_limit", new=AsyncMock(return_value=None)):
        alice = {**REG_BODY, "email": "alice-recovery@example.com"}
        bob = {**REG_BODY, "email": "bob-recovery@example.com"}
        alice_reg = await auth_client.post("/auth/register", json=alice)
        bob_reg = await auth_client.post("/auth/register", json=bob)
    assert alice_reg.status_code == 201
    assert bob_reg.status_code == 201
    bob_key = bob_reg.json()["api_key"]

    recovered = await auth_client.post(
        "/auth/reissue-key",
        json={"email": alice["email"], "password": alice["password"]},
    )
    assert recovered.status_code == 201, recovered.text

    bob_listing = await auth_client.get("/auth/keys", headers={"X-API-Key": bob_key})
    assert bob_listing.status_code == 200
    assert len(bob_listing.json()) == 1


@pytest.mark.asyncio
async def test_reissue_keeps_existing_keys_active_intentionally(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    original_key = reg.json()["api_key"]

    recovered = await auth_client.post(
        "/auth/reissue-key",
        json={"email": REG_BODY["email"], "password": REG_BODY["password"]},
    )
    assert recovered.status_code == 201, recovered.text

    listing_with_original = await auth_client.get("/auth/keys", headers={"X-API-Key": original_key})
    assert listing_with_original.status_code == 200
    assert len(listing_with_original.json()) == 2


def test_dev_auth_recovery_bootstrap_flag_is_rejected_outside_development():
    from api.main import _assert_dev_auth_flag_restricted_to_development

    with patch.dict(
        os.environ,
        {"OLYMPUS_ENV": "production", "OLYMPUS_ALLOW_DEV_AUTH": "1"},
        clear=False,
    ):
        with pytest.raises(RuntimeError):
            _assert_dev_auth_flag_restricted_to_development()


# ---------------------------------------------------------------------------
# /auth/recovery/* tokenized recovery path
# ---------------------------------------------------------------------------


async def _request_recovery_token(client: AsyncClient, email: str) -> str:
    resp = await client.post("/auth/recovery/request", json={"email": email})
    assert resp.status_code == 202, resp.text
    token = resp.json().get("recovery_token")
    assert token
    return token


@pytest.mark.asyncio
async def test_recovery_token_is_single_use_and_replay_is_rejected(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    token = await _request_recovery_token(auth_client, REG_BODY["email"])

    first = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": token, "new_password": "new-supersecretpw1234"},
    )
    assert first.status_code == 201, first.text
    old_login = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": REG_BODY["password"]},
    )
    new_login = await auth_client.post(
        "/auth/login",
        json={"email": REG_BODY["email"], "password": "new-supersecretpw1234"},
    )
    assert old_login.status_code == 401
    assert new_login.status_code == 200

    replay = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": token, "new_password": "another-supersecretpw1234"},
    )
    assert replay.status_code == 400
    assert replay.json()["detail"] == "Invalid or expired recovery token."


@pytest.mark.asyncio
async def test_recovery_token_expires(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    token = await _request_recovery_token(auth_client, REG_BODY["email"])

    from datetime import datetime

    with patch("api.routers.user_auth._naive_utc", return_value=datetime(2100, 1, 1)):
        expired = await auth_client.post(
            "/auth/recovery/complete",
            json={"token": token, "new_password": "new-supersecretpw1234"},
        )
    assert expired.status_code == 400


@pytest.mark.asyncio
async def test_recovery_request_does_not_reveal_whether_account_exists(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)

    with patch.dict(os.environ, {"OLYMPUS_RETURN_RECOVERY_TOKEN": ""}, clear=False):
        existing = await auth_client.post(
            "/auth/recovery/request", json={"email": REG_BODY["email"]}
        )
        missing = await auth_client.post(
            "/auth/recovery/request", json={"email": "missing@example.com"}
        )

    assert existing.status_code == 202
    assert missing.status_code == 202
    assert existing.json() == missing.json()


@pytest.mark.asyncio
async def test_recovery_token_is_bound_to_owning_account_and_revokes_existing_keys(auth_client):
    with patch("api.routers.user_auth.registration_rate_limit", new=AsyncMock(return_value=None)):
        alice = {**REG_BODY, "email": "alice-token@example.com"}
        bob = {**REG_BODY, "email": "bob-token@example.com"}
        alice_reg = await auth_client.post("/auth/register", json=alice)
        bob_reg = await auth_client.post("/auth/register", json=bob)
    assert alice_reg.status_code == 201
    assert bob_reg.status_code == 201
    alice_old_key = alice_reg.json()["api_key"]
    bob_key = bob_reg.json()["api_key"]
    token = await _request_recovery_token(auth_client, alice["email"])

    complete = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": token, "new_password": "new-supersecretpw1234"},
    )
    assert complete.status_code == 201, complete.text
    alice_new_key = complete.json()["api_key"]

    alice_old_listing = await auth_client.get("/auth/keys", headers={"X-API-Key": alice_old_key})
    assert alice_old_listing.status_code == 401
    alice_new_listing = await auth_client.get("/auth/keys", headers={"X-API-Key": alice_new_key})
    assert alice_new_listing.status_code == 200
    bob_listing = await auth_client.get("/auth/keys", headers={"X-API-Key": bob_key})
    assert bob_listing.status_code == 200
    assert len(bob_listing.json()) == 1


@pytest.mark.asyncio
async def test_recovery_can_intentionally_keep_existing_keys_active(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    original_key = reg.json()["api_key"]
    token = await _request_recovery_token(auth_client, REG_BODY["email"])

    complete = await auth_client.post(
        "/auth/recovery/complete",
        json={
            "token": token,
            "new_password": "new-supersecretpw1234",
            "revoke_existing_keys": False,
        },
    )
    assert complete.status_code == 201, complete.text

    listing = await auth_client.get("/auth/keys", headers={"X-API-Key": original_key})
    assert listing.status_code == 200
    assert len(listing.json()) == 2


@pytest.mark.asyncio
async def test_recovery_rejects_foreign_account_binding_fields_safely(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)
    token = await _request_recovery_token(auth_client, REG_BODY["email"])

    resp = await auth_client.post(
        "/auth/recovery/complete",
        json={
            "token": token,
            "new_password": "new-supersecretpw1234",
            "user_id": "00000000-0000-0000-0000-000000000000",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_recovery_caps_scopes_to_existing_active_account_grants(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)
    token = await _request_recovery_token(auth_client, REG_BODY["email"])

    resp = await auth_client.post(
        "/auth/recovery/complete",
        json={
            "token": token,
            "new_password": "new-supersecretpw1234",
            "scopes": ["ingest", "commit", "write"],
        },
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_recovery_token_response_dev_hook_is_unavailable_in_production(auth_client):
    await auth_client.post("/auth/register", json=REG_BODY)

    with patch.dict(
        os.environ,
        {"OLYMPUS_ENV": "production", "OLYMPUS_RETURN_RECOVERY_TOKEN": "1"},
        clear=False,
    ):
        resp = await auth_client.post("/auth/recovery/request", json={"email": REG_BODY["email"]})

    assert resp.status_code == 202
    assert resp.json()["recovery_token"] is None
    assert resp.json()["expires_at"] is None


@pytest.mark.asyncio
async def test_recovery_errors_are_safe_4xx_responses(auth_client):
    malformed = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": "not-a-real-token", "new_password": "new-supersecretpw1234"},
    )
    weak_password = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": "not-a-real-token", "new_password": "short"},
    )

    assert malformed.status_code == 400
    assert weak_password.status_code == 422
    assert "Traceback" not in malformed.text
    assert "Traceback" not in weak_password.text


# ---------------------------------------------------------------------------
# /key/signing account signing-key provisioning
# ---------------------------------------------------------------------------


def _make_signing_registration(label: str = "dataset-key", purpose: str = "dataset"):
    signing_key = nacl.signing.SigningKey.generate()
    public_key = bytes(signing_key.verify_key).hex()
    signature = signing_key.sign(
        signing_key_binding_payload(public_key=public_key, label=label, purpose=purpose)
    ).signature.hex()
    return signing_key, {
        "public_key": public_key,
        "label": label,
        "purpose": purpose,
        "proof_signature": signature,
    }


@pytest.mark.asyncio
async def test_register_signing_key_is_account_bound_and_stores_public_only(auth_client):
    api_key = await _register_and_get_key(auth_client)
    signing_key, payload = _make_signing_registration()

    resp = await auth_client.post("/key/signing", headers={"X-API-Key": api_key}, json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["public_key"] == payload["public_key"]
    assert body["label"] == "dataset-key"

    listing = await auth_client.get("/key/signing", headers={"X-API-Key": api_key})
    assert listing.status_code == 200
    serialized = str(listing.json())
    assert payload["public_key"] in serialized
    assert bytes(signing_key).hex() not in serialized


@pytest.mark.asyncio
async def test_signing_key_registration_requires_private_key_proof(auth_client):
    api_key = await _register_and_get_key(auth_client)
    _signing_key, payload = _make_signing_registration()
    payload["proof_signature"] = "00" * 64

    resp = await auth_client.post("/key/signing", headers={"X-API-Key": api_key}, json=payload)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_signing_key_cannot_be_registered_to_another_account(auth_client):
    with patch("api.routers.user_auth.registration_rate_limit", new=AsyncMock(return_value=None)):
        alice_key = await _register_and_get_key(auth_client, email="alice-signing@example.com")
        bob_key = await _register_and_get_key(auth_client, email="bob-signing@example.com")
    _signing_key, payload = _make_signing_registration()

    first = await auth_client.post("/key/signing", headers={"X-API-Key": alice_key}, json=payload)
    second = await auth_client.post("/key/signing", headers={"X-API-Key": bob_key}, json=payload)

    assert first.status_code == 201, first.text
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_recovery_does_not_change_registered_signing_keys(auth_client):
    reg = await auth_client.post("/auth/register", json=REG_BODY)
    assert reg.status_code == 201
    original_api_key = reg.json()["api_key"]
    _signing_key, payload = _make_signing_registration()
    registered = await auth_client.post(
        "/key/signing", headers={"X-API-Key": original_api_key}, json=payload
    )
    assert registered.status_code == 201

    token = await _request_recovery_token(auth_client, REG_BODY["email"])
    recovered = await auth_client.post(
        "/auth/recovery/complete",
        json={"token": token, "new_password": "new-supersecretpw1234"},
    )
    assert recovered.status_code == 201
    recovered_api_key = recovered.json()["api_key"]

    listing = await auth_client.get("/key/signing", headers={"X-API-Key": recovered_api_key})
    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert listing.json()[0]["public_key"] == payload["public_key"]
    assert listing.json()[0]["revoked_at"] is None


@pytest.mark.asyncio
async def test_signing_key_rotation_is_explicit_and_records_replacement(auth_client):
    api_key = await _register_and_get_key(auth_client)
    _old_key, old_payload = _make_signing_registration(label="old")
    _new_key, new_payload = _make_signing_registration(label="new")
    old_resp = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=old_payload
    )
    new_resp = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=new_payload
    )
    assert old_resp.status_code == 201
    assert new_resp.status_code == 201

    old_id = old_resp.json()["key_id"]
    new_id = new_resp.json()["key_id"]
    revoked = await auth_client.delete(
        f"/key/signing/{old_id}?replaced_by_key_id={new_id}",
        headers={"X-API-Key": api_key},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_at"] is not None
    assert revoked.json()["replaced_by_key_id"] == new_id


@pytest.mark.asyncio
async def test_erc5484_wallet_challenge_records_formal_consent(auth_client):
    api_key = await _register_and_get_key(auth_client)
    _signing_key, payload = _make_signing_registration(label="ledger")
    registered = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=payload
    )
    assert registered.status_code == 201
    key_id = registered.json()["key_id"]

    challenge = await auth_client.post(
        f"/key/signing/{key_id}/wallet/challenge",
        headers={"X-API-Key": api_key},
        json={
            "wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
            "burn_authorization": "issuer_only",
        },
    )
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    assert body["erc_standard"] == "ERC-5484"
    assert body["burn_authorization"] == "issuer_only"
    assert body["wallet_address"] == "0x1234567890abcdef1234567890abcdef12345678"
    assert '"erc_standard":"ERC-5484"' in body["message"]
    assert '"consent":' in body["message"]
    assert '"burn_authorization":"issuer_only"' in body["message"]


@pytest.mark.asyncio
async def test_erc5484_wallet_binding_requires_matching_wallet_signature(auth_client):
    api_key = await _register_and_get_key(auth_client)
    _signing_key, payload = _make_signing_registration()
    registered = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=payload
    )
    key_id = registered.json()["key_id"]
    wallet = "0x1234567890abcdef1234567890abcdef12345678"
    challenge = await auth_client.post(
        f"/key/signing/{key_id}/wallet/challenge",
        headers={"X-API-Key": api_key},
        json={"wallet_address": wallet},
    )
    assert challenge.status_code == 201, challenge.text
    challenge_id = challenge.json()["challenge_id"]

    with patch("api.routers.keys._recover_eth_message_address", return_value=wallet):
        verified = await auth_client.post(
            f"/key/signing/{key_id}/wallet/verify",
            headers={"X-API-Key": api_key},
            json={"challenge_id": challenge_id, "signature": "0x" + "11" * 65},
        )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["erc_standard"] == "ERC-5484"
    assert body["burn_authorization"] == "issuer_only"
    assert body["wallet_address"] == wallet
    assert body["verified_at"]


@pytest.mark.asyncio
async def test_erc5484_wallet_binding_rejects_mismatched_wallet_signature(auth_client):
    api_key = await _register_and_get_key(auth_client)
    _signing_key, payload = _make_signing_registration()
    registered = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=payload
    )
    key_id = registered.json()["key_id"]
    wallet = "0x1234567890abcdef1234567890abcdef12345678"
    challenge = await auth_client.post(
        f"/key/signing/{key_id}/wallet/challenge",
        headers={"X-API-Key": api_key},
        json={"wallet_address": wallet},
    )
    assert challenge.status_code == 201, challenge.text

    with patch(
        "api.routers.keys._recover_eth_message_address",
        return_value="0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    ):
        verified = await auth_client.post(
            f"/key/signing/{key_id}/wallet/verify",
            headers={"X-API-Key": api_key},
            json={"challenge_id": challenge.json()["challenge_id"], "signature": "0x" + "22" * 65},
        )
    assert verified.status_code == 403


@pytest.mark.asyncio
async def test_revoked_signing_key_cannot_be_used_for_dataset_commit(auth_client):
    from api.routers.datasets import _require_active_key_credential

    api_key = await _register_and_get_key(auth_client)
    _signing_key, payload = _make_signing_registration()
    registered = await auth_client.post(
        "/key/signing", headers={"X-API-Key": api_key}, json=payload
    )
    assert registered.status_code == 201
    key_id = registered.json()["key_id"]
    revoked = await auth_client.delete(f"/key/signing/{key_id}", headers={"X-API-Key": api_key})
    assert revoked.status_code == 200

    # Use the app's DB dependency to get the same test session wiring.
    override = next(iter(auth_client._transport.app.dependency_overrides.values()))  # type: ignore[attr-defined]
    async for session in override():
        with pytest.raises(Exception) as exc:
            await _require_active_key_credential(session, payload["public_key"])
        assert getattr(exc.value, "status_code", None) == 403
        break


@pytest.mark.asyncio
async def test_dev_generated_signing_key_is_gated_and_public_only_in_db(auth_client):
    api_key = await _register_and_get_key(auth_client)

    denied = await auth_client.post(
        "/key/signing/dev-generate",
        headers={"X-API-Key": api_key},
        json={"label": "dev", "purpose": "dataset"},
    )
    assert denied.status_code == 404

    with patch.dict(os.environ, {"OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP": "1"}, clear=False):
        created = await auth_client.post(
            "/key/signing/dev-generate",
            headers={"X-API-Key": api_key},
            json={"label": "dev", "purpose": "dataset"},
        )
    assert created.status_code == 201, created.text
    body = created.json()
    assert len(body["private_key"]) == 64
    listing = await auth_client.get("/key/signing", headers={"X-API-Key": api_key})
    assert body["private_key"] not in str(listing.json())


def test_signing_key_cli_generates_local_keypair_without_server(tmp_path):
    output_prefix = tmp_path / "operator-signing"
    result = subprocess.run(
        [
            sys.executable,
            "tools/signing_key_cli.py",
            "--json",
            "--label",
            "operator",
            "--purpose",
            "dataset",
            "--output-prefix",
            str(output_prefix),
        ],
        cwd=os.getcwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    import json as _json

    body = _json.loads(result.stdout)
    assert len(body["private_key"]) == 64
    assert len(body["public_key"]) == 64
    assert (tmp_path / "operator-signing.priv").read_text(encoding="ascii").strip() == body[
        "private_key"
    ]
    assert (tmp_path / "operator-signing.pub").read_text(encoding="ascii").strip() == body[
        "public_key"
    ]


# ---------------------------------------------------------------------------
# /auth/keys (CRUD)
# ---------------------------------------------------------------------------


async def _register_and_get_key(client: AsyncClient, **overrides) -> str:
    body = {**REG_BODY, **overrides}
    resp = await client.post("/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["api_key"]


@pytest.mark.asyncio
async def test_create_key_requires_auth(auth_client):
    resp = await auth_client.post("/auth/keys", json={"name": "k2"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_list_revoke_key_flow(auth_client):
    api_key = await _register_and_get_key(auth_client)
    headers = {"X-API-Key": api_key}

    create = await auth_client.post(
        "/auth/keys",
        headers=headers,
        json={"name": "second-key", "scopes": ["verify"], "expires_at": "2099-01-01T00:00:00Z"},
    )
    assert create.status_code == 201, create.text
    new_key_id = create.json()["key_id"]
    assert create.json()["scopes"] == ["verify"]

    listing = await auth_client.get("/auth/keys", headers=headers)
    assert listing.status_code == 200
    ids = {k["id"] for k in listing.json()}
    assert new_key_id in ids
    assert len(ids) == 2  # original + new

    revoke = await auth_client.delete(f"/auth/keys/{new_key_id}", headers=headers)
    assert revoke.status_code == 204

    listing2 = await auth_client.get("/auth/keys", headers=headers)
    remaining = {k["id"] for k in listing2.json()}
    assert new_key_id not in remaining


@pytest.mark.asyncio
async def test_create_key_rejects_scope_escalation(auth_client):
    """A key with scopes=[read,verify] must not be able to mint an admin key."""
    api_key = await _register_and_get_key(auth_client)
    headers = {"X-API-Key": api_key}

    resp = await auth_client.post(
        "/auth/keys",
        headers=headers,
        json={"name": "escalated", "scopes": ["ingest", "admin"]},
    )
    assert resp.status_code == 403, resp.text
    assert "admin" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_key_subset_allowed(auth_client):
    """Creating a key with a strict subset of caller's scopes is allowed."""
    api_key = await _register_and_get_key(auth_client, scopes=["read", "verify"])
    headers = {"X-API-Key": api_key}
    resp = await auth_client.post(
        "/auth/keys", headers=headers, json={"name": "narrow", "scopes": ["verify"]}
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scopes"] == ["verify"]


@pytest.mark.asyncio
async def test_revoke_key_not_found(auth_client):
    api_key = await _register_and_get_key(auth_client)
    resp = await auth_client.delete(
        "/auth/keys/00000000-0000-0000-0000-000000000000",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /key/admin/generate
# ---------------------------------------------------------------------------


GEN_BODY = {
    "name": "ops-key",
    "scopes": ["read", "verify"],
    "expires_at": "2099-01-01T00:00:00Z",
}


@pytest.mark.asyncio
async def test_admin_generate_no_admin_key():
    """503 when OLYMPUS_ADMIN_KEY is not configured."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_ALLOW_DEV_AUTH": "1",
            "OLYMPUS_FOIA_API_KEYS": "[]",
        },
        clear=False,
    ):
        os.environ.pop("OLYMPUS_ADMIN_KEY", None)
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/key/admin/generate", json=GEN_BODY)
            assert resp.status_code == 503

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_generate_wrong_key(auth_client):
    """401 when the X-Admin-Key header is wrong."""
    resp = await auth_client.post(
        "/key/admin/generate",
        headers={"x-admin-key": "wrong"},
        json=GEN_BODY,
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_generate_success(auth_client):
    """200/201 with full response shape when admin key is correct."""
    resp = await auth_client.post(
        "/key/admin/generate",
        headers={"x-admin-key": "test-admin-secret"},
        json=GEN_BODY,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert len(data["raw_key"]) == 64
    assert len(data["key_hash"]) == 64
    assert data["key_id"] == "ops-key"
    assert data["scopes"] == ["read", "verify"]
    assert data["expires_at"] == "2099-01-01T00:00:00Z"
    # env_entry must be valid JSON containing the key_hash
    import json as _json

    entry = _json.loads(data["env_entry"])
    assert entry["key_hash"] == data["key_hash"]
    assert entry["key_id"] == "ops-key"
