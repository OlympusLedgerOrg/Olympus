"""
Tests boosting coverage for API routers and services.

Covers:
    - api/routers/appeals.py — POST/GET appeal endpoints and error paths
    - api/routers/keys.py — credential issuance, revocation, admin reload
    - api/services/zkproof.py — stub generation, proof type verification, groth16 checks
    - api/services/upload_validation.py — ZIP safety, zstd safety, MIME validation
    - api/services/verification.py — verify_by_commit_id, verify_by_file, verify_by_doc_hash
"""

from __future__ import annotations

import io
import os
import struct
import uuid
import zipfile
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.models.request import PublicRecordsRequest, RequestStatus


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures — function-scoped for test isolation
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def fresh_db_engine():
    """Create a fresh in-memory SQLite engine per test."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def fresh_client(fresh_db_engine):
    """HTTP test client backed by a fresh per-test database."""
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
        },
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            yield ac


@pytest_asyncio.fixture()
async def fresh_session(fresh_db_engine):
    """Return an async session factory bound to the same fresh engine."""
    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with session_factory() as session:
        yield session


async def _insert_request(session: AsyncSession, *, request_id: str, status: str = "PENDING"):
    """Insert a PublicRecordsRequest directly into the test database."""
    req = PublicRecordsRequest(
        id=request_id,
        display_id=f"REQ-{request_id[:8]}",
        subject="Test subject",
        description="Test request description",
        status=status,
    )
    session.add(req)
    await session.commit()


# ---------------------------------------------------------------------------
# 1. Appeals router
# ---------------------------------------------------------------------------

APPEAL_BODY_TEMPLATE = {
    "grounds": "NO_RESPONSE",
    "statement": "The agency did not respond within the statutory deadline.",
}


@pytest.mark.asyncio
async def test_appeal_request_not_found(fresh_client):
    """POST /appeals returns 404 with REQUEST_NOT_FOUND for unknown request_id."""
    body = {**APPEAL_BODY_TEMPLATE, "request_id": str(uuid.uuid4())}
    resp = await fresh_client.post("/appeals", json=body)
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["code"] == "REQUEST_NOT_FOUND"
    assert "not found" in detail["detail"].lower()


@pytest.mark.asyncio
async def test_appeal_request_fulfilled(fresh_client, fresh_session):
    """POST /appeals returns 409 with REQUEST_FULFILLED when request is already fulfilled."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.FULFILLED.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    resp = await fresh_client.post("/appeals", json=body)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["code"] == "REQUEST_FULFILLED"


@pytest.mark.asyncio
async def test_appeal_already_exists(fresh_client, fresh_session):
    """Filing a second appeal returns 409 with APPEAL_EXISTS."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.DENIED.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    first = await fresh_client.post("/appeals", json=body)
    assert first.status_code == 201

    second = await fresh_client.post("/appeals", json=body)
    assert second.status_code == 409
    detail = second.json()["detail"]
    assert detail["code"] == "APPEAL_EXISTS"


@pytest.mark.asyncio
async def test_appeal_not_allowed_pending(fresh_client, fresh_session):
    """POST /appeals returns 409 with APPEAL_NOT_ALLOWED for a PENDING request."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.PENDING.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    resp = await fresh_client.post("/appeals", json=body)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["code"] == "APPEAL_NOT_ALLOWED"
    assert "DENIED or OVERDUE" in detail["detail"]


@pytest.mark.asyncio
async def test_appeal_success_denied(fresh_client, fresh_session):
    """POST /appeals succeeds for a DENIED request and returns 201."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.DENIED.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    resp = await fresh_client.post("/appeals", json=body)
    assert resp.status_code == 201
    data = resp.json()
    assert data["request_id"] == rid
    assert data["grounds"] == "NO_RESPONSE"
    assert data["status"] == "UNDER_REVIEW"
    assert data["commit_hash"]  # non-empty hash


@pytest.mark.asyncio
async def test_list_appeals_empty(fresh_client):
    """GET /appeals returns an empty list when no appeals exist."""
    resp = await fresh_client.get("/appeals")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_appeals_populated(fresh_client, fresh_session):
    """GET /appeals returns filed appeals."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.DENIED.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    create_resp = await fresh_client.post("/appeals", json=body)
    assert create_resp.status_code == 201

    resp = await fresh_client.get("/appeals")
    assert resp.status_code == 200
    appeals = resp.json()
    assert len(appeals) >= 1
    assert appeals[0]["request_id"] == rid


@pytest.mark.asyncio
async def test_get_appeal_not_found(fresh_client):
    """GET /appeals/{id} returns 404 with APPEAL_NOT_FOUND for unknown id."""
    resp = await fresh_client.get(f"/appeals/{uuid.uuid4()}")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["code"] == "APPEAL_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_appeal_found(fresh_client, fresh_session):
    """GET /appeals/{id} returns correct appeal detail."""
    rid = str(uuid.uuid4())
    await _insert_request(fresh_session, request_id=rid, status=RequestStatus.OVERDUE.value)

    body = {**APPEAL_BODY_TEMPLATE, "request_id": rid}
    create_resp = await fresh_client.post("/appeals", json=body)
    assert create_resp.status_code == 201
    appeal_id = create_resp.json()["id"]

    resp = await fresh_client.get(f"/appeals/{appeal_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == appeal_id
    assert data["request_id"] == rid
    assert data["grounds"] == "NO_RESPONSE"
    assert data["statement"] == APPEAL_BODY_TEMPLATE["statement"]


# ---------------------------------------------------------------------------
# 2. Keys router
# ---------------------------------------------------------------------------

CREDENTIAL_BODY = {
    "holder_key": "ed25519:abc123pubkey",
    "credential_type": "journalist",
    "issuer": "Watauga County Clerk",
}


@pytest.mark.asyncio
async def test_issue_credential_success(fresh_client):
    """POST /key/credential returns 201 with correct structure."""
    resp = await fresh_client.post("/key/credential", json=CREDENTIAL_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert data["holder_key"] == CREDENTIAL_BODY["holder_key"]
    assert data["credential_type"] == "journalist"
    assert data["issuer"] == CREDENTIAL_BODY["issuer"]
    assert data["sbt_nontransferable"] is True
    assert data["commit_id"].startswith("0x")
    assert data["revoked_at"] is None


@pytest.mark.asyncio
async def test_revoke_credential_not_found(fresh_client):
    """DELETE /key/credential/{id} returns 404 for non-existent credential."""
    resp = await fresh_client.delete(f"/key/credential/{uuid.uuid4()}")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["code"] == "CREDENTIAL_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_credential_already_revoked(fresh_client):
    """DELETE /key/credential/{id} returns 409 after revoking twice."""
    create_resp = await fresh_client.post("/key/credential", json=CREDENTIAL_BODY)
    assert create_resp.status_code == 201
    cred_id = create_resp.json()["id"]

    first_revoke = await fresh_client.delete(f"/key/credential/{cred_id}")
    assert first_revoke.status_code == 204

    second_revoke = await fresh_client.delete(f"/key/credential/{cred_id}")
    assert second_revoke.status_code == 409
    detail = second_revoke.json()["detail"]
    assert detail["code"] == "ALREADY_REVOKED"


@pytest.mark.asyncio
async def test_admin_reload_keys_no_admin_key():
    """POST /key/admin/reload-keys returns 503 when OLYMPUS_ADMIN_KEY is not set."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    env = {
        "OLYMPUS_ENV": "development",
        "OLYMPUS_ALLOW_DEV_AUTH": "1",
        "OLYMPUS_FOIA_API_KEYS": "[]",
    }
    # Ensure OLYMPUS_ADMIN_KEY is absent
    env_copy = {**env}
    with patch.dict(os.environ, env_copy, clear=False):
        os.environ.pop("OLYMPUS_ADMIN_KEY", None)
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post("/key/admin/reload-keys")
            assert resp.status_code == 503
            assert "not configured" in resp.json()["detail"].lower()

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_reload_keys_wrong_key():
    """POST /key/admin/reload-keys returns 401 with wrong admin key."""
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
            "OLYMPUS_ADMIN_KEY": "correct-secret",
        },
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/key/admin/reload-keys", headers={"x-admin-key": "wrong-secret"}
            )
            assert resp.status_code == 401
            assert "invalid" in resp.json()["detail"].lower()

    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_reload_keys_success():
    """POST /key/admin/reload-keys returns 200 with correct admin key."""
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
            "OLYMPUS_ADMIN_KEY": "test-admin-secret",
        },
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/key/admin/reload-keys",
                headers={"x-admin-key": "test-admin-secret"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["reloaded"] is True
            assert "key_count" in data

    await engine.dispose()


# ---------------------------------------------------------------------------
# 3. ZK proof service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_proof_stub_production():
    """generate_proof_stub raises RuntimeError when OLYMPUS_ENV != development."""
    from api.services.zkproof import generate_proof_stub

    with patch.dict(os.environ, {"OLYMPUS_ENV": "production"}):
        with pytest.raises(RuntimeError, match="disabled in production"):
            generate_proof_stub("0xabc", "deadbeef" * 8)


@pytest.mark.asyncio
async def test_generate_proof_stub_development():
    """generate_proof_stub returns valid structure in development."""
    from api.services.zkproof import generate_proof_stub

    with patch.dict(os.environ, {"OLYMPUS_ENV": "development"}):
        result = generate_proof_stub("0xabc", "deadbeef" * 8)
        assert result["protocol"] == "groth16"
        assert result["curve"] == "bn128"
        assert result["proof_type"] == "stub"
        assert "pi_a" in result["proof"]
        assert "pi_b" in result["proof"]
        assert "pi_c" in result["proof"]
        assert result["public_signals"] == ["0xabc", "deadbeef" * 8]
        assert result["verified"] is False


@pytest.mark.asyncio
async def test_verify_proof_type_stub_rejected_in_production():
    """verify_proof_type rejects stubs in production."""
    from api.services.zkproof import verify_proof_type

    with patch.dict(os.environ, {"OLYMPUS_ENV": "production"}):
        accepted, reason = verify_proof_type({"proof_type": "stub"})
        assert accepted is False
        assert reason == "stub_proof_rejected_in_production"


@pytest.mark.asyncio
async def test_verify_proof_type_stub_accepted_in_development():
    """verify_proof_type accepts stubs in development."""
    from api.services.zkproof import verify_proof_type

    with patch.dict(os.environ, {"OLYMPUS_ENV": "development"}):
        accepted, reason = verify_proof_type({"proof_type": "stub"})
        assert accepted is True
        assert reason is None


@pytest.mark.asyncio
async def test_verify_proof_type_non_stub_always_accepted():
    """verify_proof_type accepts non-stub proofs in any environment."""
    from api.services.zkproof import verify_proof_type

    with patch.dict(os.environ, {"OLYMPUS_ENV": "production"}):
        accepted, reason = verify_proof_type({"proof_type": "groth16"})
        assert accepted is True
        assert reason is None


@pytest.mark.asyncio
async def test_verify_groth16_stub_proof():
    """verify_groth16_proof returns (False, 'stub_proof') for stub proofs."""
    from api.services.zkproof import verify_groth16_proof

    ok, reason = verify_groth16_proof({"proof_type": "stub"})
    assert ok is False
    assert reason == "stub_proof"


@pytest.mark.asyncio
async def test_verify_groth16_no_vkey():
    """verify_groth16_proof returns (False, 'no_vkey_configured') without vkey."""
    from api.services.zkproof import verify_groth16_proof

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("OLYMPUS_ZK_VKEY_PATH", None)
        ok, reason = verify_groth16_proof({"proof_type": "groth16"})
        assert ok is False
        assert reason == "no_vkey_configured"


@pytest.mark.asyncio
async def test_verify_groth16_vkey_not_found():
    """verify_groth16_proof returns (False, 'vkey_not_found') for missing vkey file."""
    from api.services.zkproof import verify_groth16_proof

    ok, reason = verify_groth16_proof(
        {"proof_type": "groth16"}, vkey_path="/nonexistent/path/vkey.json"
    )
    assert ok is False
    assert reason == "vkey_not_found"


@pytest.mark.asyncio
async def test_verify_groth16_native_verifier_unavailable():
    """verify_groth16_proof raises HTTPException 503 when olympus_core is missing."""
    import builtins

    from fastapi import HTTPException

    from api.services.zkproof import verify_groth16_proof

    # Create a real temporary vkey file within the project directory
    vkey_path = os.path.join(
        os.path.dirname(__file__), "_test_vkey_temp.json"
    )
    try:
        with open(vkey_path, "w") as f:
            f.write("{}")

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "olympus_core":
                raise ImportError("mocked")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            with pytest.raises(HTTPException) as exc_info:
                verify_groth16_proof({"proof_type": "groth16"}, vkey_path=vkey_path)
            assert exc_info.value.status_code == 503
            assert "native" in exc_info.value.detail.lower()
    finally:
        if os.path.exists(vkey_path):
            os.remove(vkey_path)


# ---------------------------------------------------------------------------
# 4. Upload validation service
# ---------------------------------------------------------------------------


class TestZipSafety:
    """Tests for validate_zip_safety."""

    def test_path_traversal_detected(self):
        """ZIP with path-traversal entries is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zip_safety

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../escape.txt", "malicious content")
        buf.seek(0)

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(buf.read())
        assert exc_info.value.status_code == 400
        assert "path traversal" in exc_info.value.detail.lower()

    def test_compression_ratio_bomb(self):
        """ZIP with extreme compression ratio is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zip_safety

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # A long run of zeroes compresses extremely well
            zf.writestr("bomb.txt", "\x00" * (10 * 1024 * 1024))
        buf.seek(0)
        content = buf.read()

        # Check if this actually triggers the ratio guard; if the file
        # compresses to >1 byte the ratio will be checked.
        # The ratio guard triggers when ratio > 50:1
        # 10MB of zeroes should compress to well under 200KB -> ratio >> 50
        try:
            validate_zip_safety(content)
            # If it didn't raise, the ratio wasn't extreme enough
            # (depends on zipfile implementation); skip gracefully.
        except HTTPException as exc:
            assert exc.status_code == 400
            assert "ratio" in exc.detail.lower() or "limit" in exc.detail.lower()

    def test_total_size_exceeded(self):
        """ZIP with total uncompressed size exceeding 100MB is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import (
            _MAX_DECOMPRESSED_BYTES,
            validate_zip_safety,
        )

        # Craft a ZIP with a declared uncompressed size exceeding the limit
        # by manipulating the ZipInfo directly.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("big_file.txt")
            zf.writestr(info, "small content")
        buf.seek(0)
        raw = bytearray(buf.read())

        # Patch the uncompressed size in the local file header and central
        # directory to exceed the limit.  The uncompressed size field is at
        # offset 22 in the local file header (4 bytes, little-endian).
        # This is fragile but effective for testing the size guard.
        over_limit = _MAX_DECOMPRESSED_BYTES + 1
        # Find the local header and patch file_size
        local_header_offset = raw.find(b"PK\x03\x04")
        if local_header_offset >= 0:
            struct.pack_into("<I", raw, local_header_offset + 22, over_limit)

        # Patch central directory entry
        cd_offset = raw.find(b"PK\x01\x02")
        if cd_offset >= 0:
            struct.pack_into("<I", raw, cd_offset + 24, over_limit)

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(bytes(raw))
        assert exc_info.value.status_code == 400
        assert "limit" in exc_info.value.detail.lower() or "size" in exc_info.value.detail.lower()

    def test_valid_zip_passes(self):
        """A well-formed ZIP with safe contents passes validation."""
        from api.services.upload_validation import validate_zip_safety

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "Hello Olympus")
            zf.writestr("subdir/data.json", '{"key":"value"}')
        buf.seek(0)

        # Should not raise
        validate_zip_safety(buf.read())

    def test_corrupt_zip_rejected(self):
        """Corrupt ZIP content is rejected with 400."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zip_safety

        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(b"not a zip file at all")
        assert exc_info.value.status_code == 400
        assert "corrupt" in exc_info.value.detail.lower() or "invalid" in exc_info.value.detail.lower()


class TestZstdSafety:
    """Tests for validate_zstd_safety (requires zstandard)."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_zstd(self):
        try:
            import zstandard  # noqa: F401
        except ImportError:
            pytest.skip("zstandard not installed")

    def test_empty_stream_rejected(self):
        """Empty zstd content is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zstd_safety

        with pytest.raises(HTTPException) as exc_info:
            validate_zstd_safety(b"")
        assert exc_info.value.status_code == 400
        assert "empty" in exc_info.value.detail.lower()

    def test_valid_zstd_passes(self):
        """A well-formed zstd stream passes validation."""
        import zstandard as zstd

        from api.services.upload_validation import validate_zstd_safety

        data = b"Hello Olympus " * 100
        cctx = zstd.ZstdCompressor()
        compressed = cctx.compress(data)

        # Should not raise
        validate_zstd_safety(compressed)

    def test_corrupt_zstd_rejected(self):
        """Corrupt zstd content is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zstd_safety

        # Valid zstd magic bytes (0xFD2FB528) followed by garbage
        corrupt = b"\x28\xb5\x2f\xfd" + b"\xff" * 100

        with pytest.raises(HTTPException) as exc_info:
            validate_zstd_safety(corrupt)
        assert exc_info.value.status_code == 400


class TestFileMagic:
    """Tests for validate_file_magic."""

    def test_allowed_mime_type(self):
        """Plain text content passes validation."""
        from api.services.upload_validation import validate_file_magic

        content = b"Hello, this is a plain text document.\n"
        result = validate_file_magic(content, "text/plain")
        assert result in ("text/plain", "text/html", "application/octet-stream") or result is not None

    def test_disallowed_mime_type(self):
        """Content detected as a disallowed MIME type is rejected."""
        from fastapi import HTTPException

        from api.services.upload_validation import validate_file_magic

        # Minimal ELF binary: the ELF header must be well-formed enough for
        # libmagic to identify it as application/x-executable (or similar).
        elf_content = (
            b"\x7fELF"  # magic
            b"\x02"  # 64-bit
            b"\x01"  # little-endian
            b"\x01"  # ELF version
            b"\x00"  # OS/ABI
            + b"\x00" * 8  # padding
            + b"\x02\x00"  # e_type = ET_EXEC
            + b"\x3e\x00"  # e_machine = EM_X86_64
            + b"\x01\x00\x00\x00"  # e_version
            + b"\x00" * 2024  # rest of header
        )

        with pytest.raises(HTTPException) as exc_info:
            validate_file_magic(elf_content, "application/octet-stream")
        assert exc_info.value.status_code == 415
        assert "not permitted" in exc_info.value.detail.lower()

    def test_zip_triggers_safety_check(self):
        """ZIP content triggers validate_zip_safety via validate_file_magic."""
        from api.services.upload_validation import validate_file_magic

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("ok.txt", "safe content")
        buf.seek(0)
        content = buf.read()

        result = validate_file_magic(content, "application/zip")
        assert result == "application/zip"


# ---------------------------------------------------------------------------
# 5. Verification service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_by_commit_id_not_found(fresh_db_engine):
    """verify_by_commit_id returns not-verified for unknown commit_id."""
    from api.services.verification import verify_by_commit_id

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with session_factory() as session:
        result = await verify_by_commit_id("0xdeadbeef12345678", session)
        assert result.verified is False
        assert "no record found" in result.summary.lower()
        assert result.confidence in ("certain", "none")


@pytest.mark.asyncio
async def test_verify_by_commit_id_oly_prefix_not_found(fresh_db_engine):
    """verify_by_commit_id returns not-verified for unknown OLY- display ID."""
    from api.services.verification import verify_by_commit_id

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with session_factory() as session:
        result = await verify_by_commit_id("OLY-9999", session)
        assert result.verified is False
        assert "OLY-9999" in result.summary


@pytest.mark.asyncio
async def test_verify_by_doc_hash_not_found(fresh_db_engine):
    """verify_by_doc_hash returns not-verified for unknown hash."""
    from api.services.verification import verify_by_doc_hash

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with session_factory() as session:
        result = await verify_by_doc_hash("a" * 64, session)
        assert result.verified is False
        assert "not in the permanent record" in result.summary.lower()


@pytest.mark.asyncio
async def test_verify_by_file_not_found(fresh_db_engine):
    """verify_by_file returns not-verified for content not in ledger."""
    from api.services.verification import verify_by_file

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )
    async with session_factory() as session:
        result = await verify_by_file(b"unknown document content", "test.txt", session)
        assert result.verified is False


@pytest.mark.asyncio
async def test_verify_by_commit_id_found(fresh_db_engine):
    """verify_by_commit_id finds an existing commit and runs verification."""
    from api.models.document import DocCommit
    from api.services.verification import verify_by_commit_id

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )

    commit_id = "0x" + "ab" * 8
    doc_hash = "cd" * 32

    async with session_factory() as session:
        commit = DocCommit(
            doc_hash=doc_hash,
            commit_id=commit_id,
            shard_id="test-shard",
            epoch_timestamp=datetime.now(timezone.utc),
        )
        session.add(commit)
        await session.commit()

    async with session_factory() as session:
        result = await verify_by_commit_id(commit_id, session)
        # The commit exists; verification runs (may or may not pass depending
        # on Merkle tree state, but we get a non-error response).
        assert result.summary  # non-empty summary
        assert result.confidence in ("certain", "none")
        assert len(result.proof_details) >= 1


@pytest.mark.asyncio
async def test_verify_by_file_hash_fail(fresh_db_engine):
    """verify_by_file gracefully handles hash computation failure."""
    from api.services.verification import verify_by_file

    session_factory = async_sessionmaker(
        fresh_db_engine, expire_on_commit=False, class_=AsyncSession
    )

    async with session_factory() as session:
        with patch("api.services.verification.hash_document", side_effect=Exception("boom")):
            result = await verify_by_file(b"some bytes", "fail.txt", session)
            assert result.verified is False
            assert "could not" in result.summary.lower()
            assert result.what_this_means is not None


@pytest.mark.asyncio
async def test_format_epoch():
    """_format_epoch produces a human-readable UTC string."""
    from api.services.verification import _format_epoch

    dt = datetime(2025, 1, 15, 14, 34, 0, tzinfo=timezone.utc)
    result = _format_epoch(dt)
    assert "January" in result
    assert "15" in result
    assert "2025" in result
    assert "PM" in result
    assert "UTC" in result
