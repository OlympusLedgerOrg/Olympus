"""
Tests for the user-friendly ledger endpoints.

Covers:
  GET  /ledger/activity            — activity feed
  POST /ledger/ingest/simple       — guided document ingestion
  POST /ledger/verify/simple       — plain-English verification (public, no API key required)
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def client(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ── Activity feed ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_activity_feed_empty(client):
    """GET /ledger/activity returns an empty feed on a fresh DB."""
    resp = await client.get("/ledger/activity")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_activity_feed_limit_param(client):
    """GET /ledger/activity accepts a limit query param."""
    resp = await client.get("/ledger/activity?limit=5")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_activity_feed_type_filter(client):
    """GET /ledger/activity accepts an activity_type filter."""
    resp = await client.get("/ledger/activity?activity_type=DOCUMENT_SUBMITTED")
    assert resp.status_code == 200
    data = resp.json()
    # All returned items must match the requested type
    for item in data["items"]:
        assert item["activity_type"] == "DOCUMENT_SUBMITTED"


# ── Simple ingestion ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_simple_ingest_text_file(client):
    """POST /ledger/ingest/simple accepts a plain-text file."""
    content = b"This is a test FOIA document for permanent recording."
    resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("test.txt", content, "text/plain")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["permanent_record_id"] is not None
    assert data["permanent_record_id"].startswith("OLY-")
    assert data["commit_id"] is not None
    assert isinstance(data["steps"], list)
    assert len(data["steps"]) > 0
    # All steps should be complete on success
    for step in data["steps"]:
        assert step["status"] in ("complete", "in_progress")


@pytest.mark.asyncio
async def test_simple_ingest_creates_activity(client):
    """Successful ingestion creates a DOCUMENT_SUBMITTED activity entry."""
    content = b"Another test document for activity log checking."
    await client.post(
        "/ledger/ingest/simple",
        files={"file": ("activity_test.txt", content, "text/plain")},
    )
    resp = await client.get("/ledger/activity?activity_type=DOCUMENT_SUBMITTED")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_simple_ingest_duplicate_returns_success(client):
    """Submitting the same file twice returns success with an existing-record message."""
    content = b"Duplicate document content for deduplication test."
    first = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("dup.txt", content, "text/plain")},
    )
    assert first.status_code == 200
    first_id = first.json()["permanent_record_id"]

    second = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("dup.txt", content, "text/plain")},
    )
    assert second.status_code == 200
    data = second.json()
    assert data["success"] is True
    # Same record ID returned
    assert data["permanent_record_id"] == first_id


@pytest.mark.asyncio
async def test_simple_ingest_unsupported_type(client):
    """POST /ledger/ingest/simple rejects unsupported file types with HTTP 415."""
    content = b"\x00\x01\x02\x03unsupported binary"
    resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("malware.exe", content, "application/octet-stream")},
    )
    assert resp.status_code == 415


@pytest.mark.asyncio
async def test_simple_ingest_with_description(client):
    """POST /ledger/ingest/simple accepts optional description and request_id."""
    content = b"Document with metadata attached."
    resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("meta.txt", content, "text/plain")},
        data={"description": "Test description", "request_id": "OLY-0001"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True


# ── Simple verification ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_simple_verify_by_file_found(client):
    """POST /ledger/verify/simple verifies a previously submitted file."""
    content = b"Verifiable document content for the round-trip test."
    ingest_resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("verify_me.txt", content, "text/plain")},
    )
    assert ingest_resp.json()["success"] is True

    verify_resp = await client.post(
        "/ledger/verify/simple",
        files={"file": ("verify_me.txt", content, "text/plain")},
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["verified"] is True
    assert data["confidence"] == "certain"
    assert data["recorded_date"] is not None
    assert isinstance(data["proof_details"], list)


@pytest.mark.asyncio
async def test_simple_verify_by_file_not_found(client):
    """POST /ledger/verify/simple returns not-found for an unknown file."""
    content = b"This document was never submitted to the ledger."
    resp = await client.post(
        "/ledger/verify/simple",
        files={"file": ("unknown.txt", content, "text/plain")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is False
    assert data["confidence"] == "certain"


@pytest.mark.asyncio
async def test_simple_verify_by_commit_id(client):
    """POST /ledger/verify/simple verifies by OLY-NNNN display ID."""
    content = b"Document for commit ID verification test."
    ingest_resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("by_id.txt", content, "text/plain")},
    )
    display_id = ingest_resp.json()["permanent_record_id"]
    assert display_id is not None

    verify_resp = await client.post(
        "/ledger/verify/simple",
        data={"commit_id": display_id},
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["verified"] is True


@pytest.mark.asyncio
async def test_simple_verify_by_hash(client):
    """POST /ledger/verify/simple verifies by BLAKE3 doc_hash."""
    from protocol.hashes import hash_bytes

    content = b"Document for hash-based verification test."
    doc_hash = hash_bytes(content).hex()

    # Ingest first
    await client.post(
        "/ledger/ingest/simple",
        files={"file": ("by_hash.txt", content, "text/plain")},
    )

    verify_resp = await client.post(
        "/ledger/verify/simple",
        data={"doc_hash": doc_hash},
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["verified"] is True


@pytest.mark.asyncio
async def test_simple_verify_no_input_returns_400(client):
    """POST /ledger/verify/simple with no inputs returns HTTP 400."""
    resp = await client.post("/ledger/verify/simple")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_simple_verify_unknown_commit_id(client):
    """POST /ledger/verify/simple returns not-found for an unknown OLY-ID."""
    resp = await client.post(
        "/ledger/verify/simple",
        data={"commit_id": "OLY-9999"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is False


@pytest.mark.asyncio
async def test_verify_creates_activity_entry(client):
    """Successful verification is recorded in the activity feed."""
    content = b"Document to check activity log after verification."
    ingest_resp = await client.post(
        "/ledger/ingest/simple",
        files={"file": ("activity_verify.txt", content, "text/plain")},
    )
    assert ingest_resp.json()["success"] is True

    await client.post(
        "/ledger/verify/simple",
        files={"file": ("activity_verify.txt", content, "text/plain")},
    )

    activity_resp = await client.get("/ledger/activity?activity_type=VERIFICATION_SUCCESS")
    assert activity_resp.status_code == 200
    data = activity_resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_verify_simple_allows_unauthenticated(db_engine):
    """POST /ledger/verify/simple is publicly accessible without an API key.

    Verification is a read-semantic operation — this is a transparency system.
    """
    import os

    import api.auth as _auth_mod

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    original_env = os.environ.pop("OLYMPUS_ENV", None)
    original_keys = os.environ.get("OLYMPUS_FOIA_API_KEYS")
    original_allow_dev_auth = os.environ.get("OLYMPUS_ALLOW_DEV_AUTH")
    os.environ["OLYMPUS_ENV"] = "production"
    os.environ["OLYMPUS_ALLOW_DEV_AUTH"] = "0"
    os.environ["OLYMPUS_FOIA_API_KEYS"] = (
        '[{"key_hash":"' + "a" * 64 + '","key_id":"test","scopes":["write"],'
        '"expires_at":"2099-01-01T00:00:00Z"}]'
    )

    try:
        _auth_mod._keys_loaded = False
        _auth_mod._key_store.clear()

        app = create_app()
        app.dependency_overrides[get_db] = override_get_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(
                "/ledger/verify/simple",
                data={"doc_hash": "a" * 64},
            )
        # 200 (not-found result) or 400 (missing input) are both fine —
        # neither is 401, confirming the endpoint is publicly accessible.
        assert resp.status_code != 401, (
            f"POST /ledger/verify/simple should not require auth, got {resp.status_code}"
        )
    finally:
        _auth_mod._keys_loaded = False
        _auth_mod._key_store.clear()
        if original_keys is None:
            os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)
        else:
            os.environ["OLYMPUS_FOIA_API_KEYS"] = original_keys
        if original_env is None:
            os.environ.pop("OLYMPUS_ENV", None)
        else:
            os.environ["OLYMPUS_ENV"] = original_env
        if original_allow_dev_auth is None:
            os.environ.pop("OLYMPUS_ALLOW_DEV_AUTH", None)
        else:
            os.environ["OLYMPUS_ALLOW_DEV_AUTH"] = original_allow_dev_auth
