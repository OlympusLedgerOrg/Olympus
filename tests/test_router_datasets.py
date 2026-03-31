"""
Integration tests for the datasets provenance router (api/routers/datasets.py).

Covers:
    - POST /datasets/commit — happy path, duplicate, invalid signature, missing fields
    - GET /datasets — empty list, paginated results, filter by status
    - GET /datasets/{dataset_id} — found, not found
    - GET /datasets/{dataset_id}/verify — verification pass, verification fail
    - GET /datasets/{dataset_id}/history — single version, multi-version chain
    - POST /datasets/{dataset_id}/lineage — happy path, dataset not found

Uses in-memory SQLite with aiosqlite and mocks RFC 3161 timestamp requests.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import nacl.signing
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import api.auth as auth_module
from api.deps import get_db
from api.main import create_app
from api.models import Base
from protocol.hashes import (
    DATASET_LINEAGE_PREFIX,
    blake3_hash,
    compute_dataset_commit_id,
    dataset_key,
    hash_bytes,
)


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anyio_backend():
    """Configure pytest-asyncio to use the asyncio backend."""
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    """Create an in-memory SQLite database engine for tests."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def client(db_engine):
    """Create an async HTTP test client with overridden DB dependency."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    # Set development mode and no API keys for test bypass
    with patch.dict(
        os.environ,
        {"OLYMPUS_ENV": "development", "OLYMPUS_ALLOW_DEV_AUTH": "1", "OLYMPUS_FOIA_API_KEYS": "[]"},
    ):
        app = create_app()
        app.dependency_overrides[get_db] = override_get_db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


def create_signing_keypair() -> tuple[str, str, nacl.signing.SigningKey]:
    """Generate a new Ed25519 keypair for testing.

    Returns:
        Tuple of (pubkey_hex, private_key_hex, signing_key).
    """
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    pubkey_hex = bytes(verify_key).hex()
    return pubkey_hex, bytes(signing_key).hex(), signing_key


def sign_commit(signing_key: nacl.signing.SigningKey, commit_id: str) -> str:
    """Sign a commit_id with the given Ed25519 signing key.

    Returns:
        128-character hex-encoded signature.
    """
    signed = signing_key.sign(bytes.fromhex(commit_id))
    return signed.signature.hex()


def build_commit_request(
    pubkey_hex: str,
    signing_key: nacl.signing.SigningKey,
    dataset_name: str = "test-dataset",
    dataset_version: str = "1.0.0",
    source_uri: str = "https://example.com/data.csv",
    canonical_namespace: str = "test.namespace",
    parent_commit_id: str | None = None,
) -> dict:
    """Build a complete DatasetCommitRequest body with valid signature.

    Computes the deterministic commit_id and signs it.
    """
    from protocol.canonical_json import canonical_json_bytes

    files = [
        {
            "path": "data.csv",
            "content_hash": "a" * 64,
            "byte_size": 1024,
            "record_count": 100,
        }
    ]

    # Build canonical manifest to compute manifest_hash
    manifest_dict = {
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": canonical_namespace,
        "granularity": "file",
        "license_spdx": "MIT",
        "license_uri": None,
        "usage_restrictions": [],
        "file_format": "csv",
        "files": files,
        "manifest_schema_version": "dataset_manifest_v1",
    }
    manifest_bytes = canonical_json_bytes(manifest_dict)
    manifest_hash = blake3_hash([manifest_bytes]).hex()

    # Compute dataset_id
    ds_id = dataset_key(dataset_name, source_uri, canonical_namespace, pubkey_hex)

    # Compute commit_id (content-only, no timestamp)
    commit_id = compute_dataset_commit_id(
        ds_id,
        parent_commit_id or "",
        manifest_hash,
        pubkey_hex,
    )

    # Sign the commit_id
    signature = sign_commit(signing_key, commit_id)

    return {
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": canonical_namespace,
        "granularity": "file",
        "license_spdx": "MIT",
        "license_uri": None,
        "usage_restrictions": [],
        "file_format": "csv",
        "files": files,
        "parent_dataset_id": None,
        "parent_commit_id": parent_commit_id,
        "transform_description": None,
        "committer_pubkey": pubkey_hex,
        "committer_label": "test-user",
        "commit_signature": signature,
        "manifest_schema_version": "dataset_manifest_v1",
    }


def build_lineage_request(
    pubkey_hex: str,
    signing_key: nacl.signing.SigningKey,
    dataset_id: str,
    parent_commit_id: str,
    model_id: str = "gpt-4",
    event_type: str = "training_started",
) -> dict:
    """Build a complete LineageCommitRequest body with valid signature.

    The commit_id computation matches the server implementation in
    api/routers/datasets.py (lines 678-679):
      payload = f"{dataset_id}:{parent_commit_id}:{model_id}:{committer_pubkey}"
      commit_id = blake3_hash([DATASET_LINEAGE_PREFIX, payload.encode()]).hex()

    Note: event_type is NOT included in commit_id, so different event_types
    for the same (dataset_id, model_id, committer_pubkey) will have the same
    commit_id and fail the unique constraint.
    """
    payload = f"{dataset_id}:{parent_commit_id}:{model_id}:{pubkey_hex}"
    commit_id = blake3_hash([DATASET_LINEAGE_PREFIX, payload.encode()]).hex()
    signature = sign_commit(signing_key, commit_id)

    return {
        "dataset_id": dataset_id,
        "model_id": model_id,
        "model_version": "1.0",
        "model_org": "OpenAI",
        "event_type": event_type,
        "committer_pubkey": pubkey_hex,
        "commit_signature": signature,
    }


# ---------------------------------------------------------------------------
# Mock RFC 3161 Timestamp Requests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_rfc3161():
    """Mock RFC 3161 timestamp requests to avoid network calls.

    The import happens inside the function body, so we patch at the source module.
    """
    mock_token = MagicMock()
    mock_token.tst_bytes = b"\x00" * 32
    mock_token.tsa_url = "https://freetsa.org/tsr"

    with patch("protocol.rfc3161.request_timestamp", return_value=mock_token):
        yield


# ---------------------------------------------------------------------------
# POST /datasets/commit Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_commit_dataset_happy_path(client):
    """POST /datasets/commit should create a dataset and return 201 with deterministic IDs."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="happy-path-test",
        source_uri="https://example.com/happy.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201, resp.text

    data = resp.json()
    assert len(data["dataset_id"]) == 64
    assert len(data["commit_id"]) == 64
    assert len(data["manifest_hash"]) == 64
    assert data["file_count"] == 1
    assert data["shard_id"] is not None
    assert data["timestamp_status"] in ("pending", "verified")


@pytest.mark.asyncio
async def test_commit_dataset_duplicate_manifest_returns_409(client):
    """POST /datasets/commit with the same content twice should return 409 Conflict."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="duplicate-test",
        source_uri="https://example.com/duplicate.csv",
    )

    # First commit succeeds
    resp1 = await client.post("/datasets/commit", json=body)
    assert resp1.status_code == 201

    # Second identical commit should return 409
    resp2 = await client.post("/datasets/commit", json=body)
    assert resp2.status_code == 409
    assert "Duplicate" in str(resp2.json())


@pytest.mark.asyncio
async def test_commit_dataset_invalid_signature_returns_403(client):
    """POST /datasets/commit with an invalid Ed25519 signature should return 403."""
    pubkey, _, _ = create_signing_keypair()
    _, _, other_signing_key = create_signing_keypair()

    # Build request but sign with a different key
    body = build_commit_request(pubkey, other_signing_key, dataset_name="bad-sig-test")

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 403
    assert "signature" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_commit_dataset_malformed_signature_returns_403(client):
    """POST /datasets/commit with a malformed signature should return 403."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(pubkey, signing_key, dataset_name="malformed-sig-test")
    # Replace signature with invalid hex
    body["commit_signature"] = "f" * 128

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 403
    assert "signature" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_commit_dataset_missing_required_fields_returns_422(client):
    """POST /datasets/commit without required fields should return 422 Validation Error."""
    resp = await client.post("/datasets/commit", json={"dataset_name": "incomplete"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_commit_dataset_invalid_pubkey_format_returns_422(client):
    """POST /datasets/commit with invalid pubkey format should return 422."""
    body = {
        "dataset_name": "test",
        "dataset_version": "1.0.0",
        "source_uri": "https://example.com/data.csv",
        "canonical_namespace": "test",
        "granularity": "file",
        "license_spdx": "MIT",
        "file_format": "csv",
        "files": [{"path": "a.csv", "content_hash": "a" * 64, "byte_size": 100}],
        "committer_pubkey": "invalid-not-hex",  # Invalid format
        "commit_signature": "a" * 128,
    }

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_commit_dataset_empty_files_returns_422(client):
    """POST /datasets/commit with empty files list should return 422."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(pubkey, signing_key)
    body["files"] = []  # Invalid: at least 1 file required

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_commit_dataset_invalid_source_uri_scheme_returns_422(client):
    """POST /datasets/commit rejects source_uri values without http(s) scheme."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(pubkey, signing_key, source_uri="ftp://example.com/data.csv")

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /datasets Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_datasets_empty(client):
    """GET /datasets should return an empty list when no datasets with matching filters exist."""
    resp = await client.get("/datasets", params={"search": "nonexistent-xyz-123"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1


@pytest.mark.asyncio
async def test_list_datasets_paginated_results(client):
    """GET /datasets should return paginated results."""
    pubkey, _, signing_key = create_signing_keypair()

    # Create multiple datasets
    for i in range(3):
        body = build_commit_request(
            pubkey,
            signing_key,
            dataset_name=f"paginated-test-{i}",
            source_uri=f"https://example.com/paginated-{i}.csv",
        )
        resp = await client.post("/datasets/commit", json=body)
        assert resp.status_code == 201

    # List with pagination
    resp = await client.get(
        "/datasets",
        params={"search": "paginated-test", "page": 1, "per_page": 2},
    )
    assert resp.status_code == 200

    data = resp.json()
    assert len(data["items"]) <= 2
    assert data["per_page"] == 2
    assert data["page"] == 1


@pytest.mark.asyncio
async def test_list_datasets_filter_by_timestamp_status(client):
    """GET /datasets with timestamp_status filter should return only matching datasets."""
    # Query for datasets with verified status
    resp = await client.get("/datasets", params={"timestamp_status": "verified"})
    assert resp.status_code == 200

    data = resp.json()
    for item in data["items"]:
        assert item["timestamp_status"] == "verified"


@pytest.mark.asyncio
async def test_list_datasets_filter_by_license(client):
    """GET /datasets with license filter should return only matching datasets."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="license-filter-test",
        source_uri="https://example.com/license-filter.csv",
    )
    body["license_spdx"] = "Apache-2.0"

    # Need to recompute commit_id with new manifest
    from protocol.canonical_json import canonical_json_bytes

    files = body["files"]
    manifest_dict = {
        "dataset_name": body["dataset_name"],
        "dataset_version": body["dataset_version"],
        "source_uri": body["source_uri"],
        "canonical_namespace": body["canonical_namespace"],
        "granularity": body["granularity"],
        "license_spdx": "Apache-2.0",
        "license_uri": body["license_uri"],
        "usage_restrictions": body["usage_restrictions"],
        "file_format": body["file_format"],
        "files": files,
        "manifest_schema_version": body["manifest_schema_version"],
    }
    manifest_bytes = canonical_json_bytes(manifest_dict)
    manifest_hash = blake3_hash([manifest_bytes]).hex()
    ds_id = dataset_key(
        body["dataset_name"],
        body["source_uri"],
        body["canonical_namespace"],
        pubkey,
    )
    commit_id = compute_dataset_commit_id(ds_id, "", manifest_hash, pubkey)
    body["commit_signature"] = sign_commit(signing_key, commit_id)

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201

    # Filter by license
    resp = await client.get("/datasets", params={"license": "Apache-2.0"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_list_datasets_filter_by_committer(client):
    """GET /datasets with committer filter should return only datasets from that pubkey."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="committer-filter-test",
        source_uri="https://example.com/committer-filter.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201

    # Filter by committer pubkey
    resp = await client.get("/datasets", params={"committer": pubkey})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    # Verify items exist (committer_pubkey not in list response, only in detail)
    assert len(data["items"]) >= 1


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id} Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_dataset_found(client):
    """GET /datasets/{dataset_id} should return 200 with full dataset details."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="get-test",
        source_uri="https://example.com/get-test.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    # Get the dataset
    resp = await client.get(f"/datasets/{dataset_id}")
    assert resp.status_code == 200

    data = resp.json()
    assert data["dataset_id"] == dataset_id
    assert data["dataset_name"] == "get-test"
    assert data["committer_pubkey"] == pubkey
    assert len(data["files"]) == 1
    assert data["files"][0]["path"] == "data.csv"


@pytest.mark.asyncio
async def test_get_dataset_not_found(client):
    """GET /datasets/{dataset_id} for a non-existent dataset should return 404."""
    fake_dataset_id = "0" * 64

    resp = await client.get(f"/datasets/{fake_dataset_id}")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}/verify Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_dataset_pass(client):
    """GET /datasets/{dataset_id}/verify should return verified=True for a valid dataset."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="verify-pass-test",
        source_uri="https://example.com/verify-pass.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    # Verify the dataset
    resp = await client.get(f"/datasets/{dataset_id}/verify")
    assert resp.status_code == 200

    data = resp.json()
    assert data["verified"] is True
    assert data["commit_id_valid"] is True
    assert data["signature_valid"] is True
    assert data["chain_valid"] is True
    assert data["key_revoked"] is False
    assert data["checks"]["commit_id_valid"] is True
    assert data["checks"]["signature_valid"] is True


@pytest.mark.asyncio
async def test_verify_dataset_not_found(client):
    """GET /datasets/{dataset_id}/verify for non-existent dataset should return verified=False."""
    fake_dataset_id = "1" * 64

    resp = await client.get(f"/datasets/{fake_dataset_id}/verify")
    assert resp.status_code == 200

    data = resp.json()
    assert data["verified"] is False
    assert data["dataset"] is None


@pytest.mark.asyncio
async def test_verify_dataset_with_rfc3161_status(client):
    """GET /datasets/{dataset_id}/verify should include RFC 3161 status in checks."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="verify-rfc3161-test",
        source_uri="https://example.com/verify-rfc3161.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    # Verify the dataset
    resp = await client.get(f"/datasets/{dataset_id}/verify")
    assert resp.status_code == 200

    data = resp.json()
    # RFC 3161 status should be in checks
    assert "rfc3161_valid" in data["checks"]


@pytest.mark.asyncio
async def test_verify_dataset_requires_api_key_outside_development(monkeypatch, db_engine):
    """GET /datasets/{dataset_id}/verify requires API key auth in non-development mode."""
    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)
    original_env = os.environ.get("OLYMPUS_FOIA_API_KEYS")
    test_key = "dataset-verify-key"
    test_key_hash = hash_bytes(test_key.encode("utf-8")).hex()
    fake_dataset_id = "0" * 64
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()
        monkeypatch.setenv("OLYMPUS_ENV", "production")
        monkeypatch.setenv("OLYMPUS_ALLOW_DEV_AUTH", "0")
        monkeypatch.setenv(
            "OLYMPUS_FOIA_API_KEYS",
            json.dumps(
                [
                    {
                        "key_hash": test_key_hash,
                        "key_id": "dataset-verify-key",
                        "scopes": ["read", "write"],
                        "expires_at": "2099-01-01T00:00:00Z",
                    }
                ]
            ),
        )

        async def override_get_db():
            async with session_factory() as session:
                yield session

        app = create_app()
        app.dependency_overrides[get_db] = override_get_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            unauthenticated = await ac.get(f"/datasets/{fake_dataset_id}/verify")
            assert unauthenticated.status_code == 401

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"X-API-Key": test_key},
        ) as ac:
            authorized = await ac.get(f"/datasets/{fake_dataset_id}/verify")
            assert authorized.status_code == 200
            assert authorized.json()["verified"] is False
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        if original_env is None:
            os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)
        else:
            os.environ["OLYMPUS_FOIA_API_KEYS"] = original_env


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}/history Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dataset_history_single_version(client):
    """GET /datasets/{dataset_id}/history should return single commit for genesis dataset."""
    pubkey, _, signing_key = create_signing_keypair()
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="history-single-test",
        source_uri="https://example.com/history-single.csv",
    )

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    # Get history
    resp = await client.get(f"/datasets/{dataset_id}/history")
    assert resp.status_code == 200

    data = resp.json()
    assert data["dataset_id"] == dataset_id
    assert len(data["commits"]) == 1
    assert data["commits"][0]["parent_commit_id"] == ""  # Genesis has no parent


@pytest.mark.asyncio
async def test_dataset_history_multi_version_chain(client):
    """GET /datasets/{dataset_id}/history should return ordered commits for multi-version dataset."""
    pubkey, _, signing_key = create_signing_keypair()

    # Create genesis commit
    body1 = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="history-multi-test",
        dataset_version="1.0.0",
        source_uri="https://example.com/history-multi.csv",
    )
    resp1 = await client.post("/datasets/commit", json=body1)
    assert resp1.status_code == 201
    dataset_id = resp1.json()["dataset_id"]
    commit_id_v1 = resp1.json()["commit_id"]

    # Create second version with parent
    body2 = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="history-multi-test",
        dataset_version="2.0.0",
        source_uri="https://example.com/history-multi.csv",
        parent_commit_id=commit_id_v1,
    )
    resp2 = await client.post("/datasets/commit", json=body2)
    assert resp2.status_code == 201
    _commit_id_v2 = resp2.json()["commit_id"]  # noqa: F841

    # Get history
    resp = await client.get(f"/datasets/{dataset_id}/history")
    assert resp.status_code == 200

    data = resp.json()
    assert data["dataset_id"] == dataset_id
    assert len(data["commits"]) == 2

    # History should be ordered by epoch_timestamp ascending
    versions = [c["dataset_version"] for c in data["commits"]]
    assert versions == ["1.0.0", "2.0.0"]

    # Verify chain integrity
    assert data["commits"][0]["parent_commit_id"] == ""  # Genesis
    assert data["commits"][1]["parent_commit_id"] == commit_id_v1


@pytest.mark.asyncio
async def test_dataset_history_not_found(client):
    """GET /datasets/{dataset_id}/history for non-existent dataset should return 404."""
    fake_dataset_id = "2" * 64

    resp = await client.get(f"/datasets/{fake_dataset_id}/history")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# POST /datasets/{dataset_id}/lineage Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_commit_lineage_happy_path(client):
    """POST /datasets/{dataset_id}/lineage should create a lineage event and return 201."""
    pubkey, _, signing_key = create_signing_keypair()

    # First create a dataset
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="lineage-test",
        source_uri="https://example.com/lineage.csv",
    )
    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]
    parent_commit_id = resp.json()["commit_id"]

    # Create lineage event
    lineage_body = build_lineage_request(
        pubkey,
        signing_key,
        dataset_id=dataset_id,
        parent_commit_id=parent_commit_id,
        model_id="test-model-v1",
        event_type="training_started",
    )

    resp = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage_body)
    assert resp.status_code == 201

    data = resp.json()
    assert data["dataset_id"] == dataset_id
    assert data["model_id"] == "test-model-v1"
    assert data["event_type"] == "training_started"
    assert len(data["commit_id"]) == 64


@pytest.mark.asyncio
async def test_commit_lineage_dataset_not_found(client):
    """POST /datasets/{dataset_id}/lineage for non-existent dataset should return 404."""
    pubkey, _, signing_key = create_signing_keypair()
    fake_dataset_id = "3" * 64

    lineage_body = build_lineage_request(
        pubkey,
        signing_key,
        dataset_id=fake_dataset_id,
        parent_commit_id="",
        model_id="test-model",
    )

    resp = await client.post(f"/datasets/{fake_dataset_id}/lineage", json=lineage_body)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_commit_lineage_invalid_signature_returns_403(client):
    """POST /datasets/{dataset_id}/lineage with invalid signature should return 403."""
    pubkey, _, signing_key = create_signing_keypair()
    _, _, other_signing_key = create_signing_keypair()

    # Create a dataset first
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="lineage-bad-sig-test",
        source_uri="https://example.com/lineage-bad-sig.csv",
    )
    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]
    parent_commit_id = resp.json()["commit_id"]

    # Create lineage with wrong signature (signed by different key)
    lineage_body = build_lineage_request(
        pubkey,  # Claiming to be pubkey
        other_signing_key,  # But signing with different key
        dataset_id=dataset_id,
        parent_commit_id=parent_commit_id,
        model_id="test-model",
    )

    resp = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage_body)
    assert resp.status_code == 403
    assert "signature" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_commit_lineage_duplicate_returns_409(client):
    """POST /datasets/{dataset_id}/lineage with same event twice should return 409."""
    pubkey, _, signing_key = create_signing_keypair()

    # Create a dataset
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="lineage-dup-test",
        source_uri="https://example.com/lineage-dup.csv",
    )
    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]
    parent_commit_id = resp.json()["commit_id"]

    # First lineage event
    lineage_body = build_lineage_request(
        pubkey,
        signing_key,
        dataset_id=dataset_id,
        parent_commit_id=parent_commit_id,
        model_id="dup-model",
        event_type="training_started",
    )
    resp1 = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage_body)
    assert resp1.status_code == 201

    # Duplicate lineage event (same dataset_id, model_id, event_type, committer_pubkey)
    resp2 = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage_body)
    assert resp2.status_code == 409
    assert "Duplicate" in str(resp2.json())


@pytest.mark.asyncio
async def test_commit_lineage_different_models_allowed(client):
    """POST /datasets/{dataset_id}/lineage allows multiple models to register lineage events.

    Each (dataset_id, model_id, committer_pubkey) tuple can have at most one lineage
    event due to how commit_id is computed (without event_type). Different model_ids
    are treated as independent lineage records.
    """
    pubkey, _, signing_key = create_signing_keypair()

    # Create a dataset
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="lineage-events-test",
        source_uri="https://example.com/lineage-events.csv",
    )
    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]
    parent_commit_id = resp.json()["commit_id"]

    # training_started event with model-1
    lineage1 = build_lineage_request(
        pubkey,
        signing_key,
        dataset_id=dataset_id,
        parent_commit_id=parent_commit_id,
        model_id="multi-event-model-1",
        event_type="training_started",
    )
    resp1 = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage1)
    assert resp1.status_code == 201

    # training_completed event with a DIFFERENT model (model-2)
    # Different model_ids can coexist
    lineage2 = build_lineage_request(
        pubkey,
        signing_key,
        dataset_id=dataset_id,
        parent_commit_id=parent_commit_id,
        model_id="multi-event-model-2",
        event_type="training_completed",
    )
    resp2 = await client.post(f"/datasets/{dataset_id}/lineage", json=lineage2)
    assert resp2.status_code == 201


@pytest.mark.asyncio
async def test_commit_lineage_missing_required_fields_returns_422(client):
    """POST /datasets/{dataset_id}/lineage without required fields should return 422."""
    pubkey, _, signing_key = create_signing_keypair()

    # Create a dataset first
    body = build_commit_request(
        pubkey,
        signing_key,
        dataset_name="lineage-validation-test",
        source_uri="https://example.com/lineage-validation.csv",
    )
    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    # Missing required fields
    incomplete_body = {"model_id": "incomplete"}
    resp = await client.post(f"/datasets/{dataset_id}/lineage", json=incomplete_body)
    assert resp.status_code == 422
