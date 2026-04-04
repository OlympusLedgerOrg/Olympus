"""
Integration tests for the shards router (api/routers/shards.py).

Covers:
    - GET /shards — list all shards, empty list
    - GET /shards/{shard_id}/header/latest — found (200), not found (404)
    - GET /shards/{shard_id}/proof — existence proof, non-existence proof, shard not found (404)

Uses mock storage layer and bypasses auth/rate limiting in development mode.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import api.services.storage_layer as storage_layer_module
from api.main import create_app


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anyio_backend():
    """Configure pytest-asyncio to use the asyncio backend."""
    return "asyncio"


@dataclass
class MockExistenceProof:
    """Mock ExistenceProof for testing."""

    key: bytes
    value_hash: bytes
    siblings: list[bytes]
    root_hash: bytes


@dataclass
class MockNonExistenceProof:
    """Mock NonExistenceProof for testing."""

    key: bytes
    siblings: list[bytes]
    root_hash: bytes


def create_mock_header(shard_id: str, seq: int = 1) -> dict:
    """Create a mock header response for testing.

    Args:
        shard_id: Shard identifier for the header.
        seq: Sequence number for the header.

    Returns:
        Dictionary containing mock header data with signature and pubkey.
    """
    return {
        "seq": seq,
        "header": {
            "shard_id": shard_id,
            "root_hash": "a" * 64,
            "tree_size": 10,
            "header_hash": "b" * 64,
            "previous_header_hash": "c" * 64,
            "timestamp": "2024-01-15T12:00:00Z",
        },
        "signature": "d" * 128,
        "pubkey": "e" * 64,
    }


def create_mock_storage(
    shard_ids: list[str] | None = None,
    headers: dict[str, dict] | None = None,
    proofs: dict[str, MockExistenceProof | None] | None = None,
    non_proofs: dict[str, MockNonExistenceProof] | None = None,
) -> MagicMock:
    """Create a mock StorageLayer for testing.

    Args:
        shard_ids: List of shard IDs to return from get_all_shard_ids.
        headers: Mapping of shard_id to header data for get_latest_header.
        proofs: Mapping of key to existence proof for get_proof.
        non_proofs: Mapping of key to non-existence proof for get_nonexistence_proof.

    Returns:
        MagicMock configured to simulate StorageLayer behavior.
    """
    mock = MagicMock()

    # Configure get_all_shard_ids
    mock.get_all_shard_ids.return_value = shard_ids or []

    # Configure get_latest_header
    if headers:
        mock.get_latest_header.side_effect = lambda sid: headers.get(sid)
    else:
        mock.get_latest_header.return_value = None

    # Configure get_proof
    if proofs:
        mock.get_proof.side_effect = lambda sid, rt, rid, v: proofs.get(f"{sid}:{rt}:{rid}:{v}")
    else:
        mock.get_proof.return_value = None

    # Configure get_nonexistence_proof
    if non_proofs:
        mock.get_nonexistence_proof.side_effect = lambda sid, rt, rid, v: non_proofs.get(
            f"{sid}:{rt}:{rid}:{v}"
        )
    else:
        # Return a default non-existence proof
        mock.get_nonexistence_proof.return_value = MockNonExistenceProof(
            key=b"\x00" * 32,
            siblings=[b"\x00" * 32] * 256,
            root_hash=b"\x00" * 32,
        )

    return mock


@contextmanager
def inject_mock_storage(mock: MagicMock):
    """Context manager to inject mock storage into the storage layer module.

    This directly sets the module-level _storage singleton to bypass
    the lazy initialization that requires DATABASE_URL.

    Args:
        mock: MagicMock configured as a StorageLayer.

    Yields:
        None
    """
    original_storage = storage_layer_module._storage
    storage_layer_module._storage = mock
    try:
        yield
    finally:
        storage_layer_module._storage = original_storage


@pytest_asyncio.fixture
async def client():
    """Create an async HTTP test client with mocked storage and auth bypass."""
    # Set development mode and disable API keys for test bypass
    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_ALLOW_DEV_AUTH": "1",
            "OLYMPUS_FOIA_API_KEYS": "[]",
        },
    ):
        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


# ---------------------------------------------------------------------------
# GET /shards Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_shards_empty(client):
    """GET /shards should return an empty list when no shards exist."""
    storage_mock = create_mock_storage(shard_ids=[])

    with inject_mock_storage(storage_mock):
        resp = await client.get("/shards")

    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_shards_multiple(client):
    """GET /shards should return all shards with their latest state."""
    shard_ids = ["watauga:2024:budget", "watauga:2024:contracts", "nc:state:permits"]
    headers = {
        shard_id: create_mock_header(shard_id, seq=i + 1) for i, shard_id in enumerate(shard_ids)
    }
    storage_mock = create_mock_storage(shard_ids=shard_ids, headers=headers)

    with inject_mock_storage(storage_mock):
        resp = await client.get("/shards")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3

    # Verify each shard in response
    for shard_info in data:
        assert shard_info["shard_id"] in shard_ids
        assert "latest_seq" in shard_info
        assert "latest_root" in shard_info
        assert shard_info["latest_root"] == "a" * 64  # from create_mock_header


@pytest.mark.asyncio
async def test_list_shards_partial_headers(client):
    """GET /shards should only include shards that have headers."""
    # Two shards exist, but only one has a header
    shard_ids = ["shard-with-header", "shard-without-header"]
    headers = {"shard-with-header": create_mock_header("shard-with-header")}
    storage_mock = create_mock_storage(shard_ids=shard_ids, headers=headers)

    with inject_mock_storage(storage_mock):
        resp = await client.get("/shards")

    assert resp.status_code == 200
    data = resp.json()
    # Only the shard with a header should be returned
    assert len(data) == 1
    assert data[0]["shard_id"] == "shard-with-header"


# ---------------------------------------------------------------------------
# GET /shards/{shard_id}/header/latest Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_latest_header_found(client):
    """GET /shards/{shard_id}/header/latest should return 200 when shard exists."""
    shard_id = "watauga:2024:budget"
    headers = {shard_id: create_mock_header(shard_id, seq=5)}
    storage_mock = create_mock_storage(headers=headers)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b'{"canonical":"json"}'):
            resp = await client.get(f"/shards/{shard_id}/header/latest")

    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == shard_id
    assert data["seq"] == 5
    assert data["root_hash"] == "a" * 64
    assert data["tree_size"] == 10
    assert data["header_hash"] == "b" * 64
    assert data["previous_header_hash"] == "c" * 64
    assert data["timestamp"] == "2024-01-15T12:00:00Z"
    assert data["signature"] == "d" * 128
    assert data["pubkey"] == "e" * 64
    assert "canonical_header_json" in data


@pytest.mark.asyncio
async def test_get_latest_header_not_found(client):
    """GET /shards/{shard_id}/header/latest should return 404 when shard doesn't exist."""
    storage_mock = create_mock_storage()  # No headers configured

    with inject_mock_storage(storage_mock):
        resp = await client.get("/shards/nonexistent-shard/header/latest")

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_latest_header_genesis(client):
    """GET /shards/{shard_id}/header/latest should work for genesis header (seq=0)."""
    shard_id = "new-shard"
    header = create_mock_header(shard_id, seq=0)
    header["header"]["previous_header_hash"] = ""  # Genesis has no previous
    headers = {shard_id: header}
    storage_mock = create_mock_storage(headers=headers)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b"{}"):
            resp = await client.get(f"/shards/{shard_id}/header/latest")

    assert resp.status_code == 200
    data = resp.json()
    assert data["seq"] == 0
    assert data["previous_header_hash"] == ""


# ---------------------------------------------------------------------------
# GET /shards/{shard_id}/proof Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_proof_existence(client):
    """GET /shards/{shard_id}/proof should return existence proof when record exists."""
    shard_id = "watauga:2024:budget"
    record_type = "document"
    record_id = "doc-001"
    version = 1

    # Create mock existence proof
    proof = MockExistenceProof(
        key=b"\x01" * 32,
        value_hash=b"\x02" * 32,
        siblings=[b"\x03" * 32] * 256,
        root_hash=b"\x04" * 32,
    )
    proofs = {f"{shard_id}:{record_type}:{record_id}:{version}": proof}
    headers = {shard_id: create_mock_header(shard_id)}
    storage_mock = create_mock_storage(headers=headers, proofs=proofs)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b"{}"):
            resp = await client.get(
                f"/shards/{shard_id}/proof",
                params={
                    "record_type": record_type,
                    "record_id": record_id,
                    "version": version,
                },
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == shard_id
    assert data["record_type"] == record_type
    assert data["record_id"] == record_id
    assert data["version"] == version
    assert data["key"] == "01" * 32
    assert data["value_hash"] == "02" * 32
    assert len(data["siblings"]) == 256
    assert data["root_hash"] == "04" * 32
    assert "shard_header" in data


@pytest.mark.asyncio
async def test_get_proof_nonexistence(client):
    """GET /shards/{shard_id}/proof should return non-existence proof when record doesn't exist."""
    shard_id = "watauga:2024:budget"
    record_type = "document"
    record_id = "nonexistent-doc"
    version = 1

    # Create mock non-existence proof
    non_proof = MockNonExistenceProof(
        key=b"\x05" * 32,
        siblings=[b"\x06" * 32] * 256,
        root_hash=b"\x07" * 32,
    )
    non_proofs = {f"{shard_id}:{record_type}:{record_id}:{version}": non_proof}
    headers = {shard_id: create_mock_header(shard_id)}
    # proofs is empty (record doesn't exist)
    storage_mock = create_mock_storage(headers=headers, proofs={}, non_proofs=non_proofs)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b"{}"):
            resp = await client.get(
                f"/shards/{shard_id}/proof",
                params={
                    "record_type": record_type,
                    "record_id": record_id,
                    "version": version,
                },
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == shard_id
    assert data["record_type"] == record_type
    assert data["record_id"] == record_id
    assert data["version"] == version
    assert data["key"] == "05" * 32
    # Non-existence proof should NOT have value_hash
    assert "value_hash" not in data
    assert len(data["siblings"]) == 256
    assert data["root_hash"] == "07" * 32
    assert "shard_header" in data


@pytest.mark.asyncio
async def test_get_proof_shard_not_found(client):
    """GET /shards/{shard_id}/proof should return 404 when shard doesn't exist."""
    storage_mock = create_mock_storage()  # No headers or proofs

    with inject_mock_storage(storage_mock):
        resp = await client.get(
            "/shards/nonexistent-shard/proof",
            params={
                "record_type": "document",
                "record_id": "doc-001",
                "version": 1,
            },
        )

    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_proof_missing_required_params(client):
    """GET /shards/{shard_id}/proof without required query params should return 422."""
    resp = await client.get("/shards/test-shard/proof")

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_proof_invalid_version(client):
    """GET /shards/{shard_id}/proof with version < 1 should return 422."""
    resp = await client.get(
        "/shards/test-shard/proof",
        params={
            "record_type": "document",
            "record_id": "doc-001",
            "version": 0,  # Invalid: version must be >= 1
        },
    )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_proof_existence_with_shard_header_fields(client):
    """GET /shards/{shard_id}/proof should include complete shard_header in response."""
    shard_id = "detailed-shard"
    proof = MockExistenceProof(
        key=b"\x01" * 32,
        value_hash=b"\x02" * 32,
        siblings=[b"\x03" * 32] * 256,
        root_hash=b"\x04" * 32,
    )
    proofs = {f"{shard_id}:document:doc-001:1": proof}
    headers = {shard_id: create_mock_header(shard_id, seq=42)}
    storage_mock = create_mock_storage(headers=headers, proofs=proofs)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b'{"test":"json"}'):
            resp = await client.get(
                f"/shards/{shard_id}/proof",
                params={"record_type": "document", "record_id": "doc-001", "version": 1},
            )

    assert resp.status_code == 200
    data = resp.json()

    # Verify shard_header contains all expected fields
    shard_header = data["shard_header"]
    assert shard_header["shard_id"] == shard_id
    assert shard_header["seq"] == 42
    assert shard_header["root_hash"] == "a" * 64
    assert shard_header["tree_size"] == 10
    assert shard_header["header_hash"] == "b" * 64
    assert shard_header["previous_header_hash"] == "c" * 64
    assert shard_header["timestamp"] == "2024-01-15T12:00:00Z"
    assert shard_header["signature"] == "d" * 128
    assert shard_header["pubkey"] == "e" * 64
    assert "canonical_header_json" in shard_header


# ---------------------------------------------------------------------------
# Edge Cases and Error Handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_proof_special_characters_in_ids(client):
    """GET /shards/{shard_id}/proof should handle special characters in identifiers."""
    # Use URL-safe shard_id (colon, hyphen, underscore are safe in path segments)
    shard_id = "county:2024:type-a_b"
    record_id = "doc-with_special.chars"

    proof = MockExistenceProof(
        key=b"\x01" * 32,
        value_hash=b"\x02" * 32,
        siblings=[b"\x03" * 32] * 256,
        root_hash=b"\x04" * 32,
    )
    proofs = {f"{shard_id}:document:{record_id}:1": proof}
    headers = {shard_id: create_mock_header(shard_id)}
    storage_mock = create_mock_storage(headers=headers, proofs=proofs)

    with inject_mock_storage(storage_mock):
        with patch("api.routers.shards.canonical_header", return_value=b"{}"):
            resp = await client.get(
                f"/shards/{shard_id}/proof",
                params={"record_type": "document", "record_id": record_id, "version": 1},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == shard_id
    assert data["record_id"] == record_id


@pytest.mark.asyncio
async def test_list_shards_storage_503(client):
    """GET /shards should return 503 when storage is unavailable."""
    # Reset storage singleton to trigger initialization attempt
    storage_layer_module._storage = None

    # Don't set DATABASE_URL - this will cause a 503 error
    with patch.dict(os.environ, {}, clear=False):
        # Remove DATABASE_URL if set
        env_backup = os.environ.pop("DATABASE_URL", None)
        try:
            resp = await client.get("/shards")
            assert resp.status_code == 503
        finally:
            if env_backup:
                os.environ["DATABASE_URL"] = env_backup
            storage_layer_module._storage = None


@pytest.mark.asyncio
async def test_get_header_storage_503(client):
    """GET /shards/{shard_id}/header/latest should return 503 when storage is unavailable."""
    # Reset storage singleton to trigger initialization attempt
    storage_layer_module._storage = None

    # Don't set DATABASE_URL - this will cause a 503 error
    with patch.dict(os.environ, {}, clear=False):
        env_backup = os.environ.pop("DATABASE_URL", None)
        try:
            resp = await client.get("/shards/test-shard/header/latest")
            assert resp.status_code == 503
        finally:
            if env_backup:
                os.environ["DATABASE_URL"] = env_backup
            storage_layer_module._storage = None


@pytest.mark.asyncio
async def test_get_proof_storage_503(client):
    """GET /shards/{shard_id}/proof should return 503 when storage is unavailable."""
    # Reset storage singleton to trigger initialization attempt
    storage_layer_module._storage = None

    # Don't set DATABASE_URL - this will cause a 503 error
    with patch.dict(os.environ, {}, clear=False):
        env_backup = os.environ.pop("DATABASE_URL", None)
        try:
            resp = await client.get(
                "/shards/test-shard/proof",
                params={"record_type": "document", "record_id": "doc-001", "version": 1},
            )
            assert resp.status_code == 503
        finally:
            if env_backup:
                os.environ["DATABASE_URL"] = env_backup
            storage_layer_module._storage = None
