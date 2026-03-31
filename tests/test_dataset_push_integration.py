"""
End-to-end integration tests for the dataset push workflow.

Covers the full lifecycle: keygen → commit → push → verify, exercising
both the CLI (tools/dataset_cli.py) and the API (api/routers/datasets.py)
together in a single test.

Also covers the proof-bundle endpoint that populates proof_bundle_uri.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import nacl.signing
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import (
    blake3_hash,
    compute_dataset_commit_id,
    dataset_key,
)


CLI_PATH = Path(__file__).parent.parent / "tools" / "dataset_cli.py"

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


@pytest.fixture(autouse=True)
def mock_rfc3161():
    mock_token = MagicMock()
    mock_token.tst_bytes = b"\x00" * 32
    mock_token.tsa_url = "https://freetsa.org/tsr"

    with patch("protocol.rfc3161.request_timestamp", return_value=mock_token):
        yield


# ---------------------------------------------------------------------------
# Helper: build API-compatible request from CLI bundle + signing key
# ---------------------------------------------------------------------------


def _build_push_request(
    bundle: dict,
    signing_key: nacl.signing.SigningKey,
    dataset_version: str = "1.0.0",
    license_spdx: str = "MIT",
    file_format: str = "csv",
    granularity: str = "file",
) -> dict:
    """Transform a CLI commit bundle into a server-compatible API request.

    This mirrors what ``dataset push`` does: build the server-format manifest,
    re-compute deterministic hashes, and re-sign with the same key.
    """
    manifest = bundle["manifest"]
    dataset_name = bundle["dataset_name"]
    source_uri = bundle["source_uri"]
    namespace = bundle.get("namespace", "default")
    pubkey_hex = bundle["committer_pubkey"]

    api_files = [
        {"path": f["path"], "content_hash": f["hash"], "byte_size": f["size"], "record_count": None}
        for f in manifest["files"]
    ]

    server_manifest = {
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": namespace,
        "granularity": granularity,
        "license_spdx": license_spdx,
        "license_uri": None,
        "usage_restrictions": [],
        "file_format": file_format,
        "files": api_files,
        "manifest_schema_version": "dataset_manifest_v1",
    }
    server_manifest_hash = blake3_hash([canonical_json_bytes(server_manifest)]).hex()

    ds_id = dataset_key(dataset_name, source_uri, namespace, pubkey_hex)
    parent_id = bundle.get("parent_id") or ""
    commit_id = compute_dataset_commit_id(ds_id, parent_id, server_manifest_hash, pubkey_hex)
    signature_hex = signing_key.sign(bytes.fromhex(commit_id)).signature.hex()

    return {
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "source_uri": source_uri,
        "canonical_namespace": namespace,
        "granularity": granularity,
        "license_spdx": license_spdx,
        "file_format": file_format,
        "files": api_files,
        "parent_commit_id": parent_id or None,
        "committer_pubkey": pubkey_hex,
        "commit_signature": signature_hex,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keygen_commit_push_verify(tmp_path, client):
    """Full end-to-end: keygen → commit (CLI) → push (API) → verify (API)."""
    # 1. keygen via CLI
    prefix = str(tmp_path / "e2e_key")
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    # Load the signing key for re-signing
    signing_key = nacl.signing.SigningKey(
        Path(f"{prefix}.priv").read_bytes(),
        encoder=nacl.encoding.HexEncoder,
    )

    # 2. Create a small dataset directory
    ds = tmp_path / "dataset"
    ds.mkdir()
    (ds / "data.csv").write_text("id,value\n1,100\n2,200\n")
    (ds / "readme.txt").write_text("Test dataset for integration test\n")

    # 3. Commit via CLI
    bundle_path = tmp_path / "bundle.json"
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{prefix}.priv",
            "--dataset-name",
            "integration-test-ds",
            "--source-uri",
            "https://example.com/integration.csv",
            "--namespace",
            "test.integration",
            "-o",
            str(bundle_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert bundle_path.exists()

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    # Confirm metadata is in the bundle
    assert bundle["dataset_name"] == "integration-test-ds"
    assert bundle["source_uri"] == "https://example.com/integration.csv"
    assert bundle["namespace"] == "test.integration"

    # 4. Push to the API (simulated — use the same push logic as the CLI)
    api_body = _build_push_request(bundle, signing_key)
    resp = await client.post("/datasets/commit", json=api_body)
    assert resp.status_code == 201, resp.text

    data = resp.json()
    dataset_id = data["dataset_id"]
    assert data["merkle_root"] is not None

    # 5. Verify via the API
    resp = await client.get(f"/datasets/{dataset_id}/verify")
    assert resp.status_code == 200
    verify_data = resp.json()
    assert verify_data["verified"] is True
    assert verify_data["commit_id_valid"] is True
    assert verify_data["signature_valid"] is True

    # 6. Also verify locally via CLI (the CLI bundle uses its own convention)
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "verify", str(bundle_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Merkle root consistent" in result.stdout
    assert "Ed25519 signature valid" in result.stdout


@pytest.mark.asyncio
async def test_proof_bundle_endpoint(tmp_path, client):
    """GET /datasets/{id}/proof-bundle generates a proof bundle and sets the URI."""
    signing_key = nacl.signing.SigningKey.generate()
    pubkey_hex = bytes(signing_key.verify_key).hex()

    files = [{"path": "test.csv", "content_hash": "a" * 64, "byte_size": 512, "record_count": None}]

    manifest_dict = {
        "dataset_name": "proof-bundle-test",
        "dataset_version": "1.0.0",
        "source_uri": "https://example.com/proof-test.csv",
        "canonical_namespace": "test.proof",
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

    ds_id = dataset_key(
        "proof-bundle-test", "https://example.com/proof-test.csv", "test.proof", pubkey_hex
    )
    commit_id = compute_dataset_commit_id(ds_id, "", manifest_hash, pubkey_hex)
    signature = signing_key.sign(bytes.fromhex(commit_id)).signature.hex()

    body = {
        "dataset_name": "proof-bundle-test",
        "dataset_version": "1.0.0",
        "source_uri": "https://example.com/proof-test.csv",
        "canonical_namespace": "test.proof",
        "granularity": "file",
        "license_spdx": "MIT",
        "file_format": "csv",
        "files": files,
        "committer_pubkey": pubkey_hex,
        "commit_signature": signature,
    }

    resp = await client.post("/datasets/commit", json=body)
    assert resp.status_code == 201, resp.text
    dataset_id = resp.json()["dataset_id"]

    # GET the proof bundle
    resp = await client.get(f"/datasets/{dataset_id}/proof-bundle")
    assert resp.status_code == 200

    pb = resp.json()
    assert pb["dataset_id"] == dataset_id
    assert pb["commit_id"] == commit_id
    assert pb["signature_valid"] is True
    assert pb["commit_id_valid"] is True
    assert pb["merkle_proof"] is not None
    assert pb["dataset_name"] == "proof-bundle-test"
    assert pb["source_uri"] == "https://example.com/proof-test.csv"
    assert len(pb["files"]) == 1

    # Verify that proof_bundle_uri is now set on the detail response
    resp = await client.get(f"/datasets/{dataset_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["proof_bundle_uri"] == f"/datasets/{dataset_id}/proof-bundle"


@pytest.mark.asyncio
async def test_proof_bundle_not_found(client):
    """GET /datasets/{nonexistent}/proof-bundle returns 404."""
    fake_id = "0" * 64
    resp = await client.get(f"/datasets/{fake_id}/proof-bundle")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_push_cli_bundle_metadata_fields(tmp_path):
    """Verify CLI commit bundle includes metadata fields needed by push."""
    prefix = str(tmp_path / "meta_key")
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "keygen", "-o", prefix],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0

    ds = tmp_path / "ds"
    ds.mkdir()
    (ds / "file.txt").write_text("test")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(ds),
            "--private-key",
            f"{prefix}.priv",
            "--dataset-name",
            "meta-test",
            "--source-uri",
            "https://example.com/meta",
            "--namespace",
            "ns.meta",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    bundle = json.loads(result.stdout)

    # These metadata fields must be present for push to work
    assert "dataset_name" in bundle
    assert bundle["dataset_name"] == "meta-test"
    assert "source_uri" in bundle
    assert bundle["source_uri"] == "https://example.com/meta"
    assert "namespace" in bundle
    assert bundle["namespace"] == "ns.meta"
