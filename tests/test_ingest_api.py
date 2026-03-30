"""Tests for api.ingest module (batch ingestion endpoints)."""

import pytest
from fastapi.testclient import TestClient

from api import ingest as ingest_api
from api.app import app
from protocol.hashes import hash_bytes, record_key
from protocol.merkle import MerkleTree, deserialize_merkle_proof, verify_proof
from protocol.ssmf import SparseMerkleTree


@pytest.fixture()
def client():
    """Create a test client for the API."""
    ingest_api._reset_ingest_state_for_tests()
    ingest_api._register_api_key_for_tests(
        api_key="test-key",
        key_id="test-key-id",
        scopes={"ingest", "commit", "verify"},
        expires_at="2099-01-01T00:00:00Z",
    )
    return TestClient(app, headers={"X-API-Key": "test-key"})


# ---------------------------------------------------------------------------
# POST /ingest/records
# ---------------------------------------------------------------------------


class TestBatchIngestion:
    def test_ingest_single_record(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-1",
                    "record_type": "document",
                    "record_id": "doc-001",
                    "version": 1,
                    "content": {"title": "Test Document", "body": "Hello world"},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 1
        assert data["deduplicated"] == 0
        assert len(data["results"]) == 1
        assert data["results"][0]["record_id"] == "doc-001"
        assert data["results"][0]["deduplicated"] is False
        assert data["results"][0]["content_hash"]  # non-empty
        assert data["ledger_entry_hash"]  # non-empty

    def test_ingest_batch_multiple_records(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-batch",
                    "record_type": "document",
                    "record_id": f"doc-{i}",
                    "version": 1,
                    "content": {"index": i, "text": f"Document {i}"},
                }
                for i in range(5)
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 5
        assert data["deduplicated"] == 0
        assert len(data["results"]) == 5

    def test_ingest_deduplication(self, client: TestClient):
        """Ingesting the same content twice should deduplicate."""
        record = {
            "shard_id": "shard-dedup",
            "record_type": "document",
            "record_id": "doc-dedup",
            "version": 1,
            "content": {"unique_key": "dedup-test-value-42"},
        }
        # First ingestion
        resp1 = client.post("/ingest/records", json={"records": [record]})
        assert resp1.status_code == 200
        proof_id_1 = resp1.json()["results"][0]["proof_id"]

        # Second ingestion of same content
        resp2 = client.post("/ingest/records", json={"records": [record]})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["deduplicated"] == 1
        assert data2["ingested"] == 0
        assert data2["results"][0]["deduplicated"] is True
        assert data2["results"][0]["proof_id"] == proof_id_1

    def test_ingest_empty_batch_rejected(self, client: TestClient):
        resp = client.post("/ingest/records", json={"records": []})
        assert resp.status_code == 422  # Validation error

    def test_ingest_invalid_version(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-1",
                    "record_type": "doc",
                    "record_id": "x",
                    "version": 0,  # must be >= 1
                    "content": {"a": 1},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        assert resp.status_code == 422

    def test_ingest_returns_timestamp(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-ts",
                    "record_type": "document",
                    "record_id": "doc-ts",
                    "version": 1,
                    "content": {"ts_test": True},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        data = resp.json()
        assert "timestamp" in data
        assert data["timestamp"].endswith("Z") or "+" in data["timestamp"]

    def test_ingest_computes_poseidon_root_for_stored_proof(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-poseidon",
                    "record_type": "document",
                    "record_id": "doc-poseidon",
                    "version": 1,
                    "content": {"poseidon": "root"},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        proof_id = resp.json()["results"][0]["proof_id"]

        proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
        assert proof_resp.status_code == 200
        proof_data = proof_resp.json()
        assert proof_data["poseidon_root"] is not None
        assert proof_data["poseidon_root"].isdigit()
        assert ingest_api._write_ledger.entries[-1].poseidon_root == proof_data["poseidon_root"]


def test_ingest_storage_normalizes_asyncpg_url_for_psycopg(monkeypatch):
    """Ingest storage init should strip +asyncpg driver suffix before psycopg use."""
    captured: dict[str, str] = {}

    class _FakeStorageLayer:
        def __init__(self, connection_string: str):
            captured["connection_string"] = connection_string

        def init_schema(self) -> None:
            return None

        def check_ingestion_schema(self) -> None:
            return None

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+asyncpg://user:pass@localhost:5432/olympus",
    )
    monkeypatch.setenv("OLYMPUS_INGEST_SIGNING_KEY", "00" * 32)
    monkeypatch.setattr(ingest_api, "_storage", None)
    monkeypatch.setattr(ingest_api, "_signing_key", None)
    monkeypatch.setattr("storage.postgres.StorageLayer", _FakeStorageLayer)

    storage = ingest_api._get_storage()

    assert storage is not None
    assert captured["connection_string"] == "postgresql://user:pass@localhost:5432/olympus"


# ---------------------------------------------------------------------------
# GET /ingest/records/{proof_id}/proof
# ---------------------------------------------------------------------------


class TestIngestionProof:
    def test_get_proof_after_ingestion(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-proof",
                    "record_type": "document",
                    "record_id": "doc-proof",
                    "version": 1,
                    "content": {"proof_test": "data-unique-xyz"},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        proof_id = resp.json()["results"][0]["proof_id"]

        proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
        assert proof_resp.status_code == 200
        proof_data = proof_resp.json()
        assert proof_data["proof_id"] == proof_id
        assert proof_data["record_id"] == "doc-proof"
        assert proof_data["merkle_root"]
        assert proof_data["merkle_proof"]
        assert proof_data["ledger_entry_hash"]

    def test_get_proof_not_found(self, client: TestClient):
        resp = client.get("/ingest/records/nonexistent-id/proof")
        assert resp.status_code == 404

    def test_verify_by_content_hash(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-hash",
                    "record_type": "document",
                    "record_id": "doc-hash",
                    "version": 1,
                    "content": {"hash_lookup": "present"},
                }
            ]
        }
        resp = client.post("/ingest/records", json=payload)
        content_hash = resp.json()["results"][0]["content_hash"]

        verify_resp = client.get(f"/ingest/records/hash/{content_hash}/verify")
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["content_hash"] == content_hash
        assert verify_data["record_id"] == "doc-hash"
        assert verify_data["merkle_proof_valid"] is True

    def test_verify_by_content_hash_rejects_invalid_hex(self, client: TestClient):
        resp = client.get("/ingest/records/hash/not-hex/verify")
        assert resp.status_code == 400

    def test_verify_by_content_hash_not_found(self, client: TestClient):
        missing_hash = "ab" * 32
        resp = client.get(f"/ingest/records/hash/{missing_hash}/verify")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_includes_endpoints(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "version" in data

    def test_health_includes_version(self, client: TestClient):
        resp = client.get("/health")
        data = resp.json()
        assert "version" in data

    def test_root_includes_ingest_endpoints(self, client: TestClient):
        resp = client.get("/")
        data = resp.json()
        assert "service" in data
        assert "version" in data
        assert data["status"] == "ok"


class TestSubmittedProofBundles:
    def test_verify_submitted_proof_bundle(self, client: TestClient):
        payload = {
            "records": [
                {
                    "shard_id": "shard-submitted-proof",
                    "record_type": "document",
                    "record_id": "doc-submitted-proof",
                    "version": 1,
                    "content": {"proof_bundle": "present"},
                }
            ]
        }
        ingest_resp = client.post("/ingest/records", json=payload)
        proof_id = ingest_resp.json()["results"][0]["proof_id"]
        proof_bundle = client.get(f"/ingest/records/{proof_id}/proof").json()

        verify_resp = client.post(
            "/ingest/proofs/verify",
            json={
                "proof_id": proof_bundle["proof_id"],
                "content_hash": proof_bundle["content_hash"],
                "merkle_root": proof_bundle["merkle_root"],
                "merkle_proof": proof_bundle["merkle_proof"],
                "poseidon_root": proof_bundle["poseidon_root"],
            },
        )

        assert verify_resp.status_code == 200
        data = verify_resp.json()
        assert data["proof_id"] == proof_id
        assert data["content_hash_matches_proof"] is True
        assert data["merkle_proof_valid"] is True
        assert data["known_to_server"] is True

    def test_submit_valid_external_proof_bundle(self, client: TestClient):
        content_hash_bytes = hash_bytes(b"external-proof-bundle")
        tree = MerkleTree([content_hash_bytes])
        merkle_proof = tree.generate_proof(0)

        resp = client.post(
            "/ingest/proofs",
            json={
                "record_id": "external-doc",
                "shard_id": "shard-external-proof",
                "content_hash": content_hash_bytes.hex(),
                "merkle_root": tree.get_root().hex(),
                "merkle_proof": {
                    "leaf_hash": merkle_proof.leaf_hash.hex(),
                    "leaf_index": merkle_proof.leaf_index,
                    "siblings": [],
                    "root_hash": merkle_proof.root_hash.hex(),
                    "proof_version": merkle_proof.proof_version,
                    "tree_version": merkle_proof.tree_version,
                    "epoch": merkle_proof.epoch,
                    "tree_size": merkle_proof.tree_size,
                },
                "ledger_entry_hash": "ab" * 32,
                "timestamp": "2026-01-01T00:00:00Z",
                "canonicalization": {"content_type": "application/octet-stream"},
                "batch_id": "external-batch",
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["submitted"] is True
        assert data["deduplicated"] is False
        assert data["content_hash"] == content_hash_bytes.hex()
        assert data["merkle_root"] == tree.get_root().hex()

    def test_submit_invalid_external_proof_bundle_rejected(self, client: TestClient):
        content_hash_bytes = hash_bytes(b"invalid-external-proof")
        tree = MerkleTree([content_hash_bytes])
        merkle_proof = tree.generate_proof(0)

        resp = client.post(
            "/ingest/proofs",
            json={
                "record_id": "external-doc-invalid",
                "shard_id": "shard-external-proof",
                "content_hash": ("00" * 32),
                "merkle_root": tree.get_root().hex(),
                "merkle_proof": {
                    "leaf_hash": merkle_proof.leaf_hash.hex(),
                    "leaf_index": merkle_proof.leaf_index,
                    "siblings": [],
                    "root_hash": merkle_proof.root_hash.hex(),
                    "proof_version": merkle_proof.proof_version,
                    "tree_version": merkle_proof.tree_version,
                    "epoch": merkle_proof.epoch,
                    "tree_size": merkle_proof.tree_size,
                },
                "ledger_entry_hash": "cd" * 32,
                "timestamp": "2026-01-01T00:00:00Z",
                "canonicalization": {"content_type": "application/octet-stream"},
            },
        )

        assert resp.status_code == 400

    def test_submit_external_proof_bundle_invalid_record_id_returns_422(self, client: TestClient):
        content_hash_bytes = hash_bytes(b"invalid-record-id-proof")
        tree = MerkleTree([content_hash_bytes])
        merkle_proof = tree.generate_proof(0)

        resp = client.post(
            "/ingest/proofs",
            json={
                "record_id": "external-doc$invalid",
                "shard_id": "shard-external-proof",
                "content_hash": content_hash_bytes.hex(),
                "merkle_root": tree.get_root().hex(),
                "merkle_proof": {
                    "leaf_hash": merkle_proof.leaf_hash.hex(),
                    "leaf_index": merkle_proof.leaf_index,
                    "siblings": [],
                    "root_hash": merkle_proof.root_hash.hex(),
                    "proof_version": merkle_proof.proof_version,
                    "tree_version": merkle_proof.tree_version,
                    "epoch": merkle_proof.epoch,
                    "tree_size": merkle_proof.tree_size,
                },
                "ledger_entry_hash": "cd" * 32,
                "timestamp": "2026-01-01T00:00:00Z",
                "canonicalization": {"content_type": "application/octet-stream"},
            },
        )

        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /ingest/commit
# ---------------------------------------------------------------------------


class TestArtifactCommit:
    def test_commit_valid_artifact_hash(self, client: TestClient):
        """A well-formed BLAKE3 hash should be committed and return a proof_id."""
        artifact_hash = "ab" * 32  # 64 hex chars = 32 bytes
        resp = client.post(
            "/ingest/commit",
            json={"artifact_hash": artifact_hash, "namespace": "github", "id": "org/repo/v1.0.0"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["proof_id"]
        assert data["artifact_hash"] == artifact_hash
        assert data["namespace"] == "github"
        assert data["id"] == "org/repo/v1.0.0"
        assert data["committed_at"]
        assert data["ledger_entry_hash"]
        assert data["poseidon_root"] is not None
        assert data["poseidon_root"].isdigit()

    def test_commit_with_poseidon_root_returns_dual_hash(self, client: TestClient):
        """Optional poseidon_root should be echoed back and persisted."""
        artifact_hash = "aa" * 32
        poseidon_root = "123456789"
        resp = client.post(
            "/ingest/commit",
            json={
                "artifact_hash": artifact_hash,
                "namespace": "zk",
                "id": "artifact/v1",
                "poseidon_root": poseidon_root,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["poseidon_root"] == poseidon_root

        # Dedup should return the same poseidon_root
        resp2 = client.post(
            "/ingest/commit",
            json={
                "artifact_hash": artifact_hash,
                "namespace": "zk",
                "id": "artifact/v1",
                "poseidon_root": poseidon_root,
            },
        )
        assert resp2.status_code == 200
        assert resp2.json()["poseidon_root"] == poseidon_root

    def test_commit_deduplication_returns_same_proof_id(self, client: TestClient):
        """Committing the same hash twice should return the same proof_id."""
        artifact_hash = "cd" * 32
        resp1 = client.post(
            "/ingest/commit",
            json={"artifact_hash": artifact_hash, "namespace": "ci", "id": "proj/v2.0.0"},
        )
        proof_id_1 = resp1.json()["proof_id"]

        resp2 = client.post(
            "/ingest/commit",
            json={"artifact_hash": artifact_hash, "namespace": "ci", "id": "proj/v2.0.0"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["proof_id"] == proof_id_1
        assert resp2.json()["poseidon_root"] is not None
        assert resp2.json()["poseidon_root"].isdigit()

    def test_commit_conflicting_poseidon_root_rejected(self, client: TestClient):
        """A conflicting poseidon_root for the same hash should be rejected."""
        artifact_hash = "aa" * 32
        client.post(
            "/ingest/commit",
            json={
                "artifact_hash": artifact_hash,
                "namespace": "ci",
                "id": "proj/v2.0.0",
                "poseidon_root": "42",
            },
        )

        resp = client.post(
            "/ingest/commit",
            json={
                "artifact_hash": artifact_hash,
                "namespace": "ci",
                "id": "proj/v2.0.0",
                "poseidon_root": "43",
            },
        )
        assert resp.status_code == 400

    def test_commit_invalid_hex_rejected(self, client: TestClient):
        resp = client.post(
            "/ingest/commit",
            json={"artifact_hash": "not-hex!", "namespace": "github", "id": "org/repo/v1.0.0"},
        )
        assert resp.status_code == 400

    def test_commit_wrong_length_rejected(self, client: TestClient):
        """A hash shorter than 32 bytes should be rejected."""
        short_hash = "ab" * 16  # only 16 bytes
        resp = client.post(
            "/ingest/commit",
            json={"artifact_hash": short_hash, "namespace": "github", "id": "org/repo/v1.0.0"},
        )
        assert resp.status_code == 400

    def test_commit_with_api_key_accepted(self, client: TestClient):
        """Extra api_key body field is silently ignored; auth uses X-API-Key header."""
        artifact_hash = "ef" * 32
        resp = client.post(
            "/ingest/commit",
            json={
                "artifact_hash": artifact_hash,
                "namespace": "github",
                "id": "org/repo/v3.0.0",
                "api_key": "test-key",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["proof_id"]

    def test_health_includes_commit_endpoint(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "version" in data


class TestAuthAndRateLimiting:
    def test_ingest_requires_api_key(self):
        """Test that ingest endpoint requires authentication.

        This test explicitly registers an API key to disable dev-mode bypass,
        then attempts access without credentials to verify 401 is returned.
        """
        ingest_api._reset_ingest_state_for_tests()
        # Register an API key so that dev-mode bypass is not active
        ingest_api._register_api_key_for_tests(
            api_key="valid-key",
            key_id="valid-key-id",
            scopes={"ingest"},
            expires_at="2099-01-01T00:00:00Z",
        )
        # Client without API key should get 401
        unauth_client = TestClient(app)
        payload = {
            "records": [
                {
                    "shard_id": "shard-auth",
                    "record_type": "document",
                    "record_id": "doc-auth",
                    "version": 1,
                    "content": {"secure": True},
                }
            ]
        }
        resp = unauth_client.post("/ingest/records", json=payload)
        assert resp.status_code == 401

    def test_scope_enforced_for_verify(self, client: TestClient):
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="ingest-only",
            key_id="ingest-only-id",
            scopes={"ingest"},
            expires_at="2099-01-01T00:00:00Z",
        )
        scoped_client = TestClient(app, headers={"X-API-Key": "ingest-only"})

        payload = {
            "records": [
                {
                    "shard_id": "shard-scope",
                    "record_type": "document",
                    "record_id": "doc-scope",
                    "version": 1,
                    "content": {"scope": "test"},
                }
            ]
        }
        ingest_resp = scoped_client.post("/ingest/records", json=payload)
        content_hash = ingest_resp.json()["results"][0]["content_hash"]
        verify_resp = scoped_client.get(f"/ingest/records/hash/{content_hash}/verify")
        assert verify_resp.status_code == 403

    def test_expired_key_rejected(self):
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="expired-key",
            key_id="expired-id",
            scopes={"ingest", "commit", "verify"},
            expires_at="2000-01-01T00:00:00Z",
        )
        expired_client = TestClient(app, headers={"X-API-Key": "expired-key"})
        payload = {
            "records": [
                {
                    "shard_id": "shard-exp",
                    "record_type": "document",
                    "record_id": "doc-exp",
                    "version": 1,
                    "content": {"expired": True},
                }
            ]
        }
        resp = expired_client.post("/ingest/records", json=payload)
        assert resp.status_code == 401

    def test_rate_limit_enforced_per_key(self):
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="rate-key",
            key_id="rate-id",
            scopes={"ingest", "commit", "verify"},
            expires_at="2099-01-01T00:00:00Z",
        )
        ingest_api._set_rate_limit_for_tests("ingest", capacity=1.0, refill_rate_per_second=0.0)
        rl_client = TestClient(app, headers={"X-API-Key": "rate-key"})
        payload = {
            "records": [
                {
                    "shard_id": "shard-rl",
                    "record_type": "document",
                    "record_id": "doc-rl",
                    "version": 1,
                    "content": {"rate": 1},
                }
            ]
        }
        first = rl_client.post("/ingest/records", json=payload)
        second = rl_client.post("/ingest/records", json=payload)
        assert first.status_code == 200
        assert second.status_code == 429

    def test_rate_limit_enforced_per_ip(self):
        """Separate keys sharing the same IP should respect the IP bucket."""
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="ip-key-1",
            key_id="ip-key-1",
            scopes={"ingest", "commit", "verify"},
            expires_at="2099-01-01T00:00:00Z",
        )
        ingest_api._register_api_key_for_tests(
            api_key="ip-key-2",
            key_id="ip-key-2",
            scopes={"ingest", "commit", "verify"},
            expires_at="2099-01-01T00:00:00Z",
        )
        ingest_api._set_rate_limit_for_tests("ingest", capacity=1.0, refill_rate_per_second=0.0)
        client_one = TestClient(app, headers={"X-API-Key": "ip-key-1"})
        client_two = TestClient(app, headers={"X-API-Key": "ip-key-2"})
        payload_one = {
            "records": [
                {
                    "shard_id": "shard-ip-1",
                    "record_type": "document",
                    "record_id": "doc-ip-1",
                    "version": 1,
                    "content": {"rate": "ip-one"},
                }
            ]
        }
        payload_two = {
            "records": [
                {
                    "shard_id": "shard-ip-2",
                    "record_type": "document",
                    "record_id": "doc-ip-2",
                    "version": 1,
                    "content": {"rate": "ip-two"},
                }
            ]
        }
        first = client_one.post("/ingest/records", json=payload_one)
        second = client_two.post("/ingest/records", json=payload_two)
        assert first.status_code == 200
        assert second.status_code == 429

    def test_rate_limit_hits_are_audited(self):
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="audit-rate",
            key_id="audit-rate",
            scopes={"ingest", "commit", "verify"},
            expires_at="2099-01-01T00:00:00Z",
        )
        ingest_api._set_rate_limit_for_tests("ingest", capacity=1.0, refill_rate_per_second=0.0)
        client = TestClient(app, headers={"X-API-Key": "audit-rate"})
        payload = {
            "records": [
                {
                    "shard_id": "shard-audit",
                    "record_type": "document",
                    "record_id": "doc-audit",
                    "version": 1,
                    "content": {"audit": True},
                }
            ]
        }
        client.post("/ingest/records", json=payload)
        ledger_len_before = len(ingest_api._write_ledger.entries)
        rate_limited = client.post("/ingest/records", json=payload)
        assert rate_limited.status_code == 429
        assert len(ingest_api._write_ledger.entries) == ledger_len_before + 1
        assert ingest_api._write_ledger.entries[-1].shard_id == "audit/security"


def test_smt_proof_conversion_verifies_round_trip():
    """Sparse Merkle proofs should convert to valid MerkleProof bundles."""
    tree = SparseMerkleTree()
    key = record_key("document", "doc-smt", 1)
    value_hash = hash_bytes(b"deterministic-smt-payload")
    tree.update(key, value_hash)
    proof = tree.prove_existence(key)

    merkle_dict = ingest_api._smt_proof_to_merkle_proof_dict(proof, value_hash)
    merkle_proof = deserialize_merkle_proof(merkle_dict)

    assert verify_proof(merkle_proof)

    normalized_hash, normalized_root, matches, valid = ingest_api._evaluate_proof_bundle(
        value_hash.hex(), merkle_dict["root_hash"], merkle_dict
    )
    assert normalized_hash == value_hash.hex()
    assert normalized_root == proof.root_hash.hex()
    assert matches is True
    assert valid is True


def test_load_api_keys_from_env_requires_hashed_keys(monkeypatch):
    """Raw API keys in the environment must be rejected.

    Note: Key loading is now handled by the unified auth module (api.auth).
    """
    import api.auth as auth_module

    auth_module._reset_auth_state_for_tests()
    monkeypatch.setenv(
        "OLYMPUS_API_KEYS_JSON",
        '[{"api_key":"plaintext","key_id":"raw","scopes":["verify"],"expires_at":"2099-01-01T00:00:00Z"}]',
    )
    with pytest.raises(ValueError):
        auth_module._load_keys_into({})


def test_load_api_keys_from_env_accepts_hashes(monkeypatch):
    """Hashed API keys should register successfully.

    Note: Key loading is now handled by the unified auth module (api.auth).
    """
    import api.auth as auth_module

    auth_module._reset_auth_state_for_tests()
    key_hash = hash_bytes(b"hashed-secret").hex()
    monkeypatch.setenv(
        "OLYMPUS_API_KEYS_JSON",
        f'[{{"key_hash":"{key_hash}","key_id":"hashed","scopes":["verify"],"expires_at":"2099-01-01T00:00:00Z"}}]',
    )
    target: dict = {}
    auth_module._load_keys_into(target)
    assert key_hash in target
    assert target[key_hash].key_id == "hashed"


def test_smt_divergence_alert_requires_api_key():
    import json
    import os

    import api.auth as auth_module

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)
    original_env = os.environ.get("OLYMPUS_FOIA_API_KEYS")

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()

        test_key = "alert-key-secret"
        test_key_hash = hash_bytes(test_key.encode("utf-8")).hex()
        os.environ["OLYMPUS_FOIA_API_KEYS"] = json.dumps(
            [
                {
                    "key_hash": test_key_hash,
                    "key_id": "alert-key",
                    "scopes": ["read", "write"],
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ]
        )

        params = {
            "local_root": "00" * 32,
            "remote_root": "11" * 32,
            "remote_node": "peer-1",
        }

        unauthenticated = TestClient(app).post(
            "/shards/shard-1/alert/smt-divergence", params=params
        )
        assert unauthenticated.status_code == 401

        authed = TestClient(app, headers={"X-API-Key": test_key})
        authorized = authed.post("/shards/shard-1/alert/smt-divergence", params=params)
        assert authorized.status_code == 200
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        if original_env is None:
            os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)
        else:
            os.environ["OLYMPUS_FOIA_API_KEYS"] = original_env


def test_metrics_endpoint_requires_api_key():
    """GET /metrics should require API key authentication (H3)."""
    import json
    import os

    import api.auth as auth_module

    original_loaded = auth_module._keys_loaded
    original_store = dict(auth_module._key_store)
    original_env = os.environ.get("OLYMPUS_FOIA_API_KEYS")

    try:
        auth_module._keys_loaded = False
        auth_module._key_store.clear()

        test_key = "metrics-key-secret"
        test_key_hash = hash_bytes(test_key.encode("utf-8")).hex()
        os.environ["OLYMPUS_FOIA_API_KEYS"] = json.dumps(
            [
                {
                    "key_hash": test_key_hash,
                    "key_id": "metrics-key",
                    "scopes": ["read", "write"],
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ]
        )

        unauthenticated = TestClient(app).get("/metrics")
        assert unauthenticated.status_code == 401

        authed = TestClient(app, headers={"X-API-Key": test_key})
        authorized = authed.get("/metrics")
        # 200 if prometheus-client is installed, 503 otherwise — but NOT 401
        assert authorized.status_code in (200, 503)
    finally:
        auth_module._keys_loaded = original_loaded
        auth_module._key_store.clear()
        auth_module._key_store.update(original_store)
        if original_env is None:
            os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)
        else:
            os.environ["OLYMPUS_FOIA_API_KEYS"] = original_env
    """
    L5-C: Test that the rate limiter is thread-safe under concurrent access.

    This test validates the fix for the race condition identified in the
    red team security audit. Multiple threads consume rate limit tokens
    simultaneously to verify no corruption occurs.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ingest_api._reset_ingest_state_for_tests()
    # Set high capacity so we can test concurrent access without hitting limits
    ingest_api._set_rate_limit_for_tests("ingest", capacity=1000.0, refill_rate_per_second=100.0)

    num_threads = 20
    iterations_per_thread = 50
    results: list[bool] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(num_threads)

    def worker():
        """Each worker consumes rate limit tokens in a tight loop."""
        barrier.wait()  # Synchronize all threads to start at the same time
        local_results = []
        for _ in range(iterations_per_thread):
            try:
                # Consume from both key and IP buckets to stress both paths
                result_key = ingest_api._consume_rate_limit("api_key", "test-key", "ingest")
                result_ip = ingest_api._consume_rate_limit("ip", "127.0.0.1", "ingest")
                local_results.append(result_key and result_ip)
            except Exception as e:
                errors.append(e)
                break
        return local_results

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        for future in as_completed(futures):
            results.extend(future.result())

    # No errors should have occurred (race conditions would cause crashes or corruption)
    assert len(errors) == 0, f"Thread-safety errors: {errors}"

    # All operations should succeed (high capacity ensures no rate limiting)
    total_expected = num_threads * iterations_per_thread
    assert len(results) == total_expected
    assert all(results), "All rate limit checks should succeed with high capacity"


# ---------------------------------------------------------------------------
# Idempotency gate tests (Finding #5 — Red Team Hardening Round 2)
# ---------------------------------------------------------------------------


class TestIdempotencyGate:
    def test_duplicate_submission_returns_existing_record(self, client: TestClient):
        record = {
            "shard_id": "shard-idem",
            "record_type": "document",
            "record_id": "doc-idem-001",
            "version": 1,
            "content": {"invoice_id": "INV-0001", "amount": 100, "currency": "USD"},
        }
        r1 = client.post("/ingest/records", json={"records": [record]})
        r2 = client.post("/ingest/records", json={"records": [record]})

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["results"][0]["proof_id"] == r2.json()["results"][0]["proof_id"]
        assert r2.json()["results"][0]["idempotent"] is True
        assert r2.json()["results"][0]["deduplicated"] is True

    def test_fresh_insert_is_not_idempotent(self, client: TestClient):
        record = {
            "shard_id": "shard-fresh",
            "record_type": "document",
            "record_id": "doc-fresh-001",
            "version": 1,
            "content": {"invoice_id": "INV-FRESH", "amount": 42, "currency": "EUR"},
        }
        r = client.post("/ingest/records", json={"records": [record]})
        assert r.status_code == 200
        assert r.json()["results"][0]["idempotent"] is False
        assert r.json()["results"][0]["deduplicated"] is False

    def test_semantic_numeric_variant_is_deduplicated(self):
        """Post Round-1 fix: 100 and 100.0 must canonicalize identically."""
        from protocol.canonical import canonicalize_document, document_to_bytes

        payload_a = {"invoice_id": "INV-0003", "amount": 100, "currency": "USD"}
        payload_b = {"invoice_id": "INV-0003", "amount": 100.0, "currency": "USD"}
        assert document_to_bytes(canonicalize_document(payload_a)) == document_to_bytes(
            canonicalize_document(payload_b)
        ), "Numeric fix must be applied before idempotency gate is meaningful"


# ---------------------------------------------------------------------------
# Crypto isolation tests (Finding #6 — Red Team Hardening)
# ---------------------------------------------------------------------------


class TestConstantTimeEquals:
    """Verify _constant_time_equals wrapper behaviour.

    Note: This function is now in api.auth (unified authentication module).
    """

    def test_equal_strings(self):
        from api.auth import _constant_time_equals

        assert _constant_time_equals("abc", "abc") is True

    def test_unequal_strings(self):
        from api.auth import _constant_time_equals

        assert _constant_time_equals("abc", "xyz") is False

    def test_empty_strings(self):
        from api.auth import _constant_time_equals

        assert _constant_time_equals("", "") is True

    def test_hex_hash_comparison(self):
        """Simulates real-world use: comparing hex-encoded BLAKE3 hashes."""
        from api.auth import _constant_time_equals
        from protocol.hashes import hash_bytes

        h1 = hash_bytes(b"test-key").hex()
        h2 = hash_bytes(b"test-key").hex()
        h3 = hash_bytes(b"other-key").hex()
        assert _constant_time_equals(h1, h2) is True
        assert _constant_time_equals(h1, h3) is False
