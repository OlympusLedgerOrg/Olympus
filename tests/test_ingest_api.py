"""Tests for api.ingest module (batch ingestion endpoints)."""

import pytest
from fastapi.testclient import TestClient

from api import ingest as ingest_api
from api.app import app


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
        assert "endpoints" in data
        assert "/ingest/records" in data["endpoints"]
        assert "/ingest/records/hash/{content_hash}/verify" in data["endpoints"]

    def test_health_includes_version(self, client: TestClient):
        resp = client.get("/health")
        data = resp.json()
        assert data["version"] == "0.5.0"

    def test_root_includes_ingest_endpoints(self, client: TestClient):
        resp = client.get("/")
        data = resp.json()
        assert "/ingest/records" in data["endpoints"]
        assert "/ingest/records/hash/{content_hash}/verify" in data["endpoints"]
        assert "/ingest/commit" in data["endpoints"]


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
        assert data["poseidon_root"] is None

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
        assert resp2.json()["poseidon_root"] is None

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
        """Providing an api_key field should not cause errors."""
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
        assert "/ingest/commit" in data["endpoints"]


class TestAuthAndRateLimiting:
    def test_ingest_requires_api_key(self):
        ingest_api._reset_ingest_state_for_tests()
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
