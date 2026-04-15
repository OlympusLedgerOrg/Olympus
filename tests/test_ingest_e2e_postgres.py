"""
End-to-end Postgres integration test for the Olympus ingest pipeline.

This test performs a full round-trip against a real PostgreSQL database:
    1. Use StorageLayer to commit a document to the SMT (bypassing the Go sequencer)
    2. Store the ingestion proof via StorageLayer.store_ingestion_batch()
    3. GET /ingest/records/{proof_id}/proof to retrieve the proof via HTTP API
    4. Verify the proof cryptographically (SMT inclusion proof)
    5. GET /ingest/records/hash/{content_hash}/verify for server-side verification

This is the most valuable integration test for the Olympus ledger because
it validates the entire persistence and retrieval pipeline, including:
    - Sparse Merkle Tree (SMT) commitment via Rust extension
    - Shard header signing
    - Ledger entry persistence
    - Proof serialization and storage
    - Proof retrieval via HTTP API
    - Cryptographic proof verification

NOTE: This test bypasses the Go sequencer by calling StorageLayer.append_record()
directly. The sequencer integration is tested separately in sequencer-specific
tests. This approach allows testing Postgres persistence without requiring the
full Go service stack.

To run locally:
    export TEST_DATABASE_URL="postgresql://olympus:olympus@localhost:5432/olympus"
    export OLYMPUS_INGEST_SIGNING_KEY="0000000000000000000000000000000000000000000000000000000000000000"
    pytest tests/test_ingest_e2e_postgres.py -v
"""

from __future__ import annotations

import os
import uuid

import nacl.signing
import pytest
from fastapi.testclient import TestClient

from api import ingest as ingest_api
from api.app import app
from api.ingest import _smt_proof_to_merkle_proof_dict
from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.ssmf import ExistenceProof, verify_proof as verify_smt_proof
from protocol.timestamps import current_timestamp
from storage.postgres import StorageLayer


TEST_DB = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.postgres
@pytest.mark.skipif(
    not TEST_DB,
    reason="TEST_DATABASE_URL is not set; skipping PostgreSQL integration tests.",
)
class TestIngestE2EPostgres:
    """
    End-to-end integration tests for the Olympus ingest pipeline against PostgreSQL.

    These tests validate the complete round-trip of document ingestion,
    proof storage, retrieval, and cryptographic verification. They bypass
    the Go sequencer by using StorageLayer.append_record() directly, which
    allows testing the Postgres persistence layer in isolation.
    """

    @pytest.fixture(autouse=True)
    def _setup_storage(self) -> None:
        """Initialize storage layer and test API key."""
        # Generate unique test identifiers to avoid collision
        self._test_shard_id = f"e2e-test.{uuid.uuid4()}"
        self._test_proof_ids: list[str] = []

        # Create storage layer directly
        self._storage = StorageLayer(TEST_DB)
        self._storage.init_schema()

        # Create a deterministic signing key for tests
        signing_key_hex = os.environ.get(
            "OLYMPUS_INGEST_SIGNING_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        self._signing_key = nacl.signing.SigningKey(bytes.fromhex(signing_key_hex))

        # Reset ingest state and register test API key
        ingest_api._reset_ingest_state_for_tests()
        ingest_api._register_api_key_for_tests(
            api_key="e2e-test-key",
            key_id="e2e-test-key-id",
            scopes={"ingest", "commit", "verify"},
            expires_at="2099-01-01T00:00:00Z",
        )

        # Wire up the storage layer so HTTP API can retrieve proofs from Postgres
        # This is necessary because _reset_ingest_state_for_tests() clears _storage
        ingest_api._storage = self._storage

        yield

        # Cleanup - reset storage before closing to avoid leaving stale reference
        ingest_api._storage = None
        self._storage.close()

    @pytest.fixture
    def client(self) -> TestClient:
        """Create a test client with authentication headers."""
        return TestClient(app, headers={"X-API-Key": "e2e-test-key"})

    def _canonicalize_and_hash(self, content: dict) -> tuple[bytes, str]:
        """Canonicalize document and compute BLAKE3 hash."""
        canonical = canonicalize_document(content)
        content_bytes = document_to_bytes(canonical)
        content_hash = hash_bytes(content_bytes)
        return content_hash, content_hash.hex()

    def _commit_document_to_smt(
        self,
        content: dict,
        record_id: str,
        record_type: str = "document",
        version: int = 1,
    ) -> tuple[str, str, ExistenceProof, dict]:
        """
        Commit a document to the SMT via StorageLayer.append_record().

        Returns:
            Tuple of (proof_id, content_hash_hex, smt_proof, ledger_entry)
        """
        # Canonicalize and hash
        content_hash, content_hash_hex = self._canonicalize_and_hash(content)

        # Canonicalization provenance
        canonicalization = canonicalization_provenance("application/json", CANONICAL_VERSION)

        # Append to SMT via storage layer
        root_hash, proof, header, signature, ledger_entry = self._storage.append_record(
            shard_id=self._test_shard_id,
            record_type=record_type,
            record_id=record_id,
            version=version,
            value_hash=content_hash,
            signing_key=self._signing_key,
            canonicalization=canonicalization,
        )

        # Generate proof_id
        proof_id = str(uuid.uuid4())
        self._test_proof_ids.append(proof_id)

        return (
            proof_id,
            content_hash_hex,
            proof,
            {
                "root_hash": root_hash,
                "header": header,
                "signature": signature,
                "ledger_entry": ledger_entry,
                "canonicalization": canonicalization,
            },
        )

    def _store_ingestion_proof(
        self,
        proof_id: str,
        record_id: str,
        content_hash_hex: str,
        smt_proof: ExistenceProof,
        ledger_entry_data: dict,
        batch_id: str | None = None,
    ) -> None:
        """Store ingestion proof mapping via StorageLayer."""
        batch_id = batch_id or str(uuid.uuid4())

        # Convert SMT proof to merkle proof dict format
        merkle_proof = _smt_proof_to_merkle_proof_dict(
            smt_proof,
            bytes.fromhex(content_hash_hex),
        )

        record = {
            "proof_id": proof_id,
            "batch_id": batch_id,
            "batch_index": 0,
            "shard_id": self._test_shard_id,
            "record_type": "document",
            "record_id": record_id,
            "version": 1,
            "content_hash": content_hash_hex,
            "merkle_root": smt_proof.root_hash.hex(),
            "merkle_proof": merkle_proof,
            "ledger_entry_hash": ledger_entry_data["ledger_entry"].entry_hash,
            "timestamp": current_timestamp(),
            "canonicalization": ledger_entry_data["canonicalization"],
            "persisted": True,
        }

        self._storage.store_ingestion_batch(batch_id, [record])

    def test_full_round_trip_commit_retrieve_verify(self, client: TestClient) -> None:
        """
        Full round-trip E2E test: commit to SMT → persist proof → retrieve via API → verify.

        This is THE integration test that validates Olympus works end-to-end:
            1. Commit a document to the SMT via StorageLayer.append_record()
            2. Store the proof mapping via StorageLayer.store_ingestion_batch()
            3. GET the proof from /ingest/records/{proof_id}/proof
            4. Verify the SMT proof cryptographically
            5. GET /ingest/records/hash/{content_hash}/verify for server-side verification

        This test is more valuable than fifty unit tests for grant credibility
        because it exercises the complete persistence and verification pipeline
        against a real PostgreSQL instance.
        """
        # 1. Create a unique test document
        test_content = {
            "document_type": "e2e_test",
            "title": "E2E Round-Trip Test Document",
            "body": f"This document validates the full ingestion pipeline. Test ID: {uuid.uuid4()}",
            "metadata": {
                "version": 1,
                "created_by": "pytest",
                "purpose": "integration_test",
            },
        }
        record_id = f"doc-e2e-{uuid.uuid4()}"

        # 2. Commit to SMT via StorageLayer
        proof_id, content_hash, smt_proof, ledger_data = self._commit_document_to_smt(
            test_content, record_id
        )

        # 3. Persist the proof mapping
        self._store_ingestion_proof(proof_id, record_id, content_hash, smt_proof, ledger_data)

        # 4. Verify the SMT proof cryptographically (before API retrieval)
        assert verify_smt_proof(smt_proof), (
            "SMT proof verification failed - the proof chain does not "
            "reconstruct to the claimed root hash"
        )

        # 5. Retrieve proof via HTTP API
        proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
        assert proof_resp.status_code == 200, f"Proof retrieval failed: {proof_resp.text}"

        proof_data = proof_resp.json()
        assert proof_data["proof_id"] == proof_id
        assert proof_data["content_hash"] == content_hash
        assert proof_data["merkle_root"] == smt_proof.root_hash.hex()
        assert proof_data["ledger_entry_hash"], "Ledger entry hash should be present"

        # 6. Verify content hash lookup via API
        verify_resp = client.get(f"/ingest/records/hash/{content_hash}/verify")
        assert verify_resp.status_code == 200, f"Hash verification failed: {verify_resp.text}"
        verify_data = verify_resp.json()
        assert verify_data["content_hash"] == content_hash
        assert verify_data["merkle_proof_valid"] is True, (
            "Server-side Merkle proof verification should return True"
        )

    def test_proof_persists_and_survives_cache_clear(self, client: TestClient) -> None:
        """
        Verify that proofs persist in PostgreSQL and survive in-memory cache clears.

        This validates that the PostgreSQL persistence layer correctly stores
        proof data and that it can be retrieved even after the in-memory cache
        is cleared (simulating an API server restart).
        """
        # Create and commit a document
        test_content = {
            "type": "persistence_test",
            "data": f"Unique data for persistence test: {uuid.uuid4()}",
        }
        record_id = f"doc-persist-{uuid.uuid4()}"

        proof_id, content_hash, smt_proof, ledger_data = self._commit_document_to_smt(
            test_content, record_id
        )
        self._store_ingestion_proof(proof_id, record_id, content_hash, smt_proof, ledger_data)

        # Clear the in-memory cache (simulates API server restart)
        ingest_api._ingestion_store.clear()
        ingest_api._content_index.clear()

        # Proof should still be retrievable from PostgreSQL
        proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
        assert proof_resp.status_code == 200, (
            f"Proof should persist in PostgreSQL after cache clear: {proof_resp.text}"
        )
        proof_data = proof_resp.json()
        assert proof_data["proof_id"] == proof_id
        assert proof_data["content_hash"] == content_hash

    def test_verify_proof_bundle_via_api(self, client: TestClient) -> None:
        """
        Verify that submitted proof bundles can be validated by the server.

        This tests the /ingest/proofs/verify endpoint which allows external
        parties to submit proof bundles for server-side validation.
        """
        # Create and commit a document
        test_content = {
            "type": "verify_bundle_test",
            "data": f"Content for verification: {uuid.uuid4()}",
        }
        record_id = f"doc-verify-{uuid.uuid4()}"

        proof_id, content_hash, smt_proof, ledger_data = self._commit_document_to_smt(
            test_content, record_id
        )
        self._store_ingestion_proof(proof_id, record_id, content_hash, smt_proof, ledger_data)

        # Get the full proof bundle
        proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
        assert proof_resp.status_code == 200
        proof_bundle = proof_resp.json()

        # Submit the proof bundle for verification
        verify_resp = client.post(
            "/ingest/proofs/verify",
            json={
                "proof_id": proof_bundle["proof_id"],
                "content_hash": proof_bundle["content_hash"],
                "merkle_root": proof_bundle["merkle_root"],
                "merkle_proof": proof_bundle["merkle_proof"],
            },
        )
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()

        assert verify_data["content_hash_matches_proof"] is True
        assert verify_data["merkle_proof_valid"] is True
        assert verify_data["known_to_server"] is True

    def test_multiple_records_same_shard(self, client: TestClient) -> None:
        """
        Verify that multiple records can be committed to the same shard.

        Tests that the SMT correctly handles multiple insertions and that
        each record gets a unique, verifiable proof.
        """
        records = []
        batch_id = str(uuid.uuid4())

        # Commit multiple records with unique content
        for i in range(3):
            # Include UUID in content to ensure uniqueness across test runs
            content = {"index": i, "data": f"Record {i} in batch", "unique_id": str(uuid.uuid4())}
            record_id = f"batch-doc-{i}-{uuid.uuid4()}"

            proof_id, content_hash, smt_proof, ledger_data = self._commit_document_to_smt(
                content, record_id
            )
            self._store_ingestion_proof(
                proof_id, record_id, content_hash, smt_proof, ledger_data, batch_id
            )
            records.append((proof_id, content_hash, smt_proof))

        # Verify all proofs are independently verifiable
        for proof_id, content_hash, smt_proof in records:
            # Verify SMT proof
            assert verify_smt_proof(smt_proof), f"SMT proof for {proof_id} should be valid"

            # Verify API retrieval
            proof_resp = client.get(f"/ingest/records/{proof_id}/proof")
            assert proof_resp.status_code == 200
            assert proof_resp.json()["content_hash"] == content_hash


@pytest.mark.postgres
@pytest.mark.skipif(
    not TEST_DB,
    reason="TEST_DATABASE_URL is not set; skipping PostgreSQL integration tests.",
)
def test_storage_layer_ingestion_proof_roundtrip() -> None:
    """
    Low-level test of StorageLayer ingestion proof persistence.

    This tests the storage layer directly without going through the HTTP API,
    validating that proof data is correctly serialized to and from PostgreSQL.
    """
    storage = StorageLayer(TEST_DB)
    storage.init_schema()

    # Use UUID-based content hash to avoid collision with previous test runs
    # (ingestion_proofs table has a unique constraint on content_hash)
    unique_suffix = uuid.uuid4().bytes[:8]
    batch_id = f"storage-test-{uuid.uuid4()}"
    proof_id = str(uuid.uuid4())
    shard_id = f"storage-test.{uuid.uuid4()}"
    content_hash = b"\xab" * 24 + unique_suffix  # 32 bytes with unique suffix
    merkle_root = b"\xcd" * 32
    ledger_entry_hash = b"\xef" * 32

    test_record = {
        "proof_id": proof_id,
        "batch_id": batch_id,
        "batch_index": 0,
        "shard_id": shard_id,
        "record_type": "document",
        "record_id": "test-doc",
        "version": 1,
        "content_hash": content_hash.hex(),
        "merkle_root": merkle_root.hex(),
        "merkle_proof": {
            "leaf_hash": "aa" * 32,
            "siblings": [],
            "root_hash": merkle_root.hex(),
        },
        "ledger_entry_hash": ledger_entry_hash.hex(),
        "timestamp": "2024-01-01T00:00:00Z",
        "canonicalization": {"version": "canonical_v2", "mime_type": "application/json"},
        "persisted": True,
    }

    # Store the proof
    storage.store_ingestion_batch(batch_id, [test_record])

    # Retrieve by proof_id
    retrieved = storage.get_ingestion_proof(proof_id)
    assert retrieved is not None, "Proof should be retrievable after storage"
    assert retrieved["proof_id"] == proof_id
    assert retrieved["content_hash"] == content_hash.hex()
    assert retrieved["merkle_root"] == merkle_root.hex()
    assert retrieved["shard_id"] == shard_id

    # Retrieve by content_hash
    retrieved_by_hash = storage.get_ingestion_proof_by_content_hash(content_hash)
    assert retrieved_by_hash is not None
    assert retrieved_by_hash["proof_id"] == proof_id

    storage.close()
