"""Integration tests for Postgres ingestion durability and proof compatibility."""

import os
import uuid

import nacl.signing
import pytest

from api.ingest import _smt_proof_to_merkle_proof_dict
from protocol.canonical import CANONICAL_VERSION
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.merkle import deserialize_merkle_proof
from storage.postgres import StorageLayer


TEST_DB = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.postgres
@pytest.mark.skipif(
    not TEST_DB,
    reason="TEST_DATABASE_URL is not set; skipping PostgreSQL integration tests.",
)
def test_postgres_persistence_survives_restart():
    """Verify proof mappings remain available after a new StorageLayer instance is created."""
    storage1 = StorageLayer(TEST_DB)
    storage1.init_schema()

    signing_key = nacl.signing.SigningKey(hash_bytes(b"postgres-persistence-test"))
    shard_id = f"ingest_persistence/{uuid.uuid4()}"
    batch_id = str(uuid.uuid4())
    proof_id = str(uuid.uuid4())
    value_hash = hash_bytes(b"durable-ingest-payload")
    canonicalization = canonicalization_provenance(
        "application/octet-stream", CANONICAL_VERSION
    )

    root_hash, proof, header, signature, ledger_entry = storage1.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc-durable",
        version=1,
        value_hash=value_hash,
        signing_key=signing_key,
        canonicalization=canonicalization,
    )

    merkle_proof = _smt_proof_to_merkle_proof_dict(proof, value_hash)
    storage1.store_ingestion_batch(
        batch_id,
        [
            {
                "proof_id": proof_id,
                "record_id": "doc-durable",
                "shard_id": shard_id,
                "record_type": "document",
                "version": 1,
                "content_hash": value_hash.hex(),
                "merkle_root": root_hash.hex(),
                "merkle_proof": merkle_proof,
                "ledger_entry_hash": ledger_entry.entry_hash,
                "timestamp": ledger_entry.ts,
                "canonicalization": canonicalization,
                "persisted": True,
                "batch_id": batch_id,
                "batch_index": 0,
            }
        ],
    )
    storage1.close()

    storage2 = StorageLayer(TEST_DB)
    storage2.init_schema()
    persisted = storage2.get_ingestion_proof(proof_id)
    storage2.close()

    assert persisted is not None
    assert persisted["proof_id"] == proof_id
    assert persisted["content_hash"] == value_hash.hex()
    assert persisted["batch_id"] == batch_id
    assert persisted["ledger_entry_hash"] == ledger_entry.entry_hash


def test_sibling_serialization_regression():
    """Ensure legacy string sibling encodings deserialize correctly."""
    proof_dict = {
        "leaf_hash": "00" * 32,
        "leaf_index": 0,
        "siblings": [
            ["11" * 32, "left"],
            ["22" * 32, "right"],
            ["33" * 32, False],
        ],
        "root_hash": "ff" * 32,
    }

    deserialized = deserialize_merkle_proof(proof_dict)

    assert deserialized.siblings[0][1] == "left"
    assert deserialized.siblings[1][1] == "right"
    assert deserialized.siblings[2][1] == "left"
