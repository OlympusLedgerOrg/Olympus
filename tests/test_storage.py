"""
Tests for storage layer.

These tests validate that the Postgres storage layer correctly
persists the Sparse Merkle State Forest, shard headers, and ledger entries.

DATABASE: PostgreSQL (production storage layer)
This test uses storage/postgres.py to validate production persistence semantics.
See docs/08_database_strategy.md for rationale.
"""

import os
from datetime import UTC, datetime

import nacl.signing
import pytest

from protocol.hashes import hash_bytes
from protocol.ssmf import verify_proof
from storage.postgres import StorageLayer

# Mark all tests in this module as requiring PostgreSQL
pytestmark = pytest.mark.postgres

# Test database connection string
TEST_DB = os.environ.get('TEST_DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/olympus_test')


@pytest.fixture
def storage():
    """Create a storage layer for testing."""
    storage = StorageLayer(TEST_DB)
    storage.init_schema()
    yield storage
    # Note: We don't clean up tables to preserve append-only semantics
    # In production, use a fresh test database for each run


@pytest.fixture
def signing_key():
    """Create a signing key for testing."""
    seed = hash_bytes(b"test seed for storage tests")
    return nacl.signing.SigningKey(seed)


def test_schema_initialization(storage):
    """Test that schema initializes without errors."""
    # Schema should already be initialized by fixture
    # Just verify we can query the tables
    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) as count FROM smt_leaves")
        assert cur.fetchone()['count'] >= 0


def test_append_record_creates_proof(storage, signing_key):
    """Test that appending a record creates a valid proof."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"
    value_hash = hash_bytes(b"test value")

    root, proof, header, signature, ledger_entry = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=value_hash,
        signing_key=signing_key
    )

    # Verify proof is valid
    assert verify_proof(proof) is True
    assert proof.root_hash == root
    assert len(proof.siblings) == 256

    # Verify header
    assert header['shard_id'] == shard_id
    assert header['root_hash'] == root.hex()
    assert len(bytes.fromhex(header['header_hash'])) == 32

    # Verify signature
    assert len(bytes.fromhex(signature)) == 64

    # Verify ledger entry
    assert ledger_entry.shard_id == shard_id
    assert ledger_entry.record_hash == value_hash.hex()
    assert ledger_entry.shard_root == root.hex()


def test_append_record_prevents_duplicates(storage, signing_key):
    """Test that appending the same record twice fails."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"
    value_hash = hash_bytes(b"test value")

    # First append should succeed
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=value_hash,
        signing_key=signing_key
    )

    # Second append should fail
    with pytest.raises(ValueError, match="already exists"):
        storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id="doc1",
            version=1,
            value_hash=value_hash,
            signing_key=signing_key
        )


def test_append_multiple_versions(storage, signing_key):
    """Test that multiple versions of the same document can coexist."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    value_v1 = hash_bytes(b"version 1")
    value_v2 = hash_bytes(b"version 2")
    value_v3 = hash_bytes(b"version 3")

    # Append three versions
    root1, proof1, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=value_v1,
        signing_key=signing_key
    )

    root2, proof2, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=2,
        value_hash=value_v2,
        signing_key=signing_key
    )

    root3, proof3, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=3,
        value_hash=value_v3,
        signing_key=signing_key
    )

    # All proofs should be valid
    assert verify_proof(proof1) is True
    assert verify_proof(proof2) is True
    assert verify_proof(proof3) is True

    # Roots should be different
    assert root1 != root2 != root3


def test_get_proof_returns_valid_proof(storage, signing_key):
    """Test that get_proof returns a valid proof for existing records."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"
    value_hash = hash_bytes(b"test value")

    # Append record
    root, _, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=value_hash,
        signing_key=signing_key
    )

    # Get proof
    proof = storage.get_proof(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1
    )

    assert proof is not None
    assert verify_proof(proof) is True
    assert proof.root_hash == root


def test_get_proof_returns_none_for_nonexistent(storage):
    """Test that get_proof returns None for non-existent records."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    proof = storage.get_proof(
        shard_id=shard_id,
        record_type="document",
        record_id="nonexistent",
        version=1
    )

    assert proof is None


def test_get_latest_header(storage, signing_key):
    """Test that get_latest_header returns the most recent header."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append first record
    root1, _, header1, sig1, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key
    )

    # Append second record
    root2, _, header2, sig2, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key
    )

    # Get latest header
    latest = storage.get_latest_header(shard_id)

    assert latest is not None
    assert latest['header']['header_hash'] == header2['header_hash']
    assert latest['header']['root_hash'] == root2.hex()
    assert latest['signature'] == sig2


def test_get_ledger_tail(storage, signing_key):
    """Test that get_ledger_tail returns recent entries."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append multiple records
    entries = []
    for i in range(5):
        _, _, _, _, entry = storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=f"doc{i}",
            version=1,
            value_hash=hash_bytes(f"value {i}".encode()),
            signing_key=signing_key
        )
        entries.append(entry)

    # Get last 3 entries
    tail = storage.get_ledger_tail(shard_id, n=3)

    assert len(tail) == 3
    # Should be in reverse order (most recent first)
    assert tail[0].entry_hash == entries[4].entry_hash
    assert tail[1].entry_hash == entries[3].entry_hash
    assert tail[2].entry_hash == entries[2].entry_hash


def test_verify_persisted_root(storage, signing_key):
    """Test that verify_persisted_root validates root integrity."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append records
    for i in range(3):
        storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=f"doc{i}",
            version=1,
            value_hash=hash_bytes(f"value {i}".encode()),
            signing_key=signing_key
        )

    # Verify root
    assert storage.verify_persisted_root(shard_id) is True


def test_shard_header_chain_linkage(storage, signing_key):
    """Test that shard headers form a proper chain."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append first record
    _, _, header1, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key
    )

    # First header should have empty previous hash
    assert header1['previous_header_hash'] == ""

    # Append second record
    _, _, header2, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key
    )

    # Second header should link to first
    assert header2['previous_header_hash'] == header1['header_hash']


def test_ledger_chain_linkage(storage, signing_key):
    """Test that ledger entries form a proper chain."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append first record
    _, _, _, _, entry1 = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key
    )

    # First entry should have empty previous hash
    assert entry1.prev_entry_hash == ""

    # Append second record
    _, _, _, _, entry2 = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key
    )

    # Second entry should link to first
    assert entry2.prev_entry_hash == entry1.entry_hash


def test_get_all_shard_ids(storage, signing_key):
    """Test that get_all_shard_ids returns all shards."""
    ts = datetime.now(UTC).timestamp()
    shard1 = f"test_shard_1_{ts}"
    shard2 = f"test_shard_2_{ts}"

    # Append to two different shards
    storage.append_record(
        shard_id=shard1,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key
    )

    storage.append_record(
        shard_id=shard2,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key
    )

    # Get all shard IDs
    shard_ids = storage.get_all_shard_ids()

    assert shard1 in shard_ids
    assert shard2 in shard_ids


def test_deterministic_root_recomputation(storage, signing_key):
    """Test that root can be deterministically recomputed from leaves."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    # Append multiple records
    roots = []
    for i in range(5):
        root, _, _, _, _ = storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=f"doc{i}",
            version=1,
            value_hash=hash_bytes(f"value {i}".encode()),
            signing_key=signing_key
        )
        roots.append(root)

    # Load tree state and verify root matches
    with storage._get_connection() as conn, conn.cursor() as cur:
        tree = storage._load_tree_state(cur, shard_id)
        computed_root = tree.get_root()

        # Should match the last recorded root
        assert computed_root == roots[-1]
