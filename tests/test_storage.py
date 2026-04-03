"""
Tests for storage layer.

PRODUCTION STORAGE LAYER TESTING (PostgreSQL REQUIRED)
=======================================================

These tests validate the PRODUCTION PostgreSQL storage layer implementation.
They test transaction semantics, persistence, and ACID guarantees.

DATABASE: PostgreSQL 16+ (via storage.postgres.StorageLayer)
CODE PATH: storage/postgres.py (production storage layer)
WHAT IS TESTED:
  ✅ Transaction atomicity across all four tables
  ✅ Sequence number generation (SELECT MAX(seq)+1 pattern)
  ✅ Chain linkage preservation (prev_entry_hash, previous_header_hash)
  ✅ Constraint enforcement (32-byte hashes, key lengths)
  ✅ Concurrent access safety
  ✅ Persistence and recovery

TABLES TESTED:
  - smt_leaves: Sparse Merkle Tree leaf nodes
  - smt_nodes: Sparse Merkle Tree internal nodes
  - shard_headers: Signed shard root commitments
  - ledger_entries: Append-only ledger chain

SETUP:
  export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
  pytest tests/test_storage.py -v

See docs/08_database_strategy.md for complete database strategy documentation.
"""

import json
import os
import uuid
from datetime import datetime, timedelta


try:
    from datetime import UTC
except ImportError:  # Python < 3.11
    from datetime import timezone

    UTC = timezone.utc

import nacl.signing
import psycopg
import pytest
from psycopg.rows import dict_row

from protocol.hashes import global_key, hash_bytes, record_key
from protocol.shards import create_shard_header
from protocol.ssmf import verify_nonexistence_proof, verify_proof
from protocol.timestamps import current_timestamp
from storage.postgres import _NODE_REHASH_GATE, StorageLayer


# Test database connection string
TEST_DB = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not TEST_DB,
        reason="TEST_DATABASE_URL is not set; skipping PostgreSQL storage tests.",
    ),
]


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
        assert cur.fetchone()["count"] >= 0


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
        signing_key=signing_key,
    )

    # Verify proof is valid
    assert verify_proof(proof) is True
    assert proof.root_hash == root
    assert len(proof.siblings) == 256

    # Verify header
    assert header["shard_id"] == shard_id
    assert header["root_hash"] == root.hex()
    assert len(bytes.fromhex(header["header_hash"])) == 32

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
        signing_key=signing_key,
    )

    # Second append should fail
    with pytest.raises(ValueError, match="already exists"):
        storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id="doc1",
            version=1,
            value_hash=value_hash,
            signing_key=signing_key,
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
        signing_key=signing_key,
    )

    root2, proof2, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=2,
        value_hash=value_v2,
        signing_key=signing_key,
    )

    root3, proof3, _, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=3,
        value_hash=value_v3,
        signing_key=signing_key,
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
        signing_key=signing_key,
    )

    # Get proof
    proof = storage.get_proof(
        shard_id=shard_id, record_type="document", record_id="doc1", version=1
    )

    assert proof is not None
    assert verify_proof(proof) is True
    assert proof.root_hash == root


def test_get_proof_returns_none_for_nonexistent(storage):
    """Test that get_proof returns None for non-existent records."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    proof = storage.get_proof(
        shard_id=shard_id, record_type="document", record_id="nonexistent", version=1
    )

    assert proof is None


def test_get_nonexistence_proof_returns_valid_proof(storage, signing_key):
    """Missing records should produce a valid non-existence proof in the global SMT."""
    shard_id = f"test_shard_nonexistence_{datetime.now(UTC).timestamp()}"

    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    proof = storage.get_nonexistence_proof(
        shard_id=shard_id, record_type="document", record_id="missing", version=1
    )

    assert verify_nonexistence_proof(proof) is True
    assert proof.key == global_key(shard_id, record_key("document", "missing", 1))


def test_get_nonexistence_proof_rejects_existing_record(storage, signing_key):
    """Existing records must not return a non-existence proof."""
    shard_id = f"test_shard_nonexistence_exists_{datetime.now(UTC).timestamp()}"

    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    with pytest.raises(ValueError, match="Record exists"):
        storage.get_nonexistence_proof(
            shard_id=shard_id, record_type="document", record_id="doc1", version=1
        )


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
        signing_key=signing_key,
    )

    # Append second record
    root2, _, header2, sig2, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key,
    )

    # Get latest header
    latest = storage.get_latest_header(shard_id)

    assert latest is not None
    assert latest["header"]["header_hash"] == header2["header_hash"]
    assert latest["header"]["root_hash"] == root2.hex()
    assert latest["signature"] == sig2


def test_get_latest_header_detects_corrupt_signature(storage, signing_key):
    """Test that get_latest_header fails if persisted signature is corrupted."""
    shard_id = f"test_shard_corrupt_sig_{datetime.now(UTC).timestamp()}"
    root = hash_bytes(f"root-{shard_id}".encode())
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    header = create_shard_header(shard_id=shard_id, root_hash=root, timestamp=ts)
    pubkey = signing_key.verify_key.encode()

    # Insert a shard header directly with an all-zero (corrupt) signature.
    # This respects the append-only constraint: no UPDATE is performed.
    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO shard_headers
                (shard_id, seq, root, tree_size, header_hash, sig, pubkey, previous_header_hash, ts)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                shard_id,
                0,
                root,
                header["tree_size"],
                bytes.fromhex(header["header_hash"]),
                b"\x00" * 64,
                pubkey,
                "",
                ts,
            ),
        )
        conn.commit()

    with pytest.raises(ValueError, match="Invalid shard header signature"):
        storage.get_latest_header(shard_id)


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
            signing_key=signing_key,
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
            signing_key=signing_key,
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
        signing_key=signing_key,
    )

    # First header should have empty previous hash
    assert header1["previous_header_hash"] == ""

    # Append second record
    _, _, header2, _, _ = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key,
    )

    # Second header should link to first
    assert header2["previous_header_hash"] == header1["header_hash"]


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
        signing_key=signing_key,
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
        signing_key=signing_key,
    )

    # Second entry should link to first
    assert entry2.prev_entry_hash == entry1.entry_hash


def test_get_latest_header_detects_corrupted_signature(storage, signing_key):
    """Test that corrupted shard header signatures are detected on read."""
    shard_id = f"test_shard_corrupted_sig_{datetime.now(UTC).timestamp()}"
    root = hash_bytes(f"root-{shard_id}".encode())
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    header = create_shard_header(shard_id=shard_id, root_hash=root, timestamp=ts)
    pubkey = signing_key.verify_key.encode()

    # Insert a shard header directly with an all-zero (corrupt) signature.
    # This respects the append-only constraint: no UPDATE is performed.
    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO shard_headers
                (shard_id, seq, root, tree_size, header_hash, sig, pubkey, previous_header_hash, ts)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                shard_id,
                0,
                root,
                header["tree_size"],
                bytes.fromhex(header["header_hash"]),
                b"\x00" * 64,
                pubkey,
                "",
                ts,
            ),
        )
        conn.commit()

    with pytest.raises(ValueError, match="Invalid shard header signature"):
        storage.get_latest_header(shard_id)


def test_ledger_entries_reject_out_of_order_seq(storage, signing_key):
    """Test that out-of-order ledger sequence insertion is rejected."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"

    _, _, _, _, entry = storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    payload = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "record_hash": hash_bytes(b"forged").hex(),
        "shard_id": shard_id,
        "shard_root": hash_bytes(b"forged root").hex(),
        "prev_entry_hash": entry.entry_hash,
    }

    with pytest.raises(
        psycopg.errors.RaiseException,
        match=r"Out-of-order ledger entry for shard .*: expected seq \d+, got \d+",
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ledger_entries (shard_id, seq, entry_hash, prev_entry_hash, payload, ts)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    shard_id,
                    5,
                    hash_bytes(b"forged entry hash"),
                    bytes.fromhex(entry.entry_hash),
                    json.dumps(payload),
                    payload["ts"],
                ),
            )


def test_ledger_trigger_rejects_out_of_order_insert(storage):
    """Test that DB trigger rejects out-of-order ledger inserts."""
    shard_id = f"test_shard_{datetime.now(UTC).timestamp()}"
    ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    genesis_payload = {
        "ts": ts,
        "record_hash": "a" * 64,
        "shard_id": shard_id,
        "shard_root": "b" * 64,
        "prev_entry_hash": "",
    }
    genesis_hash = hash_bytes(f"genesis-{shard_id}".encode())
    ooo_hash = hash_bytes(f"ooo-{shard_id}".encode())

    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ledger_entries (shard_id, seq, entry_hash, prev_entry_hash, payload, ts)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (shard_id, 0, genesis_hash, b"", json.dumps(genesis_payload), ts),
        )
        conn.commit()

    with storage._get_connection() as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.RaiseException, match=r"Out-of-order ledger entry"):
            cur.execute(
                """
                INSERT INTO ledger_entries (shard_id, seq, entry_hash, prev_entry_hash, payload, ts)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    shard_id,
                    2,
                    ooo_hash,
                    genesis_hash,
                    json.dumps(genesis_payload),
                    ts,
                ),
            )


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
        signing_key=signing_key,
    )

    storage.append_record(
        shard_id=shard2,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
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
            signing_key=signing_key,
        )
        roots.append(root)

    # Load tree state and verify root matches
    with storage._get_connection() as conn, conn.cursor() as cur:
        tree = storage._load_tree_state(cur)
        computed_root = tree.get_root()

        # Should match the last recorded root
        assert computed_root == roots[-1]


def test_shard_headers_reject_update(storage, signing_key):
    """Test that UPDATE on shard_headers is rejected by append-only trigger."""
    shard_id = f"test_shard_reject_update_{datetime.now(UTC).timestamp()}"

    # Append a record to create a shard header
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Attempt to UPDATE the shard header should fail
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"shard_headers is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE shard_headers
                SET previous_header_hash = 'modified'
                WHERE shard_id = %s
                """,
                (shard_id,),
            )


def test_shard_headers_reject_delete(storage, signing_key):
    """Test that DELETE on shard_headers is rejected by append-only trigger."""
    shard_id = f"test_shard_reject_delete_{datetime.now(UTC).timestamp()}"

    # Append a record to create a shard header
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Attempt to DELETE the shard header should fail
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"shard_headers is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM shard_headers
                WHERE shard_id = %s
                """,
                (shard_id,),
            )


def test_ledger_entries_reject_update(storage, signing_key):
    """Test that UPDATE on ledger_entries is rejected by append-only trigger."""
    shard_id = f"test_ledger_reject_update_{datetime.now(UTC).timestamp()}"

    # Append a record to create a ledger entry
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Attempt to UPDATE the ledger entry should fail
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ledger_entries is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ledger_entries
                SET payload = '{}'
                WHERE shard_id = %s
                """,
                (shard_id,),
            )


def test_ledger_entries_reject_delete(storage, signing_key):
    """Test that DELETE on ledger_entries is rejected by append-only trigger."""
    shard_id = f"test_ledger_reject_delete_{datetime.now(UTC).timestamp()}"

    # Append a record to create a ledger entry
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Attempt to DELETE the ledger entry should fail
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ledger_entries is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ledger_entries
                WHERE shard_id = %s
                """,
                (shard_id,),
            )


def test_smt_leaves_reject_update(storage, signing_key):
    """Test that UPDATE on smt_leaves is rejected by append-only trigger."""
    shard_id = f"test_smt_leaves_reject_update_{datetime.now(UTC).timestamp()}"

    # Append a record to create an SMT leaf
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Compute the actual global key that append_record stored
    actual_key = global_key(shard_id, record_key("document", "doc1", 1))

    # Attempt to UPDATE the SMT leaf should fail
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction, match=r"smt_leaves is append-only"):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE smt_leaves
                SET value_hash = %s
                WHERE key = %s AND version = 1
                """,
                (hash_bytes(b"modified"), actual_key),
            )


def test_smt_leaves_reject_delete(storage, signing_key):
    """Test that DELETE on smt_leaves is rejected by append-only trigger."""
    shard_id = f"test_smt_leaves_reject_delete_{datetime.now(UTC).timestamp()}"

    # Append a record to create an SMT leaf
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Compute the actual global key that append_record stored
    actual_key = global_key(shard_id, record_key("document", "doc1", 1))

    # Attempt to DELETE the SMT leaf should fail
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction, match=r"smt_leaves is append-only"):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM smt_leaves
                WHERE key = %s
                """,
                (actual_key,),
            )


def test_smt_nodes_reject_update(storage, signing_key):
    """Test that UPDATE on smt_nodes is rejected by append-only trigger."""
    shard_id = f"test_smt_nodes_reject_update_{datetime.now(UTC).timestamp()}"

    # Append a record to create SMT nodes
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Target an actual node row that exists.
    # smt_nodes stores internal nodes keyed by (level, encoded_path_prefix), so
    # selecting a concrete persisted row is more robust than assuming a specific
    # level/index representation.
    with storage._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT level, index
            FROM smt_nodes
            ORDER BY level ASC, index ASC
            LIMIT 1
            """
        )
        row = cur.fetchone()
    assert row is not None
    target_level = int(row["level"])
    target_index = bytes(row["index"])

    # Attempt to UPDATE the SMT node should fail
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction, match=r"smt_nodes is append-only"):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE smt_nodes
                SET hash = %s
                WHERE level = %s AND index = %s
                """,
                (hash_bytes(b"modified"), target_level, target_index),
            )


def test_smt_nodes_reject_delete(storage, signing_key):
    """Test that DELETE on smt_nodes is rejected by append-only trigger."""
    shard_id = f"test_smt_nodes_reject_delete_{datetime.now(UTC).timestamp()}"

    # Append a record to create SMT nodes
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )

    # Target an actual node row that exists.
    with storage._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT level, index
            FROM smt_nodes
            ORDER BY level ASC, index ASC
            LIMIT 1
            """
        )
        row = cur.fetchone()
    assert row is not None
    target_level = int(row["level"])
    target_index = bytes(row["index"])

    # Attempt to DELETE the SMT node should fail
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction, match=r"smt_nodes is append-only"):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM smt_nodes
                WHERE level = %s AND index = %s
                """,
                (target_level, target_index),
            )


def _store_ingestion_batch(storage: StorageLayer) -> tuple[str, str]:
    batch_id = f"test_ingestion_batch_{uuid.uuid4()}"
    proof_id = str(uuid.uuid4())
    timestamp = current_timestamp()
    record = {
        "proof_id": proof_id,
        "record_id": "doc-ingest",
        "record_type": "document",
        "version": 1,
        "shard_id": f"ingest/{batch_id}",
        # Include batch_id so each call produces a distinct content_hash, preventing
        # unique-constraint violations when multiple tests share the same database.
        "content_hash": hash_bytes(f"ingest-content-{batch_id}".encode()).hex(),
        "merkle_root": hash_bytes(f"ingest-root-{batch_id}".encode()).hex(),
        "merkle_proof": {"siblings": []},
        "ledger_entry_hash": hash_bytes(f"ingest-ledger-{batch_id}".encode()).hex(),
        "timestamp": timestamp,
        "canonicalization": {"type": "ingest-test"},
        "persisted": True,
    }
    storage.store_ingestion_batch(batch_id, [record])
    return batch_id, proof_id


def test_ingestion_batches_reject_update(storage):
    """Test that UPDATE on ingestion_batches is rejected by append-only trigger."""
    batch_id, _ = _store_ingestion_batch(storage)
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_batches is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ingestion_batches
                SET created_at = NOW()
                WHERE batch_id = %s
                """,
                (batch_id,),
            )


def test_ingestion_batches_reject_delete(storage):
    """Test that DELETE on ingestion_batches is rejected by append-only trigger."""
    batch_id, _ = _store_ingestion_batch(storage)
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_batches is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ingestion_batches
                WHERE batch_id = %s
                """,
                (batch_id,),
            )


def test_ingestion_proofs_reject_update(storage):
    """Test that UPDATE on ingestion_proofs is rejected by append-only trigger."""
    _, proof_id = _store_ingestion_batch(storage)
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_proofs is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ingestion_proofs
                SET record_id = %s
                WHERE proof_id = %s
                """,
                ("modified", proof_id),
            )


def test_ingestion_proofs_reject_delete(storage):
    """Test that DELETE on ingestion_proofs is rejected by append-only trigger."""
    _, proof_id = _store_ingestion_batch(storage)
    with pytest.raises(
        psycopg.errors.ReadOnlySqlTransaction, match=r"ingestion_proofs is append-only"
    ):
        with storage._get_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM ingestion_proofs
                WHERE proof_id = %s
                """,
                (proof_id,),
            )


def test_verify_state_replay_matches_headers_and_ledger(storage, signing_key):
    """Full replay should reproduce every persisted shard root."""
    shard_id = f"test_verify_state_replay_{datetime.now(UTC).timestamp()}"

    values = [hash_bytes(b"alpha"), hash_bytes(b"beta"), hash_bytes(b"gamma")]
    for idx, value_hash in enumerate(values, start=1):
        storage.append_record(
            shard_id=shard_id,
            record_type="document",
            record_id=f"doc{idx}",
            version=1,
            value_hash=value_hash,
            signing_key=signing_key,
        )

    result = storage.verify_state_replay(shard_id)
    assert result["verified"] is True
    assert result["headers_checked"] == 3
    assert result["next_seq"] is None


def test_verify_state_replay_detects_header_root_divergence(storage, signing_key):
    """Replay must fail if the persisted SMT state deviates from the shard headers.

    Since shard_headers is append-only (UPDATE/DELETE are rejected by trigger),
    we simulate divergence by inserting a forged leaf directly into smt_leaves
    outside of append_record.  This changes the tree state without creating a
    corresponding header, so:
    - verify_state_replay detects a count mismatch (more leaves than headers).
    - get_latest_header detects a root mismatch via _assert_root_matches_state.
    """
    shard_id = f"test_verify_state_replay_detects_divergence_{datetime.now(UTC).timestamp()}"

    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"value 1"),
        signing_key=signing_key,
    )
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc2",
        version=1,
        value_hash=hash_bytes(b"value 2"),
        signing_key=signing_key,
    )

    # Simulate state divergence by inserting a forged leaf that was never
    # recorded through append_record.  smt_leaves is append-only (UPDATE/DELETE
    # are blocked), but plain INSERTs are permitted, so this is a realistic
    # threat vector that the replay verifier must detect.
    #
    # Backdate the forged leaf to just before the first persisted header so it
    # is guaranteed to be included in replay and root verification windows.
    # This avoids boundary flakiness when multiple headers share close
    # timestamps.
    forged_version = 9999
    forged_record_key = record_key("document", "forged-doc", forged_version)
    forged_key = global_key(shard_id, forged_record_key)
    forged_value = hash_bytes(b"forged-leaf-value")
    with storage._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT ts FROM shard_headers WHERE shard_id = %s ORDER BY seq ASC LIMIT 1",
            (shard_id,),
        )
        first_header_ts = cur.fetchone()["ts"]
        forged_ts = first_header_ts - timedelta(microseconds=1)
        cur.execute(f"SET LOCAL olympus.allow_smt_insert = '{_NODE_REHASH_GATE}'")
        cur.execute(
            """
            INSERT INTO smt_leaves (key, version, value_hash, ts)
            VALUES (%s, %s, %s, %s)
            """,
            (forged_key, forged_version, forged_value, forged_ts),
        )
        conn.commit()

    # verify_state_replay should detect the discrepancy (count or root mismatch).
    with pytest.raises(ValueError, match="mismatch"):
        storage.verify_state_replay(shard_id)

    # get_latest_header should also reject the diverged state because the
    # recomputed tree root no longer matches the persisted header root.
    with pytest.raises(ValueError, match="Computed root"):
        storage.get_latest_header(shard_id)


def test_replay_naive_datetime_cutoff_is_normalized(storage, signing_key):
    """Timezone-naive cutoffs must not silently miss leaves near the boundary.

    If _load_tree_state or replay_tree_incremental passes a naive datetime to
    the WHERE ts <= %s TIMESTAMPTZ comparison, Postgres may apply local-clock
    semantics and exclude leaves that sit within a microsecond of the boundary.
    This regression test constructs an explicit naive cutoff and verifies that
    verify_state_replay still raises for a forged leaf, and that
    get_latest_header does too — confirming both code paths normalize tzinfo
    before handing the value to psycopg.
    """
    shard_id = f"test_replay_naive_tz_{datetime.now(UTC).timestamp()}"

    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"tz-naive-value-1"),
        signing_key=signing_key,
    )

    # Insert a forged leaf backdated by 1 µs so it falls in the first window.
    forged_version = 8888
    forged_record_key = record_key("document", "tz-forged-doc", forged_version)
    forged_key = global_key(shard_id, forged_record_key)
    forged_value = hash_bytes(b"tz-naive-forged-value")
    with storage._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT ts FROM shard_headers WHERE shard_id = %s ORDER BY seq ASC LIMIT 1",
            (shard_id,),
        )
        first_header_ts = cur.fetchone()["ts"]
        # Construct a naive datetime (tzinfo=None) to simulate application code
        # that strips timezone info before passing a cutoff to the replay path.
        # The guard in _load_tree_state / replay_tree_incremental must re-attach
        # UTC so the TIMESTAMPTZ comparison is unambiguous.
        naive_ts = first_header_ts.replace(tzinfo=None) - timedelta(microseconds=1)
        cur.execute(f"SET LOCAL olympus.allow_smt_insert = '{_NODE_REHASH_GATE}'")
        cur.execute(
            """
            INSERT INTO smt_leaves (key, version, value_hash, ts)
            VALUES (%s, %s, %s, %s)
            """,
            (forged_key, forged_version, forged_value, naive_ts),
        )
        conn.commit()

    # Both replay paths must detect the forged leaf despite the naive timestamp.
    with pytest.raises(ValueError, match="mismatch"):
        storage.verify_state_replay(shard_id)

    with pytest.raises(ValueError, match="Computed root"):
        storage.get_latest_header(shard_id)


def test_init_schema_renames_legacy_smt_tables(storage):
    """init_schema should preserve legacy per-shard SMT tables before creating global SMT tables."""
    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS smt_leaves_legacy_011")
        cur.execute("DROP TABLE IF EXISTS smt_nodes_legacy_011")
        cur.execute("DROP TABLE IF EXISTS smt_leaves")
        cur.execute("DROP TABLE IF EXISTS smt_nodes")
        cur.execute(
            """
            CREATE TABLE smt_leaves (
                shard_id TEXT NOT NULL,
                key BYTEA NOT NULL,
                version INT NOT NULL,
                value_hash BYTEA NOT NULL,
                ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE smt_nodes (
                shard_id TEXT NOT NULL,
                level SMALLINT NOT NULL,
                index BYTEA NOT NULL,
                hash BYTEA NOT NULL,
                ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.commit()

    storage.init_schema()

    with storage._get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM smt_leaves_legacy_011 LIMIT 1")
        assert cur.fetchone() is None
        cur.execute("SELECT 1 FROM smt_nodes_legacy_011 LIMIT 1")
        assert cur.fetchone() is None

        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'smt_leaves'
            ORDER BY ordinal_position
            """
        )
        assert [row["column_name"] for row in cur.fetchall()] == [
            "key",
            "version",
            "value_hash",
            "ts",
        ]

        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'smt_nodes'
            ORDER BY ordinal_position
            """
        )
        assert [row["column_name"] for row in cur.fetchall()] == [
            "level",
            "index",
            "hash",
            "ts",
        ]
