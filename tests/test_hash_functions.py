"""
Tests for new BLAKE3 hash functions
"""

import pytest

from protocol.hashes import (
    blake3_hash,
    create_dual_root_commitment,
    forest_root,
    hash_bytes,
    leaf_hash,
    merkle_root,
    node_hash,
    parse_dual_root_commitment,
    record_key,
    shard_header_hash,
)


def test_blake3_hash_deterministic():
    """Test that BLAKE3 hash is deterministic."""
    parts = [b"hello", b"world"]

    hash1 = blake3_hash(parts)
    hash2 = blake3_hash(parts)

    assert hash1 == hash2
    assert len(hash1) == 32


def test_blake3_hash_different_inputs():
    """Test that different inputs produce different hashes."""
    hash1 = blake3_hash([b"hello", b"world"])
    hash2 = blake3_hash([b"hello", b"mars"])

    assert hash1 != hash2


def test_record_key_deterministic():
    """Test that record key generation is deterministic."""
    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc1", 1)

    assert key1 == key2
    assert len(key1) == 32


def test_record_key_different_versions():
    """Test that different versions produce different keys."""
    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc1", 2)

    assert key1 != key2


def test_record_key_different_types():
    """Test that different record types produce different keys."""
    key1 = record_key("document", "doc1", 1)
    key2 = record_key("policy", "doc1", 1)

    assert key1 != key2


def test_record_key_different_ids():
    """Test that different record IDs produce different keys."""
    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc2", 1)

    assert key1 != key2


def test_leaf_hash_valid():
    """Test leaf hash computation."""
    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")

    leaf = leaf_hash(key, value_hash)

    assert len(leaf) == 32


def test_leaf_hash_deterministic():
    """Test that leaf hash is deterministic."""
    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")

    leaf1 = leaf_hash(key, value_hash)
    leaf2 = leaf_hash(key, value_hash)

    assert leaf1 == leaf2


def test_leaf_hash_handles_short_key():
    """Leaf hashing should still produce a digest even with odd-length keys."""
    leaf = leaf_hash(b"short", hash_bytes(b"value"))
    assert len(leaf) == 32


def test_leaf_hash_handles_short_value_hash():
    """Leaf hashing is tolerant of non-32-byte value inputs."""
    key = record_key("document", "doc1", 1)
    leaf = leaf_hash(key, b"short")
    assert len(leaf) == 32


def test_node_hash_valid():
    """Test node hash computation."""
    left = hash_bytes(b"left")
    right = hash_bytes(b"right")

    node = node_hash(left, right)

    assert len(node) == 32


def test_node_hash_deterministic():
    """Test that node hash is deterministic."""
    left = hash_bytes(b"left")
    right = hash_bytes(b"right")

    node1 = node_hash(left, right)
    node2 = node_hash(left, right)

    assert node1 == node2


def test_node_hash_order_matters():
    """Test that node hash is order-dependent."""
    left = hash_bytes(b"left")
    right = hash_bytes(b"right")

    node1 = node_hash(left, right)
    node2 = node_hash(right, left)

    assert node1 != node2


def test_node_hash_accepts_short_left():
    """Node hashing is tolerant of non-32-byte left inputs."""
    node = node_hash(b"short", hash_bytes(b"right"))
    assert len(node) == 32


def test_node_hash_accepts_short_right():
    """Node hashing is tolerant of non-32-byte right inputs."""
    node = node_hash(hash_bytes(b"left"), b"short")
    assert len(node) == 32


def test_merkle_root_single_leaf():
    """Test Merkle root with single leaf."""
    leaves = [hash_bytes(b"leaf1")]

    root = merkle_root(leaves)

    assert len(root) == 32


def test_merkle_root_multiple_leaves():
    """Test Merkle root with multiple leaves."""
    leaves = [hash_bytes(b"leaf1"), hash_bytes(b"leaf2"), hash_bytes(b"leaf3")]

    root = merkle_root(leaves)

    assert len(root) == 32


def test_merkle_root_deterministic():
    """Test that Merkle root is deterministic."""
    leaves = [hash_bytes(b"leaf1"), hash_bytes(b"leaf2")]

    root1 = merkle_root(leaves)
    root2 = merkle_root(leaves)

    assert root1 == root2


def test_merkle_root_order_matters():
    """Test that Merkle root changes with leaf order."""
    leaves1 = [hash_bytes(b"leaf1"), hash_bytes(b"leaf2")]
    leaves2 = [hash_bytes(b"leaf2"), hash_bytes(b"leaf1")]

    root1 = merkle_root(leaves1)
    root2 = merkle_root(leaves2)

    assert root1 != root2


def test_merkle_root_empty_list():
    """Test that empty list is rejected."""
    with pytest.raises(ValueError, match="empty list"):
        merkle_root([])


def test_merkle_root_invalid_leaf_length():
    """Test that invalid leaf length is rejected."""
    leaves = [b"short", hash_bytes(b"leaf2")]

    with pytest.raises(ValueError, match="must be 32 bytes"):
        merkle_root(leaves)


def test_shard_header_hash_deterministic():
    """Test that shard header hash is deterministic."""
    fields = {
        "shard_id": "shard1",
        "root_hash": hash_bytes(b"root").hex(),
        "timestamp": "2024-01-01T00:00:00Z",
    }

    hash1 = shard_header_hash(fields)
    hash2 = shard_header_hash(fields)

    assert hash1 == hash2
    assert len(hash1) == 32


def test_shard_header_hash_changes_with_content():
    """Test that shard header hash changes with content."""
    fields1 = {
        "shard_id": "shard1",
        "root_hash": hash_bytes(b"root").hex(),
        "timestamp": "2024-01-01T00:00:00Z",
    }

    fields2 = {
        "shard_id": "shard2",
        "root_hash": hash_bytes(b"root").hex(),
        "timestamp": "2024-01-01T00:00:00Z",
    }

    hash1 = shard_header_hash(fields1)
    hash2 = shard_header_hash(fields2)

    assert hash1 != hash2


def test_forest_root_deterministic():
    """Test that forest root is deterministic."""
    headers = [hash_bytes(b"header1"), hash_bytes(b"header2")]

    root1 = forest_root(headers)
    root2 = forest_root(headers)

    assert root1 == root2
    assert len(root1) == 32


def test_forest_root_sorted():
    """Test that forest root sorts headers for determinism."""
    headers1 = [hash_bytes(b"header1"), hash_bytes(b"header2")]
    headers2 = [hash_bytes(b"header2"), hash_bytes(b"header1")]

    root1 = forest_root(headers1)
    root2 = forest_root(headers2)

    # Should be the same because they're sorted internally
    assert root1 == root2


def test_forest_root_empty_list():
    """Test that empty list is rejected."""
    with pytest.raises(ValueError, match="empty list"):
        forest_root([])


def test_forest_root_invalid_hash_length():
    """Test that invalid hash length is rejected."""
    headers = [b"short", hash_bytes(b"header2")]

    with pytest.raises(ValueError, match="must be 32 bytes"):
        forest_root(headers)


# ---------------------------------------------------------------------------
# Dual-root commitment tests
# ---------------------------------------------------------------------------


def test_create_dual_root_commitment_returns_32_bytes():
    """Dual-root commitment must always be exactly 32 bytes."""
    blake3_root = hash_bytes(b"blake3 shard root")
    poseidon_root = hash_bytes(b"poseidon root as bytes")
    result = create_dual_root_commitment(blake3_root, poseidon_root)
    assert len(result) == 32


def test_create_dual_root_commitment_deterministic():
    """Same inputs must produce the same commitment."""
    blake3_root = hash_bytes(b"blake3 shard root")
    poseidon_root = hash_bytes(b"poseidon root as bytes")
    assert create_dual_root_commitment(blake3_root, poseidon_root) == create_dual_root_commitment(
        blake3_root, poseidon_root
    )


def test_create_dual_root_commitment_different_blake3_root():
    """Changing the BLAKE3 root must change the commitment."""
    poseidon_root = hash_bytes(b"poseidon root as bytes")
    c1 = create_dual_root_commitment(hash_bytes(b"root_a"), poseidon_root)
    c2 = create_dual_root_commitment(hash_bytes(b"root_b"), poseidon_root)
    assert c1 != c2


def test_create_dual_root_commitment_different_poseidon_root():
    """Changing the Poseidon root must change the commitment."""
    blake3_root = hash_bytes(b"blake3 shard root")
    c1 = create_dual_root_commitment(blake3_root, hash_bytes(b"poseidon_a"))
    c2 = create_dual_root_commitment(blake3_root, hash_bytes(b"poseidon_b"))
    assert c1 != c2


def test_create_dual_root_commitment_differs_from_single_root_hash():
    """The dual commitment must not equal the BLAKE3 hash of either root alone."""
    from protocol.hashes import LEDGER_PREFIX

    blake3_root = hash_bytes(b"blake3 shard root")
    poseidon_root = hash_bytes(b"poseidon root as bytes")
    dual = create_dual_root_commitment(blake3_root, poseidon_root)
    single = blake3_hash([LEDGER_PREFIX, blake3_root])
    assert dual != single


def test_create_dual_root_commitment_rejects_short_blake3_root():
    """BLAKE3 root shorter than 32 bytes must raise ValueError."""
    with pytest.raises(ValueError, match="32 bytes"):
        create_dual_root_commitment(b"short", hash_bytes(b"poseidon"))


def test_create_dual_root_commitment_rejects_short_poseidon_root():
    """Poseidon root shorter than 32 bytes must raise ValueError."""
    with pytest.raises(ValueError, match="32 bytes"):
        create_dual_root_commitment(hash_bytes(b"blake3"), b"short")


def test_parse_dual_root_commitment_round_trips():
    """parse_dual_root_commitment must recover the original roots from 64-byte input."""
    blake3_root = hash_bytes(b"blake3 shard root")
    poseidon_root = hash_bytes(b"poseidon root as bytes")
    serialized = blake3_root + poseidon_root
    recovered_blake3, recovered_poseidon = parse_dual_root_commitment(serialized)
    assert recovered_blake3 == blake3_root
    assert recovered_poseidon == poseidon_root


def test_parse_dual_root_commitment_rejects_wrong_length():
    """Input that is not exactly 64 bytes must raise ValueError."""
    with pytest.raises(ValueError, match="64 bytes"):
        parse_dual_root_commitment(b"too short")

    with pytest.raises(ValueError, match="64 bytes"):
        parse_dual_root_commitment(b"x" * 65)
