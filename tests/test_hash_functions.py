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


def test_create_dual_root_commitment_returns_bytes():
    """create_dual_root_commitment must return bytes."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment = create_dual_root_commitment(b3, pos)
    assert isinstance(commitment, bytes)


def test_create_dual_root_commitment_deterministic():
    """Same inputs must always produce the same commitment."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    assert create_dual_root_commitment(b3, pos) == create_dual_root_commitment(b3, pos)


def test_create_dual_root_commitment_rejects_empty_blake3_root():
    """Empty blake3_root must raise ValueError."""
    with pytest.raises(ValueError, match="blake3_root"):
        create_dual_root_commitment(b"", hash_bytes(b"poseidon root"))


def test_create_dual_root_commitment_rejects_empty_poseidon_root():
    """Empty poseidon_root must raise ValueError."""
    with pytest.raises(ValueError, match="poseidon_root"):
        create_dual_root_commitment(hash_bytes(b"blake3 root"), b"")


def test_parse_dual_root_commitment_round_trip():
    """create → parse must return the original roots unchanged."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment = create_dual_root_commitment(b3, pos)
    extracted_b3, extracted_pos = parse_dual_root_commitment(commitment)
    assert extracted_b3 == b3
    assert extracted_pos == pos


def test_parse_dual_root_commitment_round_trip_variable_lengths():
    """Round-trip must work for roots that are not exactly 32 bytes."""
    b3 = b"short"
    pos = b"also-short"
    commitment = create_dual_root_commitment(b3, pos)
    extracted_b3, extracted_pos = parse_dual_root_commitment(commitment)
    assert extracted_b3 == b3
    assert extracted_pos == pos


def test_parse_dual_root_commitment_rejects_too_short():
    """Commitments that are too short must raise ValueError."""
    with pytest.raises(ValueError, match="too short"):
        parse_dual_root_commitment(b"tiny")


def test_parse_dual_root_commitment_rejects_tampered_binding_hash():
    """Commitments with a corrupted binding hash must raise ValueError."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment = bytearray(create_dual_root_commitment(b3, pos))
    # Flip the last byte of the binding hash
    commitment[-1] ^= 0xFF
    with pytest.raises(ValueError, match="binding hash verification failed"):
        parse_dual_root_commitment(bytes(commitment))


def test_parse_dual_root_commitment_rejects_tampered_root():
    """Commitments with a corrupted root must fail binding hash verification."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment = bytearray(create_dual_root_commitment(b3, pos))
    # Flip a byte inside the blake3_root portion (after the 2-byte length prefix)
    commitment[2] ^= 0xFF
    with pytest.raises(ValueError, match="binding hash verification failed"):
        parse_dual_root_commitment(bytes(commitment))


def test_dual_root_commitment_domain_separation():
    """Different root pairs must produce different commitments."""
    b3_a = hash_bytes(b"doc A blake3 root")
    pos_a = hash_bytes(b"doc A poseidon root")
    b3_b = hash_bytes(b"doc B blake3 root")
    pos_b = hash_bytes(b"doc B poseidon root")

    commitment_a = create_dual_root_commitment(b3_a, pos_a)
    commitment_b = create_dual_root_commitment(b3_b, pos_b)
    assert commitment_a != commitment_b


def test_dual_root_commitment_order_matters():
    """Swapping blake3_root and poseidon_root must produce a different commitment."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment_ab = create_dual_root_commitment(b3, pos)
    commitment_ba = create_dual_root_commitment(pos, b3)
    assert commitment_ab != commitment_ba


def test_parse_dual_root_commitment_rejects_truncated_commitment():
    """A commitment truncated before the binding hash must raise ValueError."""
    b3 = hash_bytes(b"blake3 root")
    pos = hash_bytes(b"poseidon root")
    commitment = create_dual_root_commitment(b3, pos)
    # Drop the last 10 bytes (part of the binding hash)
    with pytest.raises(ValueError):
        parse_dual_root_commitment(commitment[:-10])
