"""
Tests for new BLAKE3 hash functions
"""

import pytest
from protocol.hashes import (
    blake3_hash,
    record_key,
    leaf_hash,
    node_hash,
    merkle_root,
    shard_header_hash,
    forest_root,
    hash_bytes,
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


def test_leaf_hash_invalid_key_length():
    """Test that invalid key length is rejected."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        leaf_hash(b"short", hash_bytes(b"value"))


def test_leaf_hash_invalid_value_length():
    """Test that invalid value hash length is rejected."""
    key = record_key("document", "doc1", 1)
    
    with pytest.raises(ValueError, match="must be 32 bytes"):
        leaf_hash(key, b"short")


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


def test_node_hash_invalid_left_length():
    """Test that invalid left hash length is rejected."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        node_hash(b"short", hash_bytes(b"right"))


def test_node_hash_invalid_right_length():
    """Test that invalid right hash length is rejected."""
    with pytest.raises(ValueError, match="must be 32 bytes"):
        node_hash(hash_bytes(b"left"), b"short")


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
        "timestamp": "2024-01-01T00:00:00Z"
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
        "timestamp": "2024-01-01T00:00:00Z"
    }
    
    fields2 = {
        "shard_id": "shard2",
        "root_hash": hash_bytes(b"root").hex(),
        "timestamp": "2024-01-01T00:00:00Z"
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
