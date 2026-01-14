"""
Tests for Sparse Merkle Tree implementation
"""

import pytest

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import ExistenceProof, SparseMerkleTree, verify_nonexistence_proof, verify_proof


def test_ssmf_empty_tree():
    """Test empty sparse Merkle tree."""
    tree = SparseMerkleTree()
    root = tree.get_root()
    assert len(root) == 32


def test_ssmf_insert_and_retrieve():
    """Test inserting and retrieving values."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")

    tree.update(key, value_hash)

    retrieved = tree.get(key)
    assert retrieved == value_hash


def test_ssmf_versioning_via_key():
    """Test that versioning works through key derivation."""
    tree = SparseMerkleTree()

    key_v1 = record_key("document", "doc1", 1)
    key_v2 = record_key("document", "doc1", 2)

    value_v1 = hash_bytes(b"version 1")
    value_v2 = hash_bytes(b"version 2")

    tree.update(key_v1, value_v1)
    tree.update(key_v2, value_v2)

    # Both versions should exist independently
    assert tree.get(key_v1) == value_v1
    assert tree.get(key_v2) == value_v2


def test_ssmf_existence_proof():
    """Test generating and verifying existence proof."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")

    tree.update(key, value_hash)

    proof = tree.prove_existence(key)

    assert proof.key == key
    assert proof.value_hash == value_hash
    assert len(proof.siblings) == 256
    assert proof.root_hash == tree.get_root()

    # Verify proof
    assert verify_proof(proof) is True


def test_ssmf_existence_proof_for_nonexistent_key():
    """Test that proving existence of non-existent key fails."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)

    with pytest.raises(ValueError, match="does not exist"):
        tree.prove_existence(key)


def test_ssmf_nonexistence_proof():
    """Test generating and verifying non-existence proof."""
    tree = SparseMerkleTree()

    # Add some data
    key1 = record_key("document", "doc1", 1)
    value_hash1 = hash_bytes(b"test value 1")
    tree.update(key1, value_hash1)

    # Prove that a different key doesn't exist
    key2 = record_key("document", "doc2", 1)
    proof = tree.prove_nonexistence(key2)

    assert proof.key == key2
    assert len(proof.siblings) == 256
    assert proof.root_hash == tree.get_root()

    # Verify proof
    assert verify_nonexistence_proof(proof) is True


def test_ssmf_nonexistence_proof_for_existing_key():
    """Test that proving non-existence of existing key fails."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash)

    with pytest.raises(ValueError, match="exists in tree"):
        tree.prove_nonexistence(key)


def test_ssmf_tampered_proof_detected():
    """Test that tampering with proof is detected."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash)

    proof = tree.prove_existence(key)

    # Tamper with value hash
    tampered_proof = ExistenceProof(
        key=proof.key,
        value_hash=hash_bytes(b"different value"),
        siblings=proof.siblings,
        root_hash=proof.root_hash,
    )

    assert verify_proof(tampered_proof) is False


def test_ssmf_tampered_siblings_detected():
    """Test that tampering with siblings is detected."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash)

    proof = tree.prove_existence(key)

    # Tamper with a sibling
    tampered_siblings = proof.siblings[:]
    tampered_siblings[0] = hash_bytes(b"tampered")

    tampered_proof = ExistenceProof(
        key=proof.key,
        value_hash=proof.value_hash,
        siblings=tampered_siblings,
        root_hash=proof.root_hash,
    )

    assert verify_proof(tampered_proof) is False


def test_ssmf_wrong_key_detected():
    """Test that using wrong key in proof is detected."""
    tree = SparseMerkleTree()

    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc2", 1)
    value_hash = hash_bytes(b"test value")

    tree.update(key1, value_hash)

    proof = tree.prove_existence(key1)

    # Use wrong key
    wrong_proof = ExistenceProof(
        key=key2, value_hash=proof.value_hash, siblings=proof.siblings, root_hash=proof.root_hash
    )

    assert verify_proof(wrong_proof) is False


def test_ssmf_invalid_key_length():
    """Test that invalid key length is rejected."""
    tree = SparseMerkleTree()

    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.update(b"short", hash_bytes(b"value"))

    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.get(b"short")


def test_ssmf_invalid_value_hash_length():
    """Test that invalid value hash length is rejected."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)

    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.update(key, b"short")


def test_ssmf_multiple_updates():
    """Test multiple updates and root consistency."""
    tree = SparseMerkleTree()

    keys = [record_key("document", f"doc{i}", 1) for i in range(5)]
    values = [hash_bytes(f"value {i}".encode()) for i in range(5)]

    for key, value in zip(keys, values, strict=False):
        tree.update(key, value)

    # All values should be retrievable
    for key, value in zip(keys, values, strict=False):
        assert tree.get(key) == value

    # Root should be consistent
    root1 = tree.get_root()
    root2 = tree.get_root()
    assert root1 == root2


def test_ssmf_deterministic_root():
    """Test that same updates produce same root."""
    tree1 = SparseMerkleTree()
    tree2 = SparseMerkleTree()

    keys = [record_key("document", f"doc{i}", 1) for i in range(3)]
    values = [hash_bytes(f"value {i}".encode()) for i in range(3)]

    for key, value in zip(keys, values, strict=False):
        tree1.update(key, value)
        tree2.update(key, value)

    assert tree1.get_root() == tree2.get_root()
