"""
Tests for unified proof generation (existence and non-existence)

This test validates that the new `prove()` method correctly handles
both existence and non-existence cases without raising exceptions.
"""

import pytest

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    is_existence_proof,
    is_nonexistence_proof,
    verify_unified_proof,
)


def test_prove_returns_existence_proof_for_existing_key():
    """Test that prove() returns ExistenceProof for existing keys."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash, "docling@2.3.1", "v1")

    # This should NOT raise an exception
    proof = tree.prove(key)

    # Should be an existence proof
    assert isinstance(proof, ExistenceProof)
    assert is_existence_proof(proof)
    assert not is_nonexistence_proof(proof)

    # Verify proof structure
    assert proof.key == key
    assert proof.value_hash == value_hash
    assert len(proof.siblings) == 256
    assert proof.root_hash == tree.get_root()

    # Verify proof is valid
    assert verify_unified_proof(proof) is True


def test_prove_returns_nonexistence_proof_for_missing_key():
    """
    CRITICAL: Test that prove() returns NonExistenceProof for missing keys.

    This is the core fix - non-existence should NOT raise an exception.
    """
    tree = SparseMerkleTree()

    # Add some data to the tree
    key1 = record_key("document", "doc1", 1)
    value_hash1 = hash_bytes(b"test value 1")
    tree.update(key1, value_hash1, "docling@2.3.1", "v1")

    # Query for a non-existent key
    missing_key = record_key("document", "nonexistent", 1)

    # This should NOT raise an exception
    proof = tree.prove(missing_key)

    # Should be a non-existence proof
    assert isinstance(proof, NonExistenceProof)
    assert is_nonexistence_proof(proof)
    assert not is_existence_proof(proof)

    # Verify proof structure
    assert proof.key == missing_key
    assert len(proof.siblings) == 256
    assert proof.root_hash == tree.get_root()

    # Verify proof is valid
    assert verify_unified_proof(proof) is True


def test_prove_on_empty_tree():
    """Test that prove() works on empty tree (returns non-existence proof)."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)

    # Should return non-existence proof without exception
    proof = tree.prove(key)

    assert isinstance(proof, NonExistenceProof)
    assert proof.key == key
    assert len(proof.siblings) == 256
    assert verify_unified_proof(proof) is True


def test_prove_multiple_keys_mixed_existence():
    """Test prove() with multiple keys, some existing and some not."""
    tree = SparseMerkleTree()

    # Add some keys
    existing_keys = [record_key("document", f"doc{i}", 1) for i in range(3)]
    for key in existing_keys:
        tree.update(key, hash_bytes(f"value for {key.hex()}".encode()), "docling@2.3.1", "v1")

    # Test existing keys
    for key in existing_keys:
        proof = tree.prove(key)
        assert isinstance(proof, ExistenceProof)
        assert verify_unified_proof(proof) is True

    # Test non-existing keys
    missing_keys = [record_key("document", f"missing{i}", 1) for i in range(3)]
    for key in missing_keys:
        proof = tree.prove(key)
        assert isinstance(proof, NonExistenceProof)
        assert verify_unified_proof(proof) is True


def test_prove_invalid_key_length():
    """Test that prove() still validates key length."""
    tree = SparseMerkleTree()

    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.prove(b"short")


def test_prove_deterministic():
    """Test that prove() returns deterministic results."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)

    # First proof (non-existence)
    proof1 = tree.prove(key)
    proof2 = tree.prove(key)

    assert isinstance(proof1, NonExistenceProof)
    assert isinstance(proof2, NonExistenceProof)
    assert proof1.key == proof2.key
    assert proof1.root_hash == proof2.root_hash
    assert proof1.siblings == proof2.siblings

    # Add the key
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash, "docling@2.3.1", "v1")

    # Second set of proofs (existence)
    proof3 = tree.prove(key)
    proof4 = tree.prove(key)

    assert isinstance(proof3, ExistenceProof)
    assert isinstance(proof4, ExistenceProof)
    assert proof3.key == proof4.key
    assert proof3.value_hash == proof4.value_hash
    assert proof3.root_hash == proof4.root_hash
    assert proof3.siblings == proof4.siblings


def test_backward_compatibility_with_old_methods():
    """Test that old prove_existence and prove_nonexistence still work."""
    tree = SparseMerkleTree()

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")
    tree.update(key, value_hash, "docling@2.3.1", "v1")

    # Old method should still work
    existence_proof = tree.prove_existence(key)
    assert isinstance(existence_proof, ExistenceProof)

    # Old method should still raise for non-existent key
    missing_key = record_key("document", "missing", 1)
    with pytest.raises(ValueError):
        tree.prove_existence(missing_key)

    # Old non-existence method should still work
    nonexistence_proof = tree.prove_nonexistence(missing_key)
    assert isinstance(nonexistence_proof, NonExistenceProof)

    # Old method should still raise for existing key
    with pytest.raises(ValueError):
        tree.prove_nonexistence(key)


def test_unified_verification():
    """Test that verify_unified_proof works with both proof types."""
    tree = SparseMerkleTree()

    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc2", 1)
    value_hash = hash_bytes(b"test value")

    tree.update(key1, value_hash, "docling@2.3.1", "v1")

    # Get both types of proofs
    existence_proof = tree.prove(key1)
    nonexistence_proof = tree.prove(key2)

    # Both should verify successfully
    assert verify_unified_proof(existence_proof) is True
    assert verify_unified_proof(nonexistence_proof) is True


def test_type_helpers():
    """Test the type checking helper functions."""
    tree = SparseMerkleTree()

    key1 = record_key("document", "doc1", 1)
    key2 = record_key("document", "doc2", 1)
    value_hash = hash_bytes(b"test value")

    tree.update(key1, value_hash, "docling@2.3.1", "v1")

    existence_proof = tree.prove(key1)
    nonexistence_proof = tree.prove(key2)

    # Test is_existence_proof
    assert is_existence_proof(existence_proof) is True
    assert is_existence_proof(nonexistence_proof) is False

    # Test is_nonexistence_proof
    assert is_nonexistence_proof(existence_proof) is False
    assert is_nonexistence_proof(nonexistence_proof) is True
