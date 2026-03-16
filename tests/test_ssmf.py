"""
Tests for Sparse Merkle Tree implementation
"""

import pytest

from protocol.hashes import hash_bytes, record_key
from protocol.ssmf import (
    ExistenceProof,
    SparseMerkleTree,
    diff_sparse_merkle_trees,
    verify_nonexistence_proof,
    verify_proof,
)


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


def test_ssmf_existence_proof_size_is_constant_across_tree_sizes():
    """Existence proofs should stay fixed-width regardless of tree cardinality."""
    proof_sizes: list[int] = []

    for tree_size in (1, 4, 64):
        tree = SparseMerkleTree()
        keys = [record_key("document", f"doc-{idx}", 1) for idx in range(tree_size)]
        values = [hash_bytes(f"value-{idx}".encode()) for idx in range(tree_size)]

        for key, value in zip(keys, values, strict=False):
            tree.update(key, value)

        proof = tree.prove_existence(keys[-1])
        proof_sizes.append(
            len(proof.key)
            + len(proof.value_hash)
            + sum(len(sibling) for sibling in proof.siblings)
            + len(proof.root_hash)
        )

    assert proof_sizes == [8288, 8288, 8288]


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


def test_ssmf_root_independent_of_insert_order():
    """Insertion order should not change the final root for the same key/value set."""
    keys = [record_key("document", f"doc{i}", 1) for i in range(4)]
    values = [hash_bytes(f"value {i}".encode()) for i in range(4)]

    tree_in_order = SparseMerkleTree()
    for key, value in zip(keys, values, strict=False):
        tree_in_order.update(key, value)

    tree_reordered = SparseMerkleTree()
    # Apply a different network arrival order
    reorder = [2, 0, 3, 1]
    for idx in reorder:
        tree_reordered.update(keys[idx], values[idx])

    assert tree_in_order.get_root() == tree_reordered.get_root()


def test_ssmf_diff_reports_added_changed_and_removed_keys():
    """Tree diffs should classify added, changed, and removed leaves deterministically."""
    before = SparseMerkleTree()
    after = SparseMerkleTree()

    key_removed = record_key("document", "removed", 1)
    key_changed = record_key("document", "changed", 1)
    key_added = record_key("document", "added", 1)

    before.update(key_removed, hash_bytes(b"old removed value"))
    before.update(key_changed, hash_bytes(b"before change"))

    after.update(key_changed, hash_bytes(b"after change"))
    after.update(key_added, hash_bytes(b"new value"))

    diff = diff_sparse_merkle_trees(before, after)

    assert [entry.key for entry in diff["added"]] == [key_added]
    assert [entry.key for entry in diff["changed"]] == [key_changed]
    assert [entry.key for entry in diff["removed"]] == [key_removed]
    assert diff["changed"][0].before_value_hash == hash_bytes(b"before change")
    assert diff["changed"][0].after_value_hash == hash_bytes(b"after change")


def test_ssmf_diff_is_empty_for_identical_trees():
    """No diff entries should be reported when the trees are identical."""
    left = SparseMerkleTree()
    right = SparseMerkleTree()

    key = record_key("document", "same", 1)
    value_hash = hash_bytes(b"same value")
    left.update(key, value_hash)
    right.update(key, value_hash)

    diff = diff_sparse_merkle_trees(left, right)

    assert diff == {"added": [], "changed": [], "removed": []}


def test_ssmf_prove_with_invalid_key_length():
    """Test that prove() rejects invalid key length."""
    tree = SparseMerkleTree()

    # Try to prove with a key that's not 32 bytes
    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.prove(b"short_key")


def test_ssmf_prove_existence_returns_existence_proof():
    """Test that prove() returns ExistenceProof for existing keys."""
    from protocol.ssmf import is_existence_proof, is_nonexistence_proof

    tree = SparseMerkleTree()
    key = record_key("document", "existing", 1)
    value = hash_bytes(b"value")
    tree.update(key, value)

    # Use the prove() method
    proof = tree.prove(key)

    # Should be an ExistenceProof
    assert is_existence_proof(proof) is True
    assert is_nonexistence_proof(proof) is False
    proof_dict = proof.to_dict()
    assert proof_dict["exists"] is True
    assert proof.key == key
    assert proof.value_hash == value


def test_ssmf_prove_nonexistence_returns_nonexistence_proof():
    """Test that prove() returns NonExistenceProof for missing keys."""
    from protocol.ssmf import is_existence_proof, is_nonexistence_proof

    tree = SparseMerkleTree()
    key = record_key("document", "missing", 1)

    # Use the prove() method
    proof = tree.prove(key)

    # Should be a NonExistenceProof
    assert is_nonexistence_proof(proof) is True
    assert is_existence_proof(proof) is False
    proof_dict = proof.to_dict()
    assert proof_dict["exists"] is False
    assert proof.key == key


def test_ssmf_verify_unified_proof():
    """Test verify_unified_proof function with both proof types."""
    from protocol.ssmf import verify_unified_proof

    tree = SparseMerkleTree()
    key1 = record_key("document", "exists", 1)
    value1 = hash_bytes(b"value1")
    tree.update(key1, value1)

    key2 = record_key("document", "missing", 1)

    # Test with existence proof
    existence_proof = tree.prove(key1)
    assert verify_unified_proof(existence_proof) is True

    # Test with nonexistence proof
    nonexistence_proof = tree.prove(key2)
    assert verify_unified_proof(nonexistence_proof) is True

    # Test with invalid proof type (should return False)
    assert verify_unified_proof("not a proof") is False


def test_ssmf_prove_existence_invalid_key():
    """Test prove_existence raises error for invalid key."""
    tree = SparseMerkleTree()

    # Try to get existence proof for invalid key length
    with pytest.raises(ValueError, match="must be 32 bytes"):
        tree.prove_existence(b"short")


def test_ssmf_prove_existence_missing_key():
    """Test prove_existence raises error for missing key."""
    tree = SparseMerkleTree()
    key = record_key("document", "missing", 1)

    # Try to get existence proof for key that doesn't exist
    with pytest.raises(ValueError, match="does not exist"):
        tree.prove_existence(key)
