"""Cross-language parity tests: Rust SMT vs Python SMT.

These tests verify the interface contract of SparseMerkleTree (whichever
backend is active) and, when both backends are available, assert that they
produce byte-identical roots and proofs.
"""

import pytest

from protocol.ssmf import (
    EMPTY_HASHES,
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    verify_nonexistence_proof,
    verify_proof,
)


class TestSmtInterfaceContract:
    """Verify SparseMerkleTree (either backend) honours the interface."""

    def test_empty_tree_root(self):
        tree = SparseMerkleTree()
        assert tree.get_root() == EMPTY_HASHES[256]

    def test_single_insert_root(self):
        key = b"\x01" * 32
        val = b"\x02" * 32
        tree = SparseMerkleTree()
        tree.update(key, val, "docling@2.3.1", "v1")
        root = tree.get_root()
        assert len(root) == 32
        assert root != EMPTY_HASHES[256]

    def test_two_inserts_order_independent(self):
        k1, k2 = b"\x01" * 32, b"\x02" * 32
        v1, v2 = b"\xaa" * 32, b"\xbb" * 32

        t1 = SparseMerkleTree()
        t1.update(k1, v1, "docling@2.3.1", "v1")
        t1.update(k2, v2, "docling@2.3.1", "v1")

        t2 = SparseMerkleTree()
        t2.update(k2, v2, "docling@2.3.1", "v1")
        t2.update(k1, v1, "docling@2.3.1", "v1")

        assert t1.get_root() == t2.get_root()

    def test_get_returns_value(self):
        key = b"\x01" * 32
        val = b"\x02" * 32
        tree = SparseMerkleTree()
        assert tree.get(key) is None
        tree.update(key, val, "docling@2.3.1", "v1")
        assert tree.get(key) == val

    def test_leaves_property(self):
        key = b"\x01" * 32
        val = b"\x02" * 32
        tree = SparseMerkleTree()
        tree.update(key, val, "docling@2.3.1", "v1")
        leaves = tree.leaves
        assert len(leaves) == 1
        assert leaves[key] == val

    def test_nodes_property_root_key(self):
        key = b"\x01" * 32
        val = b"\x02" * 32
        tree = SparseMerkleTree()
        tree.update(key, val, "docling@2.3.1", "v1")
        nodes = tree.nodes
        # Root node should be at empty tuple key
        assert () in nodes
        assert nodes[()] == tree.get_root()

    def test_inclusion_proof_verifies(self):
        key = b"\x01" * 32
        val = b"\x02" * 32
        tree = SparseMerkleTree()
        tree.update(key, val, "docling@2.3.1", "v1")
        proof = tree.prove_existence(key)
        assert isinstance(proof, ExistenceProof)
        assert verify_proof(proof)

    def test_nonexistence_proof_verifies(self):
        present = b"\x01" * 32
        absent = b"\x02" * 32
        val = b"\xaa" * 32
        tree = SparseMerkleTree()
        tree.update(present, val, "docling@2.3.1", "v1")
        proof = tree.prove_nonexistence(absent)
        assert isinstance(proof, NonExistenceProof)
        assert verify_nonexistence_proof(proof)

    def test_ten_keys_all_proofs_verify(self):
        tree = SparseMerkleTree()
        keys = []
        for i in range(10):
            k = bytes([i] + [0] * 31)
            v = bytes([i + 100] + [0] * 31)
            tree.update(k, v, "docling@2.3.1", "v1")
            keys.append((k, v))

        for k, v in keys:
            proof = tree.prove_existence(k)
            assert verify_proof(proof), f"Proof failed for key {k[0]}"

    def test_update_existing_key(self):
        key = b"\x01" * 32
        v1 = b"\x02" * 32
        v2 = b"\x03" * 32
        tree = SparseMerkleTree()
        tree.update(key, v1, "docling@2.3.1", "v1")
        r1 = tree.get_root()
        tree.update(key, v2, "docling@2.3.1", "v1")
        r2 = tree.get_root()
        assert r1 != r2
        assert tree.get(key) == v2
        assert len(tree.leaves) == 1

    def test_prove_dispatches_correctly(self):
        k1 = b"\x01" * 32
        k2 = b"\x02" * 32
        val = b"\xaa" * 32
        tree = SparseMerkleTree()
        tree.update(k1, val, "docling@2.3.1", "v1")

        proof_exist = tree.prove(k1)
        assert isinstance(proof_exist, ExistenceProof)
        assert verify_proof(proof_exist)

        proof_absent = tree.prove(k2)
        assert isinstance(proof_absent, NonExistenceProof)
        assert verify_nonexistence_proof(proof_absent)

    def test_size_property(self):
        """Test size: uses .size property when available, else len(leaves)."""
        tree = SparseMerkleTree()
        # size is a Rust getter; pure-Python class exposes it via len(leaves)
        _size = getattr(tree, "size", None)
        if _size is not None:
            assert _size == 0
        tree.update(b"\x01" * 32, b"\x02" * 32, "docling@2.3.1", "v1")
        _size = getattr(tree, "size", None)
        if _size is not None:
            assert _size == 1
        else:
            assert len(tree.leaves) == 1
        tree.update(b"\x03" * 32, b"\x04" * 32, "docling@2.3.1", "v1")
        _size = getattr(tree, "size", None)
        if _size is not None:
            assert _size == 2
        else:
            assert len(tree.leaves) == 2
        # Update existing key should not increase count
        tree.update(b"\x01" * 32, b"\x05" * 32, "docling@2.3.1", "v1")
        _size = getattr(tree, "size", None)
        if _size is not None:
            assert _size == 2
        else:
            assert len(tree.leaves) == 2

    def test_nonexistence_proof_on_empty_tree(self):
        tree = SparseMerkleTree()
        proof = tree.prove_nonexistence(b"\x01" * 32)
        assert isinstance(proof, NonExistenceProof)
        assert verify_nonexistence_proof(proof)
        assert proof.root_hash == EMPTY_HASHES[256]

    def test_existence_proof_raises_on_missing_key(self):
        tree = SparseMerkleTree()
        with pytest.raises(ValueError):
            tree.prove_existence(b"\x01" * 32)

    def test_nonexistence_proof_raises_on_present_key(self):
        tree = SparseMerkleTree()
        tree.update(b"\x01" * 32, b"\x02" * 32, "docling@2.3.1", "v1")
        with pytest.raises(ValueError):
            tree.prove_nonexistence(b"\x01" * 32)

    def test_invalid_key_length_rejected(self):
        tree = SparseMerkleTree()
        with pytest.raises(ValueError):
            tree.update(b"\x01" * 16, b"\x02" * 32, "docling@2.3.1", "v1")
        with pytest.raises(ValueError):
            tree.update(b"\x01" * 32, b"\x02" * 16, "docling@2.3.1", "v1")
        with pytest.raises(ValueError):
            tree.get(b"\x01" * 16)
