"""
Tests for Merkle tree service.

Validates tree construction, inclusion proof generation, and proof verification
using known inputs.
"""

from __future__ import annotations

import hashlib

import pytest

from api.services.merkle import MerkleProof, build_tree, generate_proof, verify_proof


def _h(s: str) -> str:
    """Hex SHA-256 of a UTF-8 string."""
    return hashlib.sha256(s.encode()).hexdigest()


class TestBuildTree:
    def test_single_leaf(self):
        leaf = _h("a")
        tree = build_tree([leaf])
        assert tree.root_hash == leaf
        assert tree.leaf_hashes == [leaf]

    def test_two_leaves(self):
        a, b = _h("a"), _h("b")
        tree = build_tree([a, b])
        # Leaves are sorted; compute expected root manually
        sorted_leaves = sorted([a, b])
        expected = hashlib.sha256(bytes.fromhex(sorted_leaves[0]) + bytes.fromhex(sorted_leaves[1])).hexdigest()
        assert tree.root_hash == expected

    def test_four_leaves(self):
        leaves = [_h(s) for s in ["alpha", "beta", "gamma", "delta"]]
        tree = build_tree(leaves)
        assert isinstance(tree.root_hash, str)
        assert len(tree.root_hash) == 64

    def test_deterministic_regardless_of_insertion_order(self):
        leaves = [_h(s) for s in ["x", "y", "z"]]
        import random
        shuffled = leaves[:]
        random.shuffle(shuffled)
        tree1 = build_tree(leaves)
        tree2 = build_tree(shuffled)
        assert tree1.root_hash == tree2.root_hash

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_tree([])

    def test_odd_number_of_leaves_ct_promotion(self):
        """Lone node at any level must be promoted without rehashing."""
        leaves = [_h(s) for s in ["a", "b", "c"]]
        tree = build_tree(leaves)
        assert len(tree.root_hash) == 64


class TestGenerateProof:
    def test_proof_for_each_leaf(self):
        leaves = [_h(s) for s in ["apple", "banana", "cherry", "date"]]
        tree = build_tree(leaves)
        for leaf in leaves:
            proof = generate_proof(leaf, tree)
            assert proof.leaf_hash == leaf
            assert proof.root_hash == tree.root_hash

    def test_missing_leaf_raises(self):
        leaves = [_h(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        with pytest.raises(ValueError, match="not found"):
            generate_proof(_h("c"), tree)


class TestVerifyProof:
    def test_valid_proof_returns_true(self):
        leaves = [_h(s) for s in ["p", "q", "r", "s"]]
        tree = build_tree(leaves)
        for leaf in leaves:
            proof = generate_proof(leaf, tree)
            assert verify_proof(leaf, proof, tree.root_hash) is True

    def test_tampered_leaf_fails(self):
        leaves = [_h(s) for s in ["m", "n", "o"]]
        tree = build_tree(leaves)
        proof = generate_proof(leaves[0], tree)
        # Replace the leaf with a different hash
        tampered_leaf = _h("tampered")
        assert verify_proof(tampered_leaf, proof, tree.root_hash) is False

    def test_tampered_sibling_fails(self):
        leaves = [_h(s) for s in ["1", "2", "3", "4"]]
        tree = build_tree(leaves)
        leaf = leaves[0]
        proof = generate_proof(leaf, tree)
        # Tamper with the first sibling hash
        bad_siblings = [(_h("evil"), proof.siblings[0][1])] + list(proof.siblings[1:])
        bad_proof = MerkleProof(
            leaf_hash=leaf, root_hash=proof.root_hash, siblings=bad_siblings
        )
        assert verify_proof(leaf, bad_proof, tree.root_hash) is False

    def test_wrong_root_fails(self):
        leaves = [_h(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(leaves[0], tree)
        wrong_root = _h("wrong_root")
        assert verify_proof(leaves[0], proof, wrong_root) is False

    def test_single_leaf_proof(self):
        """Single-leaf tree has no siblings; root equals the leaf."""
        leaf = _h("solo")
        tree = build_tree([leaf])
        proof = generate_proof(leaf, tree)
        assert proof.siblings == []
        assert verify_proof(leaf, proof, tree.root_hash) is True
