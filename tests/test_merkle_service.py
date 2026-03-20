"""
Tests for Merkle tree service.

Validates tree construction, inclusion proof generation, and proof verification
using known inputs.
"""

from __future__ import annotations

import blake3

import pytest

from api.services.merkle import MerkleProof, build_tree, generate_proof, verify_proof


def _b3(s: str) -> str:
    """Hex BLAKE3 of a UTF-8 string."""
    return blake3.blake3(s.encode()).hexdigest()


class TestBuildTree:
    def test_single_leaf(self):
        leaf = _b3("a")
        tree = build_tree([leaf])
        assert tree.root_hash == leaf
        assert tree.leaf_hashes == [leaf]

    def test_two_leaves(self):
        a, b = _b3("a"), _b3("b")
        tree = build_tree([a, b])
        # Leaves used in insertion order; compute expected root manually
        expected = blake3.blake3(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
        assert tree.root_hash == expected

    def test_four_leaves(self):
        leaves = [_b3(s) for s in ["alpha", "beta", "gamma", "delta"]]
        tree = build_tree(leaves)
        assert isinstance(tree.root_hash, str)
        assert len(tree.root_hash) == 64

    def test_order_matters(self):
        """Different insertion orders should produce different roots."""
        a, b, c = _b3("x"), _b3("y"), _b3("z")
        tree1 = build_tree([a, b, c])
        tree2 = build_tree([c, b, a])
        assert tree1.root_hash != tree2.root_hash

    def test_same_order_is_deterministic(self):
        """Same insertion order always produces the same root."""
        leaves = [_b3(s) for s in ["x", "y", "z"]]
        tree1 = build_tree(leaves)
        tree2 = build_tree(list(leaves))
        assert tree1.root_hash == tree2.root_hash

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_tree([])

    def test_odd_number_of_leaves_ct_promotion(self):
        """Lone node at any level must be promoted without rehashing."""
        leaves = [_b3(s) for s in ["a", "b", "c"]]
        tree = build_tree(leaves)
        assert len(tree.root_hash) == 64


class TestGenerateProof:
    def test_proof_for_each_leaf(self):
        leaves = [_b3(s) for s in ["apple", "banana", "cherry", "date"]]
        tree = build_tree(leaves)
        for leaf in leaves:
            proof = generate_proof(leaf, tree)
            assert proof.leaf_hash == leaf
            assert proof.root_hash == tree.root_hash

    def test_missing_leaf_raises(self):
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        with pytest.raises(ValueError, match="not found"):
            generate_proof(_b3("c"), tree)


class TestVerifyProof:
    def test_valid_proof_returns_true(self):
        leaves = [_b3(s) for s in ["p", "q", "r", "s"]]
        tree = build_tree(leaves)
        for leaf in leaves:
            proof = generate_proof(leaf, tree)
            assert verify_proof(leaf, proof, tree.root_hash) is True

    def test_tampered_leaf_fails(self):
        leaves = [_b3(s) for s in ["m", "n", "o"]]
        tree = build_tree(leaves)
        proof = generate_proof(leaves[0], tree)
        # Replace the leaf with a different hash
        tampered_leaf = _b3("tampered")
        assert verify_proof(tampered_leaf, proof, tree.root_hash) is False

    def test_tampered_sibling_fails(self):
        leaves = [_b3(s) for s in ["1", "2", "3", "4"]]
        tree = build_tree(leaves)
        leaf = leaves[0]
        proof = generate_proof(leaf, tree)
        # Tamper with the first sibling hash
        bad_siblings = [(_b3("evil"), proof.siblings[0][1])] + list(proof.siblings[1:])
        bad_proof = MerkleProof(
            leaf_hash=leaf, root_hash=proof.root_hash, siblings=bad_siblings
        )
        assert verify_proof(leaf, bad_proof, tree.root_hash) is False

    def test_wrong_root_fails(self):
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(leaves[0], tree)
        wrong_root = _b3("wrong_root")
        assert verify_proof(leaves[0], proof, wrong_root) is False

    def test_single_leaf_proof(self):
        """Single-leaf tree has no siblings; root equals the leaf."""
        leaf = _b3("solo")
        tree = build_tree([leaf])
        proof = generate_proof(leaf, tree)
        assert proof.siblings == []
        assert verify_proof(leaf, proof, tree.root_hash) is True
