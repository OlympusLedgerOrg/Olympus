"""
Tests for Merkle tree service.

Validates tree construction, inclusion proof generation, and proof verification
using known inputs.
"""

from __future__ import annotations

import warnings

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
        assert tree.leaf_hashes == [leaf]
        assert len(tree.root_hash) == 64

    def test_two_leaves_preserve_order(self):
        a, b = _b3("a"), _b3("b")
        tree = build_tree([a, b], preserve_order=True)
        # Leaves used in insertion order; compute expected root manually
        expected = blake3.blake3(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
        assert tree.root_hash == expected

    def test_four_leaves(self):
        leaves = [_b3(s) for s in ["alpha", "beta", "gamma", "delta"]]
        tree = build_tree(leaves)
        assert isinstance(tree.root_hash, str)
        assert len(tree.root_hash) == 64

    def test_same_order_is_deterministic(self):
        """Same insertion order always produces the same root."""
        leaves1 = [_b3(s) for s in ["x", "y", "z"]]
        leaves2 = [_b3(s) for s in ["x", "y", "z"]]
        tree1 = build_tree(leaves1)
        tree2 = build_tree(leaves2)
        assert tree1.root_hash == tree2.root_hash

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_tree([])

    def test_odd_number_of_leaves(self):
        """Odd leaf count must produce a valid 64-char hex root."""
        leaves = [_b3(s) for s in ["a", "b", "c"]]
        tree = build_tree(leaves)
        assert len(tree.root_hash) == 64

    # -------------------------------------------------------------------
    # Finding #7 — canonical sort tests
    # -------------------------------------------------------------------
    def test_merkle_root_is_order_independent(self):
        """Different input orderings must produce the same root (default sort)."""
        leaves = [_b3(s) for s in ["leaf_a", "leaf_b", "leaf_c"]]
        root_1 = build_tree(leaves).root_hash
        root_2 = build_tree(list(reversed(leaves))).root_hash
        assert root_1 == root_2

    def test_preserve_order_flag_bypasses_sort(self):
        """With preserve_order=True, different ordering → different root."""
        leaves = [_b3(s) for s in ["leaf_z", "leaf_a"]]
        root_sorted = build_tree(leaves).root_hash
        root_ordered = build_tree(leaves, preserve_order=True).root_hash
        assert root_sorted != root_ordered

    def test_preserve_order_emits_warning(self):
        """preserve_order=True must emit a UserWarning."""
        leaves = [_b3("x")]
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_tree(leaves, preserve_order=True)
            assert len(w) == 1
            assert "preserve_order" in str(w[0].message)

    # -------------------------------------------------------------------
    # Finding #8 — lone-node self-pair tests
    # -------------------------------------------------------------------
    def test_odd_and_padded_even_differ_from_unpadded(self):
        """Three leaves must produce a different root than two of them."""
        leaves_3 = [_b3(s) for s in ["a", "b", "c"]]
        leaves_2 = [_b3(s) for s in ["a", "b"]]
        assert build_tree(leaves_3).root_hash != build_tree(leaves_2).root_hash

    def test_lone_node_is_rehashed_not_promoted(self):
        """Single-leaf tree root should be H(H(leaf) || H(leaf)), not H(leaf)."""
        leaf = _b3("only_leaf")
        tree = build_tree([leaf])
        # The root must differ from the raw leaf hash because the lone node
        # is self-paired: root = BLAKE3(leaf || leaf).
        assert tree.root_hash != leaf
        expected = blake3.blake3(bytes.fromhex(leaf) + bytes.fromhex(leaf)).hexdigest()
        assert tree.root_hash == expected


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
        # Use leaf from sorted order (which is what the tree uses)
        leaf = tree.leaf_hashes[0]
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
        """Single-leaf tree: proof should verify correctly."""
        leaf = _b3("solo")
        tree = build_tree([leaf])
        proof = generate_proof(leaf, tree)
        assert verify_proof(leaf, proof, tree.root_hash) is True
