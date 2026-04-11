"""
Tests for Merkle tree service.

Validates tree construction, inclusion proof generation, and proof verification
using known inputs.
"""

from __future__ import annotations

import warnings

import blake3
import pytest

from api.services.merkle import (
    _INTERNAL_PREFIX,
    _LEAF_PREFIX,
    _SEP,
    MerkleProof,
    _blake3_leaf,
    _blake3_pair,
    _expected_proof_depth,
    build_tree,
    generate_proof,
    verify_proof,
)
from protocol.hashes import blake3_hash


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
        # Leaves are first domain-separated, then paired as an internal node:
        # BLAKE3(OLY:NODE:V1 || | || leaf_hash(a) || | || leaf_hash(b))
        leaf_a = _blake3_leaf(bytes.fromhex(a))
        leaf_b = _blake3_leaf(bytes.fromhex(b))
        expected = blake3_hash(
            [_INTERNAL_PREFIX, _SEP, bytes.fromhex(leaf_a), _SEP, bytes.fromhex(leaf_b)]
        ).hex()
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

    def test_lone_node_is_promoted_not_rehashed(self):
        """Single-leaf tree root should be the domain-separated leaf hash (CT-style promotion)."""
        leaf = _b3("only_leaf")
        tree = build_tree([leaf])
        # With CT-style promotion, single leaf root = domain-separated leaf hash
        expected = _blake3_leaf(bytes.fromhex(leaf))
        assert tree.root_hash == expected
        # Root differs from the original (un-hashed) leaf value
        assert tree.root_hash != leaf

    # -------------------------------------------------------------------
    # Finding #10 — domain separation tests
    # -------------------------------------------------------------------
    def test_leaf_and_internal_prefixes_are_distinct(self):
        assert _LEAF_PREFIX != _INTERNAL_PREFIX

    def test_leaf_hash_differs_from_internal_hash_of_same_bytes(self):
        data = b"some_leaf_data"
        leaf = _blake3_leaf(data)
        # Construct an "internal" hash using the same leaf as both children
        pseudo_internal = _blake3_pair(leaf, leaf)
        assert leaf != pseudo_internal, "Leaf and internal node hashes must not collide"

    def test_crafted_leaf_cannot_collide_with_internal_node(self):
        """No leaf hash should equal any internal node hash in a tree."""
        leaves_raw = [b"a", b"b", b"c", b"d"]
        leaf_hashes = [_blake3_leaf(item_list) for item_list in leaves_raw]
        tree = build_tree(leaf_hashes)

        # Collect all internal node hashes from all levels above the leaves
        internal_nodes: set[str] = set()
        for level in tree.levels[1:]:
            internal_nodes.update(level)

        assert not (set(leaf_hashes) & internal_nodes), (
            "Collision between leaf and internal node — domain separation failed"
        )

    def test_proof_verification_fails_with_wrong_prefix(self):
        """Old (no-prefix) proof must not verify against new (prefixed) root."""
        leaf_data = b"test_document"
        # Old scheme: no prefix
        old_leaf_hash = blake3.blake3(leaf_data).hexdigest()
        # New scheme: OLY:LEAF:V1 prefix
        new_leaf_hash = _blake3_leaf(leaf_data)

        new_tree = build_tree([new_leaf_hash])
        old_tree = build_tree([old_leaf_hash])
        old_proof = generate_proof(old_leaf_hash, old_tree)

        assert not verify_proof(old_leaf_hash, old_proof, new_tree.root_hash), (
            "Old-scheme proof must not verify against new-scheme root"
        )


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
        tampered_leaf = _b3("tampered")
        assert verify_proof(tampered_leaf, proof, tree.root_hash) is False

    def test_tampered_sibling_fails(self):
        leaves = [_b3(s) for s in ["1", "2", "3", "4"]]
        tree = build_tree(leaves)
        leaf = tree.leaf_hashes[0]
        proof = generate_proof(leaf, tree)
        bad_siblings = [(_b3("evil"), proof.siblings[0][1])] + list(proof.siblings[1:])
        bad_proof = MerkleProof(leaf_hash=leaf, root_hash=proof.root_hash, siblings=bad_siblings)
        assert verify_proof(leaf, bad_proof, tree.root_hash) is False

    def test_tampered_sibling_fails_preserve_order(self):
        """Tamper detection must also work for preserve_order=True trees."""
        leaves = [_b3(s) for s in ["1", "2", "3", "4"]]
        tree = build_tree(leaves, preserve_order=True)
        leaf = tree.leaf_hashes[0]
        proof = generate_proof(leaf, tree)
        bad_siblings = [(_b3("evil"), proof.siblings[0][1])] + list(proof.siblings[1:])
        bad_proof = MerkleProof(leaf_hash=leaf, root_hash=proof.root_hash, siblings=bad_siblings)
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

    # -------------------------------------------------------------------
    # Finding #9 — proof depth / direction validation tests
    # -------------------------------------------------------------------
    def test_proof_includes_tree_size(self):
        """generate_proof must populate tree_size on the proof."""
        leaves = [_b3(s) for s in ["a", "b", "c"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        assert proof.tree_size == 3

    def test_invalid_direction_raises(self):
        """Sibling direction must be exactly 'left' or 'right'."""
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=[(proof.siblings[0][0], "up")],
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Invalid sibling direction"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    def test_boolean_direction_raises(self):
        """Boolean direction values must be rejected."""
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=[(proof.siblings[0][0], True)],  # type: ignore[list-item]
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Invalid sibling direction"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    def test_too_many_siblings_rejected(self):
        """Proof with more siblings than expected depth must be rejected."""
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        # Add an extra sibling
        extra_siblings = list(proof.siblings) + [(_b3("extra"), "right")]
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=extra_siblings,
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Proof depth mismatch"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    def test_too_few_siblings_rejected(self):
        """Proof with fewer siblings than expected depth must be rejected."""
        leaves = [_b3(s) for s in ["a", "b", "c", "d"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        # Remove a sibling
        fewer_siblings = list(proof.siblings)[:-1]
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=fewer_siblings,
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Proof depth mismatch"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    def test_legacy_tree_size_zero_skips_depth_check(self):
        """tree_size=0 (legacy) skips depth validation."""
        leaves = [_b3(s) for s in ["a", "b"]]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        # Override tree_size to 0 (legacy)
        legacy_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=proof.siblings,
            tree_size=0,
        )
        assert verify_proof(legacy_proof.leaf_hash, legacy_proof, tree.root_hash) is True

    @pytest.mark.parametrize(
        "n,expected_depth",
        [
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (8, 3),
            (9, 4),
            (16, 4),
        ],
    )
    def test_expected_proof_depth(self, n: int, expected_depth: int):
        """_expected_proof_depth matches the actual generated proof depth."""
        assert _expected_proof_depth(n) == expected_depth
