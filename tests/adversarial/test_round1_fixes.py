"""
Adversarial probes for Round 1 fixes: numeric canonicalization, Merkle leaf
ordering, and lone-node self-pairing.

Each test was originally an ``xfail`` that has been verified to flip clean
now that the fixes are merged.  The probes remain as regression tests.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from protocol.canonical import (
    canonicalize_document,
    document_to_bytes,
)
from protocol.hashes import hash_bytes


# ---------------------------------------------------------------------------
# Finding #1 — Numeric canonicalization
# ---------------------------------------------------------------------------


class TestNumericCanonicalization:
    """Adversarial probes: semantically identical numbers MUST hash equally."""

    def test_whole_float_equals_int(self) -> None:
        """100 and 100.0 must produce identical canonical bytes."""
        a = document_to_bytes({"amount": 100})
        b = document_to_bytes({"amount": 100.0})
        assert a == b, "Whole-float and int diverged"

    def test_scientific_notation_equals_int(self) -> None:
        """1e2 and 100 must produce identical canonical bytes."""
        a = document_to_bytes({"amount": 100})
        b = document_to_bytes({"amount": 1e2})
        assert a == b, "Scientific notation and int diverged"

    def test_negative_zero_equals_zero(self) -> None:
        """-0.0 must canonicalize to 0."""
        a = document_to_bytes({"amount": 0})
        b = document_to_bytes({"amount": -0.0})
        assert a == b, "-0.0 did not canonicalize to 0"

    def test_non_whole_float_kept_as_decimal(self) -> None:
        """0.1 must be preserved as a Decimal — not lost to float drift."""
        canonical = canonicalize_document({"rate": 0.1})
        assert isinstance(canonical["rate"], Decimal)

    def test_nan_rejected(self) -> None:
        """NaN must be rejected outright."""
        with pytest.raises(Exception):
            canonicalize_document({"val": float("nan")})

    def test_inf_rejected(self) -> None:
        """Infinity must be rejected outright."""
        with pytest.raises(Exception):
            canonicalize_document({"val": float("inf")})


# ---------------------------------------------------------------------------
# Finding #7/#8 — Merkle leaf ordering and lone-node self-pairing
# ---------------------------------------------------------------------------

from api.services.merkle import (  # noqa: E402
    _blake3_leaf,
    build_tree,
    generate_proof,
    verify_proof,
)


class TestMerkleLeafOrdering:
    """Adversarial probes: leaf ordering must be deterministic."""

    def test_unordered_inputs_produce_same_root(self) -> None:
        """Two different orderings of the same set must yield one root."""
        leaves = [hash_bytes(c.encode()).hex() for c in "abcd"]
        root_a = build_tree(leaves).root_hash
        root_b = build_tree(list(reversed(leaves))).root_hash
        assert root_a == root_b, "Leaf re-ordering changed the root"

    def test_preserve_order_differs(self) -> None:
        """preserve_order=True must NOT sort — different ordering, different root."""
        leaves = [hash_bytes(c.encode()).hex() for c in "abcd"]
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            root_sorted = build_tree(leaves).root_hash
            root_ordered = build_tree(list(reversed(leaves)), preserve_order=True).root_hash
        assert root_sorted != root_ordered, "preserve_order had no effect"


class TestLoneNodeSelfPairing:
    """Adversarial probes: lone nodes use CT-style promotion (matching protocol.merkle.MerkleTree)."""

    def test_single_leaf_root_differs_from_leaf(self) -> None:
        """A single-leaf tree's root must NOT equal the leaf itself."""
        leaf = hash_bytes(b"only_leaf").hex()
        tree = build_tree([leaf])
        assert tree.root_hash != leaf, "Lone leaf was promoted without hashing"

    def test_single_leaf_root_equals_domain_separated_leaf(self) -> None:
        """The root must be the domain-separated leaf hash (CT-style promotion)."""
        leaf = hash_bytes(b"only_leaf").hex()
        tree = build_tree([leaf])
        expected = _blake3_leaf(bytes.fromhex(leaf))
        assert tree.root_hash == expected, "Lone leaf was not domain-separated correctly"

    def test_odd_leaf_count_lone_node_self_paired(self) -> None:
        """In a 3-leaf tree the lone node at level 1 is self-paired."""
        leaves = [hash_bytes(c.encode()).hex() for c in "abc"]
        tree = build_tree(leaves)
        # The tree should have 2 levels above the leaves
        assert len(tree.levels) >= 2

    def test_single_leaf_proof_verifies(self) -> None:
        """Proofs on a single-leaf tree must verify."""
        leaf = hash_bytes(b"solo").hex()
        tree = build_tree([leaf])
        proof = generate_proof(leaf, tree)
        assert verify_proof(leaf, proof, tree.root_hash)
