"""
Adversarial probes for Round 2 fixes: Unicode homoglyph scrub (Finding #3),
idempotency gate (Finding #5), and domain separation (Finding #10).

Each test was originally an ``xfail`` that has been verified to flip clean
now that the fixes are merged.  The probes remain as regression tests.
"""

from __future__ import annotations

import pytest

from protocol.canonical import (
    _scrub_homoglyphs,
    canonicalize_document,
    document_to_bytes,
)
from protocol.hashes import hash_bytes


# ---------------------------------------------------------------------------
# Finding #3 — Unicode homoglyph scrub
# ---------------------------------------------------------------------------


class TestHomoglyphScrub:
    """Adversarial probes: visually identical Unicode must hash identically."""

    @pytest.mark.parametrize(
        "variant,expected",
        [
            ("US\uff24", "USD"),  # fullwidth D
            ("\U0001d414\U0001d412\U0001d403", "USD"),  # mathematical bold
            ("\uff35\uff33\uff24", "USD"),  # all fullwidth
            ("USD", "USD"),  # already clean
        ],
    )
    def test_scrub_normalizes_to_ascii(self, variant: str, expected: str) -> None:
        assert _scrub_homoglyphs(variant) == expected

    def test_homoglyph_variants_produce_identical_bytes(self) -> None:
        base = {"invoice_id": "INV-8842", "amount": 100}
        variants = [
            {**base, "currency": "USD"},
            {**base, "currency": "US\uff24"},  # fullwidth D
            {**base, "currency": "\U0001d414\U0001d412\U0001d403"},  # math bold
            {**base, "currency": "\uff35\uff33\uff24"},  # all fullwidth
        ]
        hashes = [document_to_bytes(v) for v in variants]
        assert len(set(hashes)) == 1, "Homoglyph variants produced divergent bytes"

    def test_non_ascii_legitimate_content_survives(self) -> None:
        """Arabic, CJK, accented Latin must not be destroyed."""
        assert (
            _scrub_homoglyphs("\u0645\u0631\u062d\u0628\u0627") == "\u0645\u0631\u062d\u0628\u0627"
        )  # مرحبا
        assert _scrub_homoglyphs("\u65e5\u672c\u8a9e") == "\u65e5\u672c\u8a9e"  # 日本語
        assert _scrub_homoglyphs("caf\u00e9") == "caf\u00e9"  # café

    def test_scrub_opt_out_preserves_fullwidth(self) -> None:
        doc = {"currency": "\uff35\uff33\uff24"}
        bytes_on = document_to_bytes(doc, scrub_homoglyphs=True)
        bytes_off = document_to_bytes(doc, scrub_homoglyphs=False)
        assert bytes_on != bytes_off, "Opt-out flag had no effect"


# ---------------------------------------------------------------------------
# Finding #5 — Idempotency gate
# ---------------------------------------------------------------------------


class TestIdempotencySemanticVariants:
    """Adversarial probe: numeric variants must dedup to the same hash."""

    def test_integer_and_float_produce_same_content_hash(self) -> None:
        """100 and 100.0 must produce the same content_hash after canonical_v2."""
        a = document_to_bytes(
            canonicalize_document({"invoice_id": "INV-0003", "amount": 100, "currency": "USD"})
        )
        b = document_to_bytes(
            canonicalize_document({"invoice_id": "INV-0003", "amount": 100.0, "currency": "USD"})
        )
        assert hash_bytes(a).hex() == hash_bytes(b).hex(), (
            "Numeric fix must be applied before idempotency gate is meaningful"
        )


# ---------------------------------------------------------------------------
# Finding #10 — Domain separation
# ---------------------------------------------------------------------------

from api.services.merkle import (  # noqa: E402
    _INTERNAL_PREFIX,
    _LEAF_PREFIX,
    _blake3_leaf,
    _blake3_pair,
    build_tree,
    generate_proof,
    verify_proof,
)


class TestDomainSeparation:
    """Adversarial probes: leaf and internal node hashes must be distinct."""

    def test_leaf_and_internal_prefixes_are_distinct(self) -> None:
        assert _LEAF_PREFIX != _INTERNAL_PREFIX

    def test_leaf_hash_differs_from_internal_hash_of_same_bytes(self) -> None:
        data = b"some_leaf_data"
        leaf = _blake3_leaf(data)
        pseudo_internal = _blake3_pair(leaf, leaf)
        assert leaf != pseudo_internal, "Leaf and internal node hashes must not collide"

    def test_crafted_leaf_cannot_collide_with_internal_node(self) -> None:
        """Domain separation: no leaf hash should equal any internal node hash."""
        leaves_raw = [b"a", b"b", b"c", b"d"]
        leaf_hashes = [_blake3_leaf(item_list) for item_list in leaves_raw]
        tree = build_tree(leaf_hashes)

        # Collect all internal node hashes from tree levels
        internal_nodes: set[str] = set()
        for level in tree.levels[1:]:  # skip leaf level
            internal_nodes.update(level)

        assert not (set(leaf_hashes) & internal_nodes), (
            "Collision between leaf and internal node — domain separation failed"
        )

    def test_old_scheme_proof_fails_against_new_root(self) -> None:
        """A proof built without domain separation must not verify against a prefixed root."""
        import blake3 as b3

        leaf_data = b"test_document"
        old_leaf_hash = b3.blake3(leaf_data).hexdigest()  # no prefix
        new_leaf_hash = _blake3_leaf(leaf_data)  # 0x00 prefix

        new_tree = build_tree([new_leaf_hash])
        old_tree = build_tree([old_leaf_hash])
        old_proof = generate_proof(old_leaf_hash, old_tree)

        # Old proof must NOT verify against new root
        assert not verify_proof(old_leaf_hash, old_proof, new_tree.root_hash), (
            "Old-scheme proof must not verify against new-scheme root"
        )


# ---------------------------------------------------------------------------
# Finding #9 — Proof length validation
# ---------------------------------------------------------------------------

from api.services.merkle import (  # noqa: E402
    MerkleProof,
    _expected_proof_depth,
)


class TestProofLengthValidation:
    """Adversarial probes: verifier must reject structurally invalid proofs."""

    def test_invalid_direction_rejected(self) -> None:
        """Direction must be 'left' or 'right' — not a boolean."""
        leaves = [hash_bytes(c.encode()).hex() for c in "ab"]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=[(proof.siblings[0][0], "up")],  # type: ignore[list-item]
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Invalid sibling direction"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    def test_extra_siblings_rejected(self) -> None:
        """Proof with more siblings than log2(tree_size) must be rejected."""
        leaves = [hash_bytes(c.encode()).hex() for c in "ab"]
        tree = build_tree(leaves)
        proof = generate_proof(tree.leaf_hashes[0], tree)
        extra = list(proof.siblings) + [(hash_bytes(b"fake").hex(), "right")]
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            root_hash=proof.root_hash,
            siblings=extra,
            tree_size=proof.tree_size,
        )
        with pytest.raises(ValueError, match="Proof depth mismatch"):
            verify_proof(bad_proof.leaf_hash, bad_proof, tree.root_hash)

    @pytest.mark.parametrize("n,expected", [(1, 1), (2, 1), (3, 2), (4, 2), (8, 3)])
    def test_expected_depth(self, n: int, expected: int) -> None:
        assert _expected_proof_depth(n) == expected
