"""Tests for RustSparseMerkleTree.incremental_update."""

import pytest

from protocol.ssmf import (
    EMPTY_HASHES,
    ExistenceProof,
    PurePythonSparseMerkleTree,
    SparseMerkleTree,
    verify_proof,
)


# Try to import the Rust class directly for staticmethod access.
try:
    from olympus_core import RustSparseMerkleTree

    HAS_RUST = True
except ImportError:
    HAS_RUST = False

pytestmark = pytest.mark.skipif(not HAS_RUST, reason="Rust extension not built")


class TestIncrementalUpdate:
    def test_single_insert_matches_full_tree(self):
        """Incremental update on empty tree produces same root as full tree."""
        key = b"\x01" * 32
        val = b"\x02" * 32

        # Full tree approach
        tree = SparseMerkleTree()
        tree.update(key, val, "docling@2.3.1", "v1")
        expected_root = tree.get_root()

        # Incremental approach
        empty_siblings = EMPTY_HASHES[:256]
        new_root, proof_sibs, deltas = RustSparseMerkleTree.incremental_update(
            key, val, empty_siblings
        )
        assert new_root == expected_root

    def test_second_insert_matches_full_tree(self):
        """Incremental update with real siblings matches full-tree result."""
        ka, va = b"\x01" * 32, b"\xaa" * 32
        kb, vb = b"\x02" * 32, b"\xbb" * 32

        # Build tree with A, collect siblings for B
        # Use pure Python implementation to access internal methods
        tree = PurePythonSparseMerkleTree()
        tree.update(ka, va, "docling@2.3.1", "v1")
        # Siblings for B from the tree with only A
        siblings_b = tree._collect_siblings(tree._key_to_path(kb))

        # Now insert B into full tree
        tree.update(kb, vb, "docling@2.3.1", "v1")
        expected_root = tree.get_root()

        # Incremental insert of B using A's siblings
        new_root, _, _ = RustSparseMerkleTree.incremental_update(kb, vb, siblings_b)
        assert new_root == expected_root

    def test_proof_from_incremental_verifies(self):
        """ExistenceProof built from incremental output passes verification."""
        key = b"\x01" * 32
        val = b"\x02" * 32
        empty_siblings = EMPTY_HASHES[:256]

        new_root, proof_sibs, _ = RustSparseMerkleTree.incremental_update(key, val, empty_siblings)
        proof = ExistenceProof(
            key=key,
            value_hash=val,
            siblings=list(proof_sibs),
            root_hash=new_root,
        )
        assert verify_proof(proof)

    def test_delta_count_is_256(self):
        empty_siblings = EMPTY_HASHES[:256]
        _, _, deltas = RustSparseMerkleTree.incremental_update(
            b"\x01" * 32, b"\x02" * 32, empty_siblings
        )
        assert len(deltas) == 256

    def test_delta_root_entry(self):
        empty_siblings = EMPTY_HASHES[:256]
        new_root, _, deltas = RustSparseMerkleTree.incremental_update(
            b"\x01" * 32, b"\x02" * 32, empty_siblings
        )
        # Find the root delta (db_level=0)
        root_deltas = [(lvl, idx, h) for lvl, idx, h in deltas if lvl == 0]
        assert len(root_deltas) == 1
        assert root_deltas[0][1] == b""  # empty packed index
        assert root_deltas[0][2] == new_root

    def test_bad_key_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            RustSparseMerkleTree.incremental_update(b"\x01" * 31, b"\x02" * 32, EMPTY_HASHES[:256])

    def test_bad_sibling_count_raises(self):
        with pytest.raises(ValueError, match="256"):
            RustSparseMerkleTree.incremental_update(b"\x01" * 32, b"\x02" * 32, EMPTY_HASHES[:100])

    def test_bad_sibling_hash_length_raises(self):
        """Passing a sibling with wrong length raises ValueError."""
        bad_siblings = list(EMPTY_HASHES[:256])
        bad_siblings[0] = b"\x01" * 31  # 31 bytes instead of 32
        with pytest.raises(ValueError, match="32 bytes"):
            RustSparseMerkleTree.incremental_update(b"\x01" * 32, b"\x02" * 32, bad_siblings)

    def test_ten_sequential_inserts(self):
        """Incrementally insert 10 keys, verify each root matches full tree."""
        # Use pure Python implementation for both trees:
        # - tree: for verification via .get_root()
        # - siblings_source: for accessing internal ._collect_siblings()
        tree = PurePythonSparseMerkleTree()
        siblings_source = PurePythonSparseMerkleTree()

        for i in range(10):
            key = bytes([i] + [0] * 31)
            val = bytes([i + 100] + [0] * 31)

            # Get siblings from current state
            sibs = siblings_source._collect_siblings(siblings_source._key_to_path(key))

            # Incremental
            new_root, _, _ = RustSparseMerkleTree.incremental_update(key, val, sibs)

            # Full tree
            tree.update(key, val, "docling@2.3.1", "v1")
            siblings_source.update(key, val)

            assert new_root == tree.get_root(), f"Mismatch at insert {i}"
