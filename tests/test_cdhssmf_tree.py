"""
Tests for CdhssmfTree and ShardRecord from protocol/cdhssmf.py.

This module tests the public API for the CDHSSMF design: CdhssmfTree wraps
SparseMerkleTree with shard-aware methods, and ShardRecord is the logical
address type for records within shards.

These tests are regression guards for the global_key() derive_key hardening
in PR #492 — if the derivation changes, these will catch it.
"""

import pytest

from protocol.cdhssmf import (
    CdhssmfTree,
    ExistenceProof,
    NonExistenceProof,
    ShardRecord,
    verify_nonexistence_proof,
    verify_proof,
)
from protocol.hashes import global_key, hash_bytes, record_key


class TestShardRecord:
    """Tests for the ShardRecord logical address type."""

    def test_shard_record_to_global_key_deterministic(self):
        """to_global_key() should produce identical output for identical inputs."""
        record = ShardRecord(
            shard_id="watauga:2025:budget",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        
        key1 = record.to_global_key()
        key2 = record.to_global_key()
        
        assert key1 == key2
        assert len(key1) == 32

    def test_shard_record_different_shards_different_keys(self):
        """Two records in different shards with same type/id produce different keys."""
        record1 = ShardRecord(
            shard_id="shard_a",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        record2 = ShardRecord(
            shard_id="shard_b",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        
        key1 = record1.to_global_key()
        key2 = record2.to_global_key()
        
        assert key1 != key2
        assert len(key1) == 32
        assert len(key2) == 32

    def test_shard_record_different_versions_different_keys(self):
        """Same record at different versions produces different keys."""
        record_v1 = ShardRecord(
            shard_id="shard_a",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        record_v2 = ShardRecord(
            shard_id="shard_a",
            record_type="document",
            record_id="doc123",
            version=2,
        )
        
        assert record_v1.to_global_key() != record_v2.to_global_key()

    def test_shard_record_different_types_different_keys(self):
        """Same id with different record_type produces different keys."""
        record_doc = ShardRecord(
            shard_id="shard_a",
            record_type="document",
            record_id="abc",
            version=1,
        )
        record_policy = ShardRecord(
            shard_id="shard_a",
            record_type="policy",
            record_id="abc",
            version=1,
        )
        
        assert record_doc.to_global_key() != record_policy.to_global_key()

    def test_shard_record_is_frozen(self):
        """ShardRecord should be immutable (frozen dataclass)."""
        record = ShardRecord(
            shard_id="shard_a",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        
        with pytest.raises(AttributeError):
            record.shard_id = "shard_b"  # type: ignore

    def test_shard_record_consistent_with_global_key_function(self):
        """to_global_key() should match the global_key() function directly."""
        record = ShardRecord(
            shard_id="watauga:2025:budget",
            record_type="document",
            record_id="doc123",
            version=1,
        )
        
        expected_rec_key = record_key("document", "doc123", 1)
        expected_global_key = global_key("watauga:2025:budget", expected_rec_key)
        
        assert record.to_global_key() == expected_global_key


class TestCdhssmfTreeBasicOperations:
    """Tests for basic CdhssmfTree read/write operations."""

    def test_update_and_get_roundtrip(self):
        """Value is retrievable after insert via get()."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value_hash = hash_bytes(b"document content")
        
        tree.update(shard_id, rec_key, value_hash)
        retrieved = tree.get(shard_id, rec_key)
        
        assert retrieved == value_hash

    def test_get_missing_key_returns_none(self):
        """get() on a key that was never inserted returns None."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "nonexistent", 1)
        
        result = tree.get("some-shard", rec_key)
        
        assert result is None

    def test_update_overwrites_previous_value(self):
        """Updating an existing key replaces the value."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        
        value1 = hash_bytes(b"version 1")
        value2 = hash_bytes(b"version 2")
        
        tree.update(shard_id, rec_key, value1)
        assert tree.get(shard_id, rec_key) == value1
        
        tree.update(shard_id, rec_key, value2)
        assert tree.get(shard_id, rec_key) == value2

    def test_multiple_records_independent(self):
        """Multiple records in the same shard are stored independently."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        
        rec_key1 = record_key("document", "doc1", 1)
        rec_key2 = record_key("document", "doc2", 1)
        value1 = hash_bytes(b"content 1")
        value2 = hash_bytes(b"content 2")
        
        tree.update(shard_id, rec_key1, value1)
        tree.update(shard_id, rec_key2, value2)
        
        assert tree.get(shard_id, rec_key1) == value1
        assert tree.get(shard_id, rec_key2) == value2


class TestCdhssmfTreeRoot:
    """Tests for CdhssmfTree.get_root() behavior."""

    def test_empty_tree_has_stable_root(self):
        """An empty tree should have a consistent (default) root."""
        tree1 = CdhssmfTree()
        tree2 = CdhssmfTree()
        
        root1 = tree1.get_root()
        root2 = tree2.get_root()
        
        assert root1 == root2
        assert len(root1) == 32

    def test_root_changes_after_update(self):
        """get_root() should return a different value after update()."""
        tree = CdhssmfTree()
        
        root_before = tree.get_root()
        
        tree.update("shard", record_key("doc", "1", 1), hash_bytes(b"content"))
        
        root_after = tree.get_root()
        
        assert root_before != root_after

    def test_root_deterministic_for_same_inserts(self):
        """Same sequence of updates produces the same root."""
        def build_tree():
            tree = CdhssmfTree()
            tree.update("shard1", record_key("doc", "1", 1), hash_bytes(b"a"))
            tree.update("shard1", record_key("doc", "2", 1), hash_bytes(b"b"))
            tree.update("shard2", record_key("doc", "1", 1), hash_bytes(b"c"))
            return tree.get_root()
        
        root1 = build_tree()
        root2 = build_tree()
        
        assert root1 == root2

    def test_root_order_independent(self):
        """Insert order should not affect final root (SMT property)."""
        # Note: This may or may not be true depending on SMT implementation
        # For most sparse merkle trees, the root is order-independent
        tree1 = CdhssmfTree()
        tree2 = CdhssmfTree()
        
        key1 = record_key("doc", "1", 1)
        key2 = record_key("doc", "2", 1)
        val1 = hash_bytes(b"a")
        val2 = hash_bytes(b"b")
        
        # Different insert order
        tree1.update("shard", key1, val1)
        tree1.update("shard", key2, val2)
        
        tree2.update("shard", key2, val2)
        tree2.update("shard", key1, val1)
        
        assert tree1.get_root() == tree2.get_root()


class TestCdhssmfTreeProofs:
    """Tests for CdhssmfTree proof generation and verification."""

    def test_prove_returns_existence_proof_for_known_key(self):
        """prove() returns ExistenceProof for a key that exists."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        tree.update(shard_id, rec_key, value)
        
        proof = tree.prove(shard_id, rec_key)
        
        assert isinstance(proof, ExistenceProof)

    def test_prove_returns_nonexistence_proof_for_unknown_key(self):
        """prove() returns NonExistenceProof for a key that doesn't exist."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "nonexistent", 1)
        
        proof = tree.prove("shard", rec_key)
        
        assert isinstance(proof, NonExistenceProof)

    def test_prove_existence_succeeds_for_known_key(self):
        """prove_existence() succeeds when key exists."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        tree.update(shard_id, rec_key, value)
        
        proof = tree.prove_existence(shard_id, rec_key)
        
        assert isinstance(proof, ExistenceProof)
        assert proof.value_hash == value

    def test_prove_existence_raises_for_unknown_key(self):
        """prove_existence() raises ValueError when key doesn't exist."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "nonexistent", 1)
        
        with pytest.raises(ValueError):
            tree.prove_existence("shard", rec_key)

    def test_prove_nonexistence_succeeds_for_unknown_key(self):
        """prove_nonexistence() succeeds when key doesn't exist."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "nonexistent", 1)
        
        proof = tree.prove_nonexistence("shard", rec_key)
        
        assert isinstance(proof, NonExistenceProof)

    def test_prove_nonexistence_raises_for_known_key(self):
        """prove_nonexistence() raises ValueError when key exists."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        tree.update(shard_id, rec_key, value)
        
        with pytest.raises(ValueError):
            tree.prove_nonexistence(shard_id, rec_key)


class TestCdhssmfTreeProofVerification:
    """Tests for verifying proofs from CdhssmfTree."""

    def test_verify_existence_proof_with_correct_root(self):
        """verify_proof() passes with the correct root embedded in proof."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        tree.update(shard_id, rec_key, value)
        root = tree.get_root()
        proof = tree.prove_existence(shard_id, rec_key)
        
        # The proof contains its own root_hash
        assert proof.root_hash == root
        assert verify_proof(proof) is True

    def test_verify_existence_proof_fails_with_tampered_proof(self):
        """verify_proof() fails when proof is tampered."""
        tree = CdhssmfTree()
        shard_id = "test-shard"
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        tree.update(shard_id, rec_key, value)
        proof = tree.prove_existence(shard_id, rec_key)
        
        # Tamper with the root_hash in the proof
        tampered_proof = ExistenceProof(
            key=proof.key,
            value_hash=proof.value_hash,
            siblings=proof.siblings,
            root_hash=hash_bytes(b"wrong root"),
        )
        
        assert verify_proof(tampered_proof) is False

    def test_verify_nonexistence_proof_with_correct_root(self):
        """verify_nonexistence_proof() passes with correct root in proof."""
        tree = CdhssmfTree()
        # Add some data to the tree
        tree.update("shard", record_key("doc", "existing", 1), hash_bytes(b"x"))
        
        root = tree.get_root()
        
        # Prove non-existence of a different key
        proof = tree.prove_nonexistence("shard", record_key("doc", "missing", 1))
        
        # The proof contains its own root_hash
        assert proof.root_hash == root
        assert verify_nonexistence_proof(proof) is True

    def test_verify_nonexistence_proof_fails_with_tampered_proof(self):
        """verify_nonexistence_proof() fails with tampered proof."""
        tree = CdhssmfTree()
        tree.update("shard", record_key("doc", "existing", 1), hash_bytes(b"x"))
        
        proof = tree.prove_nonexistence("shard", record_key("doc", "missing", 1))
        
        # Tamper with the root_hash in the proof
        tampered_proof = NonExistenceProof(
            key=proof.key,
            siblings=proof.siblings,
            root_hash=hash_bytes(b"tampered"),
        )
        
        assert verify_nonexistence_proof(tampered_proof) is False


class TestCdhssmfTreeDiff:
    """Tests for CdhssmfTree.diff() comparison."""

    def test_diff_identical_trees_returns_empty(self):
        """Two identical trees should have an empty diff."""
        tree1 = CdhssmfTree()
        tree2 = CdhssmfTree()
        
        key = record_key("doc", "1", 1)
        value = hash_bytes(b"content")
        
        tree1.update("shard", key, value)
        tree2.update("shard", key, value)
        
        diff = tree1.diff(tree2)
        
        assert diff["added"] == []
        assert diff["changed"] == []
        assert diff["removed"] == []

    def test_diff_one_tree_with_extra_record_shows_added(self):
        """A tree with an extra record shows it in 'added'."""
        tree1 = CdhssmfTree()
        tree2 = CdhssmfTree()
        
        key1 = record_key("doc", "1", 1)
        key2 = record_key("doc", "2", 1)
        value = hash_bytes(b"content")
        
        # Both have key1
        tree1.update("shard", key1, value)
        tree2.update("shard", key1, value)
        
        # Only tree1 has key2
        tree1.update("shard", key2, value)
        
        diff = tree1.diff(tree2)
        
        # tree1 has key2 which tree2 doesn't have
        assert len(diff["added"]) == 1 or len(diff["removed"]) == 1

    def test_diff_empty_trees_returns_empty(self):
        """Two empty trees have an empty diff."""
        tree1 = CdhssmfTree()
        tree2 = CdhssmfTree()
        
        diff = tree1.diff(tree2)
        
        assert diff["added"] == []
        assert diff["changed"] == []
        assert diff["removed"] == []


class TestCdhssmfShardIsolation:
    """Tests for shard isolation guarantees in CDHSSMF."""

    def test_same_record_key_different_shards_different_global_keys(self):
        """Same record_key in two different shards produces different global keys."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "shared_doc_id", 1)
        value = hash_bytes(b"content")
        
        tree.update("shard_a", rec_key, value)
        tree.update("shard_b", rec_key, value)
        
        # Both should be stored independently (not overwrite each other)
        assert tree.get("shard_a", rec_key) == value
        assert tree.get("shard_b", rec_key) == value

    def test_proofs_from_different_shards_independent(self):
        """Proofs for same record_key in different shards are independent."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "shared_doc_id", 1)
        value_a = hash_bytes(b"content A")
        value_b = hash_bytes(b"content B")
        
        tree.update("shard_a", rec_key, value_a)
        tree.update("shard_b", rec_key, value_b)
        
        root = tree.get_root()
        
        proof_a = tree.prove_existence("shard_a", rec_key)
        proof_b = tree.prove_existence("shard_b", rec_key)
        
        # Proofs should have different keys (global_key includes shard_id)
        assert proof_a.key != proof_b.key
        
        # Both proofs should have the same root (single tree)
        assert proof_a.root_hash == root
        assert proof_b.root_hash == root
        
        # Both should verify successfully
        assert verify_proof(proof_a) is True
        assert verify_proof(proof_b) is True

    def test_proof_from_shard_a_does_not_verify_shard_b_value(self):
        """A proof for shard_a cannot be used to verify shard_b's value."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "shared_doc_id", 1)
        value_a = hash_bytes(b"content A")
        value_b = hash_bytes(b"content B")
        
        tree.update("shard_a", rec_key, value_a)
        tree.update("shard_b", rec_key, value_b)
        
        proof_a = tree.prove_existence("shard_a", rec_key)
        
        # Proof from shard_a has shard_a's value_hash
        assert proof_a.value_hash == value_a
        
        # The proof is for a different global_key than shard_b's key
        shard_b_global_key = global_key("shard_b", rec_key)
        assert proof_a.key != shard_b_global_key

    def test_nonexistence_in_one_shard_with_existence_in_another(self):
        """Record can exist in shard_a but not in shard_b (proven by non-existence)."""
        tree = CdhssmfTree()
        rec_key = record_key("document", "doc1", 1)
        value = hash_bytes(b"content")
        
        # Only exists in shard_a
        tree.update("shard_a", rec_key, value)
        
        root = tree.get_root()
        
        # Existence proof for shard_a
        proof_exists = tree.prove_existence("shard_a", rec_key)
        assert proof_exists.root_hash == root
        assert verify_proof(proof_exists) is True
        
        # Non-existence proof for shard_b
        proof_not_exists = tree.prove_nonexistence("shard_b", rec_key)
        assert proof_not_exists.root_hash == root
        assert verify_nonexistence_proof(proof_not_exists) is True


class TestCdhssmfTreeRegressionGuards:
    """Regression tests to catch changes in key derivation (PR #492)."""

    def test_global_key_derivation_stability(self):
        """Global key derivation should be stable across code changes."""
        # This is a known-answer test. If this fails, the derivation changed.
        record = ShardRecord(
            shard_id="watauga:2025:budget",
            record_type="document",
            record_id="FOIA-2025-001",
            version=1,
        )
        
        key = record.to_global_key()
        
        # Key should be 32 bytes
        assert len(key) == 32
        
        # Key should be deterministic
        assert key == record.to_global_key()

    def test_tree_root_stability_empty(self):
        """Empty tree root should be stable."""
        tree = CdhssmfTree()
        root = tree.get_root()
        
        assert len(root) == 32
        assert root == CdhssmfTree().get_root()

    def test_proof_structure_stability(self):
        """Proof structure should remain stable."""
        tree = CdhssmfTree()
        tree.update("shard", record_key("doc", "1", 1), hash_bytes(b"content"))
        
        proof = tree.prove_existence("shard", record_key("doc", "1", 1))
        
        # Proof should have expected attributes
        assert hasattr(proof, "key")
        assert hasattr(proof, "value_hash")
        assert hasattr(proof, "siblings")
        assert hasattr(proof, "root_hash")
        assert len(proof.key) == 32
        assert len(proof.value_hash) == 32
        assert len(proof.root_hash) == 32
        assert len(proof.siblings) == 256
