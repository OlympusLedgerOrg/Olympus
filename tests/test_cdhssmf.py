"""
Tests for the CDHSSMF (Constant-Depth Hierarchical Sparse Sharded Merkle Forest).

These tests validate that collapsing the old two-tree design (per-shard SMT +
separate forest layer) into a single global SMT with shard-namespaced keys
preserves all required security properties while eliminating the two-tree
synchronisation footgun.
"""

import pytest

from protocol.cdhssmf import (
    CdhssmfTree,
    ExistenceProof,
    NonExistenceProof,
    ShardRecord,
    verify_nonexistence_proof,
    verify_proof,
    verify_unified_proof,
)
from protocol.hashes import blake3_hash, global_key, hash_bytes, record_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SHARD_A = "acme:2025:budget"
SHARD_B = "watauga:2025:contracts"
SHARD_C = "delta:2025:audit"


def _rk(record_id: str, version: int = 1) -> bytes:
    return record_key("document", record_id, version)


def _vh(content: str) -> bytes:
    return hash_bytes(content.encode())


# ---------------------------------------------------------------------------
# global_key derivation
# ---------------------------------------------------------------------------


def test_global_key_length():
    """global_key must return exactly 32 bytes."""
    gk = global_key(SHARD_A, _rk("doc1"))
    assert len(gk) == 32


def test_global_key_same_record_same_shard_is_deterministic():
    """Same (shard_id, record_key) must always yield the same global key."""
    rk = _rk("doc1")
    assert global_key(SHARD_A, rk) == global_key(SHARD_A, rk)


def test_global_key_different_shards_produce_different_keys():
    """Two shards with the same record key must map to different global keys."""
    rk = _rk("doc1")
    assert global_key(SHARD_A, rk) != global_key(SHARD_B, rk)


def test_global_key_different_records_same_shard_produce_different_keys():
    """Two different record keys in the same shard must yield different global keys."""
    assert global_key(SHARD_A, _rk("doc1")) != global_key(SHARD_A, _rk("doc2"))


def test_global_key_rejects_short_record_key():
    """global_key must reject record keys that are not 32 bytes."""
    with pytest.raises(ValueError, match="32 bytes"):
        global_key(SHARD_A, b"too_short")


# ---------------------------------------------------------------------------
# CdhssmfTree — basic operations
# ---------------------------------------------------------------------------


def test_empty_tree_has_valid_root():
    tree = CdhssmfTree()
    root = tree.get_root()
    assert len(root) == 32


def test_insert_and_retrieve_single_record():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    vh = _vh("hello world")

    tree.update(SHARD_A, rk, vh)

    assert tree.get(SHARD_A, rk) == vh


def test_get_missing_record_returns_none():
    tree = CdhssmfTree()
    assert tree.get(SHARD_A, _rk("nonexistent")) is None


def test_root_changes_after_insert():
    tree = CdhssmfTree()
    root_before = tree.get_root()
    tree.update(SHARD_A, _rk("doc1"), _vh("v1"))
    assert tree.get_root() != root_before


def test_multiple_shards_in_one_tree():
    """Records from different shards can coexist in the single global SMT."""
    tree = CdhssmfTree()

    rk = _rk("report")
    vh_a = _vh("shard-a content")
    vh_b = _vh("shard-b content")

    tree.update(SHARD_A, rk, vh_a)
    tree.update(SHARD_B, rk, vh_b)

    assert tree.get(SHARD_A, rk) == vh_a
    assert tree.get(SHARD_B, rk) == vh_b


def test_update_does_not_cross_contaminate_shards():
    """Updating a record in one shard must not change another shard's record."""
    tree = CdhssmfTree()
    rk = _rk("doc1")
    vh_a = _vh("shard-a v1")
    vh_b = _vh("shard-b v1")

    tree.update(SHARD_A, rk, vh_a)
    tree.update(SHARD_B, rk, vh_b)

    # Update shard A
    vh_a_v2 = _vh("shard-a v2")
    tree.update(SHARD_A, rk, vh_a_v2)

    assert tree.get(SHARD_A, rk) == vh_a_v2
    assert tree.get(SHARD_B, rk) == vh_b  # unchanged


# ---------------------------------------------------------------------------
# Determinism and ordering invariants
# ---------------------------------------------------------------------------


def test_root_is_deterministic():
    """Same sequence of updates must produce identical roots in two trees."""
    records = [(_rk(f"doc{i}"), _vh(f"val{i}")) for i in range(8)]

    tree1 = CdhssmfTree()
    tree2 = CdhssmfTree()

    for rk, vh in records:
        tree1.update(SHARD_A, rk, vh)
        tree2.update(SHARD_A, rk, vh)

    assert tree1.get_root() == tree2.get_root()


def test_root_independent_of_insert_order():
    """Insertion order must not affect the final root for identical key/value sets."""
    records = [(_rk(f"doc{i}"), _vh(f"val{i}")) for i in range(6)]

    tree_ordered = CdhssmfTree()
    for rk, vh in records:
        tree_ordered.update(SHARD_A, rk, vh)

    tree_shuffled = CdhssmfTree()
    for rk, vh in records[::-1]:  # reverse order
        tree_shuffled.update(SHARD_A, rk, vh)

    assert tree_ordered.get_root() == tree_shuffled.get_root()


def test_roots_of_disjoint_shards_are_consistent():
    """
    A tree with records across multiple shards must produce the same root
    regardless of which shard's records were inserted first.
    """
    rk = _rk("shared-doc")
    vh_a = _vh("shard-a")
    vh_b = _vh("shard-b")

    tree1 = CdhssmfTree()
    tree1.update(SHARD_A, rk, vh_a)
    tree1.update(SHARD_B, rk, vh_b)

    tree2 = CdhssmfTree()
    tree2.update(SHARD_B, rk, vh_b)
    tree2.update(SHARD_A, rk, vh_a)

    assert tree1.get_root() == tree2.get_root()


# ---------------------------------------------------------------------------
# Proof generation and verification
# ---------------------------------------------------------------------------


def test_prove_returns_existence_proof_for_known_key():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    vh = _vh("value")
    tree.update(SHARD_A, rk, vh)

    proof = tree.prove(SHARD_A, rk)

    assert isinstance(proof, ExistenceProof)
    assert proof.root_hash == tree.get_root()
    assert proof.value_hash == vh
    assert len(proof.siblings) == 256


def test_prove_returns_nonexistence_proof_for_missing_key():
    tree = CdhssmfTree()
    proof = tree.prove(SHARD_A, _rk("missing"))

    assert isinstance(proof, NonExistenceProof)
    assert proof.root_hash == tree.get_root()
    assert len(proof.siblings) == 256


def test_existence_proof_verifies():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("content"))

    proof = tree.prove_existence(SHARD_A, rk)
    assert verify_proof(proof) is True


def test_nonexistence_proof_verifies():
    tree = CdhssmfTree()
    tree.update(SHARD_A, _rk("other"), _vh("something"))

    proof = tree.prove_nonexistence(SHARD_A, _rk("absent"))
    assert verify_nonexistence_proof(proof) is True


def test_verify_unified_proof_existence():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("v1"))

    assert verify_unified_proof(tree.prove(SHARD_A, rk)) is True


def test_verify_unified_proof_nonexistence():
    tree = CdhssmfTree()
    assert verify_unified_proof(tree.prove(SHARD_A, _rk("nope"))) is True


def test_tampered_existence_proof_fails_verification():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("original"))

    proof = tree.prove_existence(SHARD_A, rk)
    tampered = ExistenceProof(
        key=proof.key,
        value_hash=_vh("tampered"),
        siblings=proof.siblings,
        root_hash=proof.root_hash,
    )
    assert verify_proof(tampered) is False


def test_prove_existence_raises_for_missing_key():
    tree = CdhssmfTree()
    with pytest.raises(ValueError, match="does not exist"):
        tree.prove_existence(SHARD_A, _rk("missing"))


def test_prove_nonexistence_raises_for_existing_key():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("exists"))

    with pytest.raises(ValueError, match="exists in tree"):
        tree.prove_nonexistence(SHARD_A, rk)


def test_proof_key_is_global_key_not_record_key():
    """The key embedded in a proof must be the global key, not the bare record key."""
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("v"))

    proof = tree.prove_existence(SHARD_A, rk)
    expected_gk = global_key(SHARD_A, rk)

    assert proof.key == expected_gk
    assert proof.key != rk  # bare record key is NOT embedded


def test_proof_size_is_constant():
    """CDHSSMF proofs must be fixed width (256 siblings × 32 bytes)."""
    tree = CdhssmfTree()
    for i in range(64):
        tree.update(SHARD_A, _rk(f"doc{i}"), _vh(f"v{i}"))

    proof = tree.prove_existence(SHARD_A, _rk("doc0"))
    total = (
        len(proof.key)
        + len(proof.value_hash)
        + sum(len(s) for s in proof.siblings)
        + len(proof.root_hash)
    )
    expected = 32 + 32 + 256 * 32 + 32
    assert total == expected


# ---------------------------------------------------------------------------
# Single-tree vs two-tree equivalence check
# ---------------------------------------------------------------------------


def test_same_record_different_shards_do_not_collide_in_global_tree():
    """
    If two shards contain a record with the same record_key but different
    values, both must be independently provable from the same global root.
    """
    tree = CdhssmfTree()
    rk = _rk("shared-report")
    vh_a = _vh("shard-a payload")
    vh_b = _vh("shard-b payload")

    tree.update(SHARD_A, rk, vh_a)
    tree.update(SHARD_B, rk, vh_b)

    proof_a = tree.prove_existence(SHARD_A, rk)
    proof_b = tree.prove_existence(SHARD_B, rk)

    # Both proofs must verify against the same root
    assert proof_a.root_hash == proof_b.root_hash == tree.get_root()
    assert verify_proof(proof_a) is True
    assert verify_proof(proof_b) is True

    # They must encode different values
    assert proof_a.value_hash == vh_a
    assert proof_b.value_hash == vh_b

    # And their keys must differ (namespace isolation)
    assert proof_a.key != proof_b.key


def test_adding_record_to_one_shard_changes_global_root():
    """Adding a record to any shard must update the single global root."""
    tree = CdhssmfTree()
    tree.update(SHARD_A, _rk("doc"), _vh("v"))
    root_before = tree.get_root()

    tree.update(SHARD_B, _rk("doc"), _vh("v"))  # different shard, same rec_key
    assert tree.get_root() != root_before


def test_three_shards_nonexistence_across_shards():
    """
    A non-existence proof for shard C must hold even when shards A and B are
    populated — all under the same global root.
    """
    tree = CdhssmfTree()
    rk = _rk("doc")
    tree.update(SHARD_A, rk, _vh("a"))
    tree.update(SHARD_B, rk, _vh("b"))

    proof_c = tree.prove_nonexistence(SHARD_C, rk)
    assert verify_nonexistence_proof(proof_c) is True
    assert proof_c.root_hash == tree.get_root()


# ---------------------------------------------------------------------------
# ShardRecord helper
# ---------------------------------------------------------------------------


def test_shard_record_derives_correct_global_key():
    sr = ShardRecord(
        shard_id=SHARD_A,
        record_type="document",
        record_id="doc1",
        version=1,
    )
    expected = global_key(SHARD_A, record_key("document", "doc1", 1))
    assert sr.to_global_key() == expected


def test_shard_record_different_versions_produce_different_keys():
    sr_v1 = ShardRecord(SHARD_A, "document", "doc1", version=1)
    sr_v2 = ShardRecord(SHARD_A, "document", "doc1", version=2)
    assert sr_v1.to_global_key() != sr_v2.to_global_key()


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def test_diff_detects_added_record():
    before = CdhssmfTree()
    after = CdhssmfTree()

    rk = _rk("doc1")
    after.update(SHARD_A, rk, _vh("new"))

    diff = before.diff(after)
    assert len(diff["added"]) == 1
    assert diff["changed"] == []
    assert diff["removed"] == []


def test_diff_detects_changed_record():
    before = CdhssmfTree()
    after = CdhssmfTree()

    rk = _rk("doc1")
    before.update(SHARD_A, rk, _vh("old"))
    after.update(SHARD_A, rk, _vh("new"))

    diff = before.diff(after)
    assert diff["added"] == []
    assert len(diff["changed"]) == 1
    assert diff["removed"] == []


def test_diff_is_empty_for_identical_trees():
    tree = CdhssmfTree()
    rk = _rk("doc1")
    tree.update(SHARD_A, rk, _vh("v"))

    diff = tree.diff(tree)
    assert diff == {"added": [], "changed": [], "removed": []}
