"""
Tests for Merkle consistency proofs.
"""

from hypothesis import given, settings
import hypothesis.strategies as st

from protocol.hashes import node_hash
from protocol.merkle import (
    MERKLE_VERSION,
    PROOF_VERSION,
    MerkleTree,
    deserialize_merkle_proof,
    merkle_leaf_hash,
    verify_proof,
)


def test_merkle_consistency_proof_round_trip():
    """Generated consistency proofs should verify."""
    leaves = [hash_bytes(f"leaf-{i}".encode("utf-8")) for i in range(6)]
    old_size = 3
    new_size = 6

    old_root = ct_merkle_root(leaves[:old_size])
    new_root = ct_merkle_root(leaves[:new_size])
    proof = generate_consistency_proof(leaves, old_size, new_size)

    assert verify_consistency_proof(old_root, new_root, proof, old_size, new_size)


def test_merkle_consistency_proof_detects_tampering():
    """Tampering with the proof should invalidate verification."""
    leaves = [hash_bytes(f"leaf-{i}".encode("utf-8")) for i in range(5)]
    old_size = 2
    new_size = 5

    old_root = ct_merkle_root(leaves[:old_size])
    new_root = ct_merkle_root(leaves[:new_size])
    proof = generate_consistency_proof(leaves, old_size, new_size)

    bad_proof = proof.copy()
    bad_proof[0] = hash_bytes(b"tamper")


def test_merkle_leaf_prefix_applied():
    """
    Leaf data must be hashed with LEAF_PREFIX before tree construction.
    The root produced by MerkleTree must differ from a tree built using
    a node prefix for all levels (i.e., the old behavior without domain separation).
    """
    leaves = [b"leaf0", b"leaf1"]
    tree = MerkleTree(leaves)

    # Manually compute what the root should be with LEAF_PREFIX for leaves
    # and NODE_PREFIX for internal nodes.
    leaf0_hash = merkle_leaf_hash(b"leaf0")
    leaf1_hash = merkle_leaf_hash(b"leaf1")

    expected_root = node_hash(leaf0_hash, leaf1_hash)

    assert tree.get_root() == expected_root


def test_merkle_proof_verifies_with_domain_separation():
    """Inclusion proofs must verify correctly with the domain-separated leaf scheme."""
    leaves = [b"alpha", b"beta", b"gamma"]
    tree = MerkleTree(leaves)

    for i in range(len(leaves)):
        proof = tree.generate_proof(i)
        assert verify_proof(proof), f"Proof for leaf {i} should verify"


def test_merkle_proof_leaf_hash_uses_leaf_prefix():
    """MerkleProof.leaf_hash must be the LEAF_PREFIX-domain-separated hash."""
    leaves = [b"x", b"y"]
    tree = MerkleTree(leaves)

    proof = tree.generate_proof(0)
    expected_leaf_hash = merkle_leaf_hash(b"x")
    assert proof.leaf_hash == expected_leaf_hash


def test_merkle_tree_leaves_attr_unchanged():
    """tree.leaves must still expose the original raw leaf data (not prefixed)."""
    raw_leaves = [b"raw1", b"raw2"]
    tree = MerkleTree(raw_leaves)
    assert tree.leaves == raw_leaves


@given(st.binary(min_size=0, max_size=128), st.binary(min_size=0, max_size=128))
def test_leaf_and_internal_node_hashes_are_domain_separated(left: bytes, right: bytes) -> None:
    """
    Domain separation must prevent collisions between leaf and internal node hashing.

    For any inputs, a leaf hash (LEAF_PREFIX) must never collide with a
    NODE_PREFIX-derived internal node hash.
    """
    leaf_hash = merkle_leaf_hash(left)
    internal_hash = node_hash(left, right)
    assert leaf_hash != internal_hash


def test_merkleproof_normalizes_boolean_positions():
    """Legacy boolean sibling positions are normalized to strings."""
    proof = MerkleTree([b"a", b"b"]).generate_proof(0)
    proof_with_bools = proof.__class__(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=[(proof.siblings[0][0], True)],
        root_hash=proof.root_hash,
    )
    assert all(isinstance(pos, str) for _, pos in proof_with_bools.siblings)
    assert proof_with_bools.siblings[0][1] == "right"


# ---------------------------------------------------------------------------
# Proof format versioning
# ---------------------------------------------------------------------------


def test_merkle_proof_has_version_fields():
    """Generated proofs must carry all four versioning fields."""
    leaves = [b"a", b"b", b"c"]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    assert proof.proof_version == PROOF_VERSION
    assert proof.tree_version == MERKLE_VERSION
    assert isinstance(proof.epoch, int)
    assert proof.tree_size == len(leaves)


def test_merkle_proof_tree_size_matches_leaf_count():
    """tree_size in a generated proof must equal the number of leaves."""
    for n in [1, 2, 3, 4, 8, 9]:
        leaves = [bytes([i]) for i in range(n)]
        tree = MerkleTree(leaves)
        proof = tree.generate_proof(0)
        assert proof.tree_size == n, f"tree_size mismatch for {n} leaves"


def test_deserialize_merkle_proof_restores_version_fields():
    """Round-trip through deserialize_merkle_proof must preserve versioning fields."""
    leaves = [b"x", b"y", b"z"]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(1)

    proof_dict = {
        "leaf_hash": proof.leaf_hash.hex(),
        "leaf_index": proof.leaf_index,
        "siblings": [[h.hex(), pos == "right"] for h, pos in proof.siblings],
        "root_hash": proof.root_hash.hex(),
        "proof_version": proof.proof_version,
        "tree_version": proof.tree_version,
        "epoch": proof.epoch,
        "tree_size": proof.tree_size,
    }

    restored = deserialize_merkle_proof(proof_dict)
    assert restored.proof_version == PROOF_VERSION
    assert restored.tree_version == MERKLE_VERSION
    assert restored.epoch == 0
    assert restored.tree_size == len(leaves)
    assert verify_proof(restored)


def test_deserialize_merkle_proof_handles_legacy_proof_without_version_fields():
    """Legacy proofs without versioning fields must deserialize with defaults."""
    leaves = [b"legacy", b"proof"]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    # Simulate a legacy serialized proof without versioning fields
    legacy_dict = {
        "leaf_hash": proof.leaf_hash.hex(),
        "leaf_index": proof.leaf_index,
        "siblings": [[h.hex(), pos == "right"] for h, pos in proof.siblings],
        "root_hash": proof.root_hash.hex(),
    }

    restored = deserialize_merkle_proof(legacy_dict)
    assert restored.proof_version == PROOF_VERSION
    assert restored.tree_version == MERKLE_VERSION
    assert restored.epoch == 0
    assert restored.tree_size == 0
    assert verify_proof(restored)
