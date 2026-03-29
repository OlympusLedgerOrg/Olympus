"""Targeted coverage tests for protocol/merkle.py — proof verification edge cases.

Covers:
- _extract_leaf_bytes with CanonicalEvent (line 140)
- _subproof_ct identical-size non-root (line 453)
- _subproof_ct old_size>k but new_size<=k (line 472)
- _verify_subproof_ct proof exhaustion (lines 564, 566, 577-582, 586)
- _verify_subproof_ct new_size<=k branch (lines 606, 613-614)
"""

import pytest

from protocol.events import CanonicalEvent
from protocol.hashes import node_hash
from protocol.merkle import (
    MerkleTree,
    _subproof_ct,
    _verify_subproof_ct,
    ct_merkle_root,
    generate_consistency_proof,
    merkle_leaf_hash,
    verify_consistency_proof,
)


# ---------------------------------------------------------------------------
# _extract_leaf_bytes — CanonicalEvent input (line 140)
# ---------------------------------------------------------------------------


def test_merkle_tree_accepts_canonical_events():
    """MerkleTree should accept CanonicalEvent objects as leaves."""
    from protocol.canonical_json import canonical_json_bytes

    payload = {"shard_id": "test", "record_hash": "aa" * 32}
    canonical = canonical_json_bytes(payload)
    evt = CanonicalEvent(
        payload=payload,
        canonical_bytes=canonical,
        schema_version="1.0",
        hash_hex="bb" * 32,
    )
    tree = MerkleTree([evt])
    root = tree.get_root()
    assert len(root) == 32


def test_merkle_tree_rejects_non_bytes():
    """MerkleTree rejects inputs that are neither bytes nor CanonicalEvent."""
    with pytest.raises(ValueError, match="bytes or CanonicalEvent"):
        MerkleTree([123])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# Consistency proof — identical-size sub-tree (line 453)
# ---------------------------------------------------------------------------


def test_subproof_identical_size_at_root():
    """_subproof_ct with old_size==new_size at root returns empty list."""
    leaf_hashes = [merkle_leaf_hash(b"a"), merkle_leaf_hash(b"b")]
    result = _subproof_ct(leaf_hashes, 2, 2, is_root=True)
    assert result == []


def test_subproof_identical_size_not_root():
    """_subproof_ct with old_size==new_size NOT at root returns subtree root."""
    leaf_hashes = [merkle_leaf_hash(b"a"), merkle_leaf_hash(b"b")]
    result = _subproof_ct(leaf_hashes, 2, 2, is_root=False)
    assert len(result) == 1
    assert result[0] == ct_merkle_root(leaf_hashes[:2])


# ---------------------------------------------------------------------------
# Consistency proof — old_size > k edge (line 472)
# ---------------------------------------------------------------------------


def test_consistency_proof_three_to_four_leaves():
    """Generate and verify consistency proof from 3 to 4 leaves.

    This exercises the old_size > k branch in _subproof_ct.
    """
    leaves = [merkle_leaf_hash(str(i).encode()) for i in range(4)]
    old_leaves = leaves[:3]
    new_leaves = leaves[:4]
    old_root = ct_merkle_root(old_leaves)
    new_root = ct_merkle_root(new_leaves)
    proof = generate_consistency_proof(leaves, 3, 4)
    assert verify_consistency_proof(old_root, new_root, proof, 3, 4)


def test_consistency_proof_two_to_two():
    """Empty proof for identical trees should verify."""
    leaves = [merkle_leaf_hash(b"x"), merkle_leaf_hash(b"y")]
    root = ct_merkle_root(leaves)
    # Same size → empty proof
    proof = generate_consistency_proof(leaves, 2, 2)
    assert verify_consistency_proof(root, root, proof, 2, 2)


# ---------------------------------------------------------------------------
# _verify_subproof_ct — negative size (line 564)
# ---------------------------------------------------------------------------


def test_verify_subproof_negative_old_size():
    """Reject negative old_size."""
    with pytest.raises(ValueError, match="non-negative"):
        _verify_subproof_ct([], 0, -1, 2, True)


def test_verify_subproof_negative_new_size():
    """Reject negative new_size."""
    with pytest.raises(ValueError, match="non-negative"):
        _verify_subproof_ct([], 0, 1, -1, True)


# ---------------------------------------------------------------------------
# _verify_subproof_ct — old > new (line 566)
# ---------------------------------------------------------------------------


def test_verify_subproof_old_greater_than_new():
    """Reject old_size > new_size."""
    with pytest.raises(ValueError, match="cannot exceed"):
        _verify_subproof_ct([], 0, 5, 3, True)


# ---------------------------------------------------------------------------
# _verify_subproof_ct — identical-size at root (lines 577-582)
# ---------------------------------------------------------------------------


def test_verify_subproof_identical_root_exhausted():
    """Proof exhaustion with identical subtree sizes at root."""
    with pytest.raises(ValueError, match="Proof exhausted"):
        _verify_subproof_ct([], 0, 4, 4, True)


def test_verify_subproof_identical_root_with_node():
    """Identical subtree sizes at root with a proof node."""
    h = b"\xaa" * 32
    old_root, new_root, idx = _verify_subproof_ct([h], 0, 4, 4, True)
    assert old_root == h
    assert new_root == h
    assert idx == 1


# ---------------------------------------------------------------------------
# _verify_subproof_ct — identical-size NOT at root (lines 585-588)
# ---------------------------------------------------------------------------


def test_verify_subproof_identical_not_root_exhausted():
    """Proof exhaustion with identical subtree sizes not at root."""
    with pytest.raises(ValueError, match="Proof exhausted"):
        _verify_subproof_ct([], 0, 4, 4, False)


def test_verify_subproof_identical_not_root_with_node():
    """Identical subtree sizes not at root returns proof node for both roots."""
    h = b"\xbb" * 32
    old_root, new_root, idx = _verify_subproof_ct([h], 0, 4, 4, False)
    assert old_root == h
    assert new_root == h
    assert idx == 1


# ---------------------------------------------------------------------------
# _verify_subproof_ct — expected right subtree exhaustion (line 606)
# ---------------------------------------------------------------------------


def test_verify_subproof_right_exhausted():
    """Proof exhausted when expecting right subtree root."""
    # old_size=1, new_size=3, k=2 → old_size <= k, recurse left (1,2,False)
    # Then need right root but proof only has the left subtree node.
    h = b"\xcc" * 32
    with pytest.raises(ValueError, match="Proof exhausted"):
        _verify_subproof_ct([h], 0, 1, 3, True)


# ---------------------------------------------------------------------------
# _verify_subproof_ct — new_size <= k branch (lines 613-614)
# ---------------------------------------------------------------------------


def test_verify_subproof_new_size_equals_k():
    """When new_size == k, the right subtree is absent."""
    # old_size=1, new_size=2, k=2 → old_size <= k, recurse left (1,2,False)
    # new_size(2) == k(2) → no right subtree
    h = b"\xdd" * 32
    h2 = b"\xee" * 32
    # In the recursive call for left subtree (old_size=1, new_size=2, False):
    # k=1, old_size <= k → recurse left again (1,1,False) → needs proof node
    # Then new_size(2) > k(1) → needs right node
    # We need [subtree_root_for_1,1, right_root_for_2nd_leaf]
    old_root, new_root, idx = _verify_subproof_ct([h, h2], 0, 1, 2, True)
    assert idx == 2  # consumed both proof nodes
    # old_root should be based on the single-leaf tree
    assert old_root == h
    # new_root combines both
    assert new_root == node_hash(h, h2)


# ---------------------------------------------------------------------------
# End-to-end consistency proof round-trips
# ---------------------------------------------------------------------------


def test_consistency_proof_1_to_5():
    """Consistency proof spanning several doublings."""
    leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(5)]
    old_root = ct_merkle_root(leaves[:1])
    new_root = ct_merkle_root(leaves[:5])
    proof = generate_consistency_proof(leaves, 1, 5)
    assert verify_consistency_proof(old_root, new_root, proof, 1, 5)


def test_consistency_proof_3_to_7():
    """Consistency proof covering old_size > k case in generation."""
    leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(7)]
    old_root = ct_merkle_root(leaves[:3])
    new_root = ct_merkle_root(leaves[:7])
    proof = generate_consistency_proof(leaves, 3, 7)
    assert verify_consistency_proof(old_root, new_root, proof, 3, 7)


def test_consistency_proof_rejects_tampered_proof():
    """Tampered consistency proof fails verification."""
    leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(4)]
    old_root = ct_merkle_root(leaves[:2])
    new_root = ct_merkle_root(leaves[:4])
    proof = generate_consistency_proof(leaves, 2, 4)
    # Tamper
    tampered = [bytearray(p) for p in proof]
    if tampered:
        tampered[0][-1] ^= 0xFF
        assert not verify_consistency_proof(old_root, new_root, [bytes(t) for t in tampered], 2, 4)
