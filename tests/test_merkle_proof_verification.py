"""
Property-based tests for strict Merkle proof verification.

These tests verify that the Merkle proof verification correctly:
1. Enforces exact proof depth based on tree size
2. Rejects proofs with incorrect length (too short or too long)
3. Enforces canonical sibling position representation
4. Rejects variant position inputs (booleans, invalid strings)
"""

import hypothesis.strategies as st
import pytest
from hypothesis import assume, given, settings

from protocol.merkle import MerkleProof, MerkleTree, verify_proof


# Strategy for generating valid tree sizes
tree_sizes = st.integers(min_value=1, max_value=100)


@given(tree_size=tree_sizes, seed=st.integers(min_value=0, max_value=10000))
@settings(max_examples=50, deadline=None)
def test_valid_proofs_verify_for_all_leaves_and_tree_sizes(tree_size: int, seed: int):
    """
    Property: For any tree size and any leaf index, a correctly generated proof
    should always verify successfully.
    """
    # Generate deterministic leaves based on seed
    leaves = [f"leaf-{seed}-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)

    # Test proof for every leaf in the tree
    for leaf_index in range(tree_size):
        proof = tree.generate_proof(leaf_index)

        # Verify the proof structure
        assert proof.tree_size == tree_size
        assert proof.leaf_index == leaf_index
        # With CT-style promotion, proof depth can be <= ceil(log2(n)) due to promoted nodes
        max_depth = 0 if tree_size == 1 else (tree_size - 1).bit_length()
        assert len(proof.siblings) <= max_depth

        # Verify the proof validates correctly
        assert verify_proof(proof), f"Valid proof for leaf {leaf_index} should verify"


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_proof_with_wrong_depth_rejected(tree_size: int, leaf_index: int):
    """
    Property: Proofs with too many siblings (exceeding max depth) should be rejected.
    With CT-style promotion, shorter proofs are valid for promoted leaves.
    """
    assume(leaf_index < tree_size)

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    # Test with too many siblings (exceeding max depth)
    if tree_size > 1:
        max_depth = (tree_size - 1).bit_length()
        # Add enough siblings to exceed max depth
        extra_siblings = list(proof.siblings)
        while len(extra_siblings) <= max_depth:
            if proof.siblings:
                extra_siblings.append(proof.siblings[-1])
            else:
                extra_siblings.append((b"\x00" * 32, "right"))

        long_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            leaf_index=proof.leaf_index,
            siblings=extra_siblings,
            root_hash=proof.root_hash,
            tree_size=proof.tree_size,
        )

        with pytest.raises(ValueError, match="Invalid proof depth"):
            verify_proof(long_proof)


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_proof_with_boolean_positions_rejected(tree_size: int, leaf_index: int):
    """
    Property: Proofs with boolean sibling positions (instead of canonical strings)
    should be rejected during verification.
    """
    assume(leaf_index < tree_size)
    assume(tree_size > 1)  # Need at least one sibling

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    # Convert first sibling position to boolean
    siblings_with_bool = list(proof.siblings)
    first_hash, first_pos = siblings_with_bool[0]
    siblings_with_bool[0] = (first_hash, first_pos == "right")  # Convert to boolean

    # Manually construct proof with boolean position (bypassing normalization)
    proof_with_bool = object.__new__(MerkleProof)
    object.__setattr__(proof_with_bool, "leaf_hash", proof.leaf_hash)
    object.__setattr__(proof_with_bool, "leaf_index", proof.leaf_index)
    object.__setattr__(proof_with_bool, "siblings", siblings_with_bool)
    object.__setattr__(proof_with_bool, "root_hash", proof.root_hash)
    object.__setattr__(proof_with_bool, "tree_size", proof.tree_size)
    object.__setattr__(proof_with_bool, "proof_version", proof.proof_version)
    object.__setattr__(proof_with_bool, "tree_version", proof.tree_version)
    object.__setattr__(proof_with_bool, "epoch", proof.epoch)

    with pytest.raises(ValueError, match="Invalid sibling position.*boolean"):
        verify_proof(proof_with_bool)


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_proof_with_invalid_position_strings_rejected(tree_size: int, leaf_index: int):
    """
    Property: Proofs with invalid position strings (not "left" or "right")
    should be rejected.
    """
    assume(leaf_index < tree_size)
    assume(tree_size > 1)  # Need at least one sibling

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    invalid_positions = ["Left", "Right", "LEFT", "RIGHT", "l", "r", "0", "1", "", "true", "false"]

    for invalid_pos in invalid_positions:
        siblings_with_invalid = list(proof.siblings)
        first_hash = siblings_with_invalid[0][0]
        siblings_with_invalid[0] = (first_hash, invalid_pos)

        # Manually construct proof with invalid position (bypassing normalization)
        proof_with_invalid = object.__new__(MerkleProof)
        object.__setattr__(proof_with_invalid, "leaf_hash", proof.leaf_hash)
        object.__setattr__(proof_with_invalid, "leaf_index", proof.leaf_index)
        object.__setattr__(proof_with_invalid, "siblings", siblings_with_invalid)
        object.__setattr__(proof_with_invalid, "root_hash", proof.root_hash)
        object.__setattr__(proof_with_invalid, "tree_size", proof.tree_size)
        object.__setattr__(proof_with_invalid, "proof_version", proof.proof_version)
        object.__setattr__(proof_with_invalid, "tree_version", proof.tree_version)
        object.__setattr__(proof_with_invalid, "epoch", proof.epoch)

        with pytest.raises(ValueError, match="Invalid sibling position"):
            verify_proof(proof_with_invalid)


@given(tree_size=tree_sizes)
def test_proof_with_out_of_bounds_leaf_index_rejected(tree_size: int):
    """
    Property: Proofs with leaf_index outside valid range [0, tree_size) should be rejected.
    """
    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    # Test with negative leaf_index
    invalid_proof_negative = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=-1,
        siblings=proof.siblings,
        root_hash=proof.root_hash,
        tree_size=proof.tree_size,
    )

    with pytest.raises(ValueError, match="Invalid leaf_index"):
        verify_proof(invalid_proof_negative)

    # Test with leaf_index >= tree_size
    invalid_proof_too_large = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=tree_size,  # Just past the end
        siblings=proof.siblings,
        root_hash=proof.root_hash,
        tree_size=proof.tree_size,
    )

    with pytest.raises(ValueError, match="Invalid leaf_index"):
        verify_proof(invalid_proof_too_large)


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_tampered_sibling_hash_causes_verification_failure(tree_size: int, leaf_index: int):
    """
    Property: Tampering with any sibling hash should cause verification to fail
    (return False, not raise an exception).
    """
    assume(leaf_index < tree_size)
    assume(tree_size > 1)  # Need at least one sibling to tamper with

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    # Tamper with the first sibling hash
    tampered_siblings = list(proof.siblings)
    original_hash, position = tampered_siblings[0]
    # Flip one bit in the hash
    tampered_hash = bytes([original_hash[0] ^ 0x01]) + original_hash[1:]
    tampered_siblings[0] = (tampered_hash, position)

    tampered_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=tampered_siblings,
        root_hash=proof.root_hash,
        tree_size=proof.tree_size,
    )

    # Tampered proof should not verify (returns False, doesn't raise)
    assert not verify_proof(tampered_proof), "Tampered proof should fail verification"


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_tampered_root_hash_causes_verification_failure(tree_size: int, leaf_index: int):
    """
    Property: Using a different root hash should cause verification to fail.
    """
    assume(leaf_index < tree_size)

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    # Use a different root hash
    fake_root = b"\x00" * 32
    assume(fake_root != proof.root_hash)

    tampered_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root_hash=fake_root,
        tree_size=proof.tree_size,
    )

    assert not verify_proof(tampered_proof), "Proof with wrong root should fail verification"


@given(tree_size=tree_sizes, leaf_index=st.integers(min_value=0, max_value=99))
def test_swapped_sibling_positions_causes_verification_failure(tree_size: int, leaf_index: int):
    """
    Property: Swapping sibling positions (left <-> right) should cause verification to fail.
    """
    assume(leaf_index < tree_size)
    assume(tree_size > 1)  # Need at least one sibling

    leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(leaf_index)

    # Swap the position of the first sibling
    swapped_siblings = list(proof.siblings)
    first_hash, first_pos = swapped_siblings[0]
    new_pos = "left" if first_pos == "right" else "right"
    swapped_siblings[0] = (first_hash, new_pos)

    swapped_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=swapped_siblings,
        root_hash=proof.root_hash,
        tree_size=proof.tree_size,
    )

    # Swapping sibling positions should cause verification to fail.
    # This is a cryptographic property: changing the tree structure (left vs right)
    # should result in a different root hash, so verification must fail.
    # While theoretically a hash collision could make this pass, the probability is
    # negligible (2^-256 for BLAKE3), so we assert it always fails.
    assert not verify_proof(swapped_proof), (
        "Swapping sibling positions should always fail verification"
    )


def test_proof_depth_calculation_matches_expected_formula():
    """
    Test that proof depth matches the expected formula: ceil(log2(tree_size)) for tree_size > 1.
    """
    test_cases = [
        (1, 0),  # Single leaf, no siblings
        (2, 1),  # Two leaves, 1 sibling
        (3, 2),  # Three leaves, 2 siblings
        (4, 2),  # Four leaves, 2 siblings
        (5, 3),  # Five leaves, 3 siblings
        (8, 3),  # Eight leaves, 3 siblings
        (9, 4),  # Nine leaves, 4 siblings
        (16, 4),  # Sixteen leaves, 4 siblings
        (17, 5),  # Seventeen leaves, 5 siblings
    ]

    for tree_size, expected_depth in test_cases:
        leaves = [f"leaf-{i}".encode() for i in range(tree_size)]
        tree = MerkleTree(leaves)
        proof = tree.generate_proof(0)

        assert len(proof.siblings) == expected_depth, (
            f"Tree size {tree_size} should have depth {expected_depth}, got {len(proof.siblings)}"
        )

        # Verify that the proof validates
        assert verify_proof(proof), f"Proof for tree size {tree_size} should verify"


def test_rejection_of_mismatched_tree_size():
    """
    Test that verification rejects proofs where siblings exceed max depth for tree_size.
    With CT-style, shorter proofs are valid, but longer proofs are rejected.
    """
    leaves = [b"a", b"b", b"c", b"d"]  # 4 leaves, max depth should be 2
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    # Create proof claiming smaller tree size (proof has too many siblings for this size)
    # For tree_size=2, max depth is 1, but we have depth 2
    too_small_size_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root_hash=proof.root_hash,
        tree_size=2,  # Claim 2 leaves but proof has depth for 4 leaves
    )

    # This should fail because depth=2 exceeds max for tree_size=2 (should be 1)
    with pytest.raises(ValueError, match="Invalid proof depth"):
        verify_proof(too_small_size_proof)


def test_legacy_proof_without_tree_size_still_verifies():
    """
    Test that legacy proofs with tree_size=0 can still be verified,
    but without strict depth checking.
    """
    leaves = [b"x", b"y", b"z"]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(1)

    # Create a legacy-style proof with tree_size=0
    legacy_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root_hash=proof.root_hash,
        tree_size=0,  # Legacy proofs had tree_size=0
    )

    # Should verify without strict depth checking
    assert verify_proof(legacy_proof), "Legacy proof with tree_size=0 should verify"


def test_canonical_position_normalization_in_merkle_proof_init():
    """
    Test that MerkleProof.__post_init__ normalizes boolean positions to canonical strings.
    """
    leaves = [b"a", b"b", b"c"]
    tree = MerkleTree(leaves)
    proof = tree.generate_proof(0)

    # Create proof with boolean positions matching the original proof
    # Convert each position to its boolean equivalent
    siblings_with_bools = [
        (h, pos == "right")  # True for "right", False for "left"
        for h, pos in proof.siblings
    ]

    normalized_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=siblings_with_bools,
        root_hash=proof.root_hash,
        tree_size=proof.tree_size,
    )

    # Check that positions were normalized to strings
    assert all(isinstance(pos, str) for _, pos in normalized_proof.siblings)

    # Check that normalized positions match the original
    for i, ((_, orig_pos), (_, norm_pos)) in enumerate(
        zip(proof.siblings, normalized_proof.siblings)
    ):
        assert norm_pos == orig_pos, f"Position {i} should match after normalization"

    # Normalized proof should verify
    assert verify_proof(normalized_proof)


def test_deserialize_merkle_proof_rejects_excessive_depth():
    """
    L5-D: Test that deserialize_merkle_proof rejects proofs exceeding MAX_PROOF_DEPTH.

    This prevents algorithmic complexity DoS attacks where an attacker submits
    a proof with an unreasonably large number of siblings.
    """
    from protocol.merkle import MAX_PROOF_DEPTH, deserialize_merkle_proof

    # Create a minimal valid proof structure
    valid_leaf_hash = "a" * 64  # 32 bytes as hex
    valid_root_hash = "b" * 64
    valid_sibling = ["c" * 64, "right"]

    # Test at the boundary: exactly MAX_PROOF_DEPTH siblings should be accepted
    proof_at_limit = {
        "leaf_hash": valid_leaf_hash,
        "leaf_index": 0,
        "siblings": [valid_sibling] * MAX_PROOF_DEPTH,
        "root_hash": valid_root_hash,
        "tree_size": 0,  # tree_size=0 disables depth validation in verify_proof
    }
    # Should not raise - parsing succeeds (verification may fail separately)
    proof = deserialize_merkle_proof(proof_at_limit)
    assert len(proof.siblings) == MAX_PROOF_DEPTH

    # Test exceeding the limit: MAX_PROOF_DEPTH + 1 should be rejected
    proof_over_limit = {
        "leaf_hash": valid_leaf_hash,
        "leaf_index": 0,
        "siblings": [valid_sibling] * (MAX_PROOF_DEPTH + 1),
        "root_hash": valid_root_hash,
        "tree_size": 0,
    }
    with pytest.raises(ValueError, match="exceeds maximum allowed depth"):
        deserialize_merkle_proof(proof_over_limit)

    # Test way over the limit (potential DoS payload)
    proof_malicious = {
        "leaf_hash": valid_leaf_hash,
        "leaf_index": 0,
        "siblings": [valid_sibling] * 10000,  # Absurdly large
        "root_hash": valid_root_hash,
        "tree_size": 0,
    }
    with pytest.raises(ValueError, match="exceeds maximum allowed depth"):
        deserialize_merkle_proof(proof_malicious)
