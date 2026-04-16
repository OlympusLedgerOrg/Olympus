"""Property-based tests for cryptographic invariants using Hypothesis.

These tests assert fundamental properties that must hold for all inputs:
- Poseidon hash determinism and uniqueness
- Merkle tree collision resistance
"""

from hypothesis import given, strategies as st

from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element
from protocol.merkle import MerkleTree
from protocol.poseidon import poseidon_hash_bn128
from protocol.poseidon_tree import PoseidonMerkleTree


# Strategies for generating test data
field_elements = st.integers(min_value=0, max_value=SNARK_SCALAR_FIELD - 1)
binary_data = st.binary(min_size=1, max_size=1024)
leaf_lists = st.lists(binary_data, min_size=1, max_size=32)


@given(field_elements, field_elements)
def test_poseidon_is_deterministic(left: int, right: int):
    """Poseidon hash must be deterministic: same inputs always produce same output."""
    hash1 = poseidon_hash_bn128(left, right)
    hash2 = poseidon_hash_bn128(left, right)
    assert hash1 == hash2, "Poseidon hash must be deterministic"


@given(field_elements, field_elements)
def test_poseidon_output_in_field(left: int, right: int):
    """Poseidon hash output must always be in the BN128 scalar field."""
    result = poseidon_hash_bn128(left, right)
    assert 0 <= result < SNARK_SCALAR_FIELD, "Poseidon hash must be in field"


@given(st.integers(min_value=0, max_value=SNARK_SCALAR_FIELD - 1))
def test_poseidon_collision_resistance_different_pairs(value: int):
    """Different input pairs should produce different hashes (collision resistance).

    Tests that hash(a, b) != hash(b, a) when a != b, and that small changes
    in input produce different outputs.
    """
    # Test swap resistance: hash(a, b) != hash(b, a) when a != b
    if value > 0:  # Avoid the trivial case where both are the same
        hash_ab = poseidon_hash_bn128(value, 0)
        hash_ba = poseidon_hash_bn128(0, value)
        assert hash_ab != hash_ba, "Poseidon must be order-sensitive"

    # Test that changing one input changes the output
    hash_original = poseidon_hash_bn128(value, value)
    # Modify second argument slightly (stay in field)
    modified = (value + 1) % SNARK_SCALAR_FIELD
    hash_modified = poseidon_hash_bn128(value, modified)
    assert hash_original != hash_modified, "Poseidon must be sensitive to input changes"


@given(binary_data)
def test_blake3_to_field_is_deterministic(data: bytes):
    """blake3_to_field_element must be deterministic and always in field."""
    elem1 = int(blake3_to_field_element(data))
    elem2 = int(blake3_to_field_element(data))
    assert elem1 == elem2, "blake3_to_field_element must be deterministic"
    assert 0 <= elem1 < SNARK_SCALAR_FIELD, "Output must be in BN128 field"


@given(leaf_lists)
def test_merkle_root_is_deterministic(leaves: list[bytes]):
    """Merkle root must be deterministic: same leaves always produce same root."""
    tree1 = MerkleTree(leaves)
    tree2 = MerkleTree(leaves)
    assert tree1.get_root() == tree2.get_root(), "Merkle root must be deterministic"


@given(leaf_lists)
def test_merkle_root_changes_when_leaf_changes(leaves: list[bytes]):
    """Changing any leaf must change the Merkle root (collision resistance).

    This is a fundamental security property: if you can find two different
    leaf sets with the same root, you've found a collision.
    """
    if len(leaves) < 2:
        # Skip test for single-leaf trees (nothing to modify)
        return

    tree1 = MerkleTree(leaves)
    root1 = tree1.get_root()

    # Modify the first leaf
    modified_leaves = leaves.copy()
    modified_leaves[0] = modified_leaves[0] + b"_modified"

    tree2 = MerkleTree(modified_leaves)
    root2 = tree2.get_root()

    assert root1 != root2, "Changing a leaf must change the Merkle root"


@given(leaf_lists)
def test_merkle_root_is_order_sensitive(leaves: list[bytes]):
    """Merkle root must change if leaf order changes (unless leaves are identical).

    This ensures the Merkle tree preserves ordering information.
    """
    if len(leaves) < 2:
        # Skip test for single-leaf trees
        return

    # Check if all leaves are the same
    if all(leaf == leaves[0] for leaf in leaves):
        # Skip test - reordering identical elements won't change the root
        return

    tree1 = MerkleTree(leaves)
    root1 = tree1.get_root()

    # Reverse the order
    reversed_leaves = list(reversed(leaves))
    if reversed_leaves == leaves:
        # Palindromic sequences reverse to themselves; no order change occurred.
        return
    tree2 = MerkleTree(reversed_leaves)
    root2 = tree2.get_root()

    assert root1 != root2, "Changing leaf order must change the Merkle root"


@given(leaf_lists)
def test_poseidon_merkle_root_is_deterministic(leaves: list[bytes]):
    """Poseidon Merkle root must be deterministic: same leaves always produce same root."""
    tree1 = PoseidonMerkleTree(leaves)
    tree2 = PoseidonMerkleTree(leaves)
    assert tree1.get_root() == tree2.get_root(), "Poseidon Merkle root must be deterministic"


@given(leaf_lists)
def test_poseidon_merkle_root_changes_when_leaf_changes(leaves: list[bytes]):
    """Changing any leaf must change the Poseidon Merkle root (collision resistance)."""
    if len(leaves) < 2:
        # Skip test for single-leaf trees
        return

    tree1 = PoseidonMerkleTree(leaves)
    root1 = tree1.get_root()

    # Modify the first leaf
    modified_leaves = leaves.copy()
    modified_leaves[0] = modified_leaves[0] + b"_modified"

    tree2 = PoseidonMerkleTree(modified_leaves)
    root2 = tree2.get_root()

    assert root1 != root2, "Changing a leaf must change the Poseidon Merkle root"


@given(leaf_lists)
def test_poseidon_merkle_root_is_order_sensitive(leaves: list[bytes]):
    """Poseidon Merkle root must change if leaf order changes."""
    if len(leaves) < 2:
        # Skip test for single-leaf trees
        return

    # Check if all leaves are the same
    if all(leaf == leaves[0] for leaf in leaves):
        # Skip test - reordering identical elements won't change the root
        return

    tree1 = PoseidonMerkleTree(leaves)
    root1 = tree1.get_root()

    # Reverse the order
    reversed_leaves = list(reversed(leaves))
    if reversed_leaves == leaves:
        # Palindromic sequences reverse to themselves; no order change occurred.
        return
    tree2 = PoseidonMerkleTree(reversed_leaves)
    root2 = tree2.get_root()

    assert root1 != root2, "Changing leaf order must change the Poseidon Merkle root"


@given(leaf_lists, st.integers(min_value=0))
def test_merkle_proof_verifies_for_all_leaves(leaves: list[bytes], seed: int):
    """Every leaf in a Merkle tree must have a valid inclusion proof.

    This is a fundamental correctness property: if we commit to data,
    we must be able to prove that commitment.
    """
    from protocol.merkle import verify_proof

    tree = MerkleTree(leaves)

    # Test a random leaf (use seed to select deterministically)
    leaf_index = seed % len(leaves)
    proof = tree.generate_proof(leaf_index)

    assert verify_proof(proof), f"Proof for leaf {leaf_index} must verify"
    assert proof.root_hash == tree.get_root(), "Proof root must match tree root"


@given(leaf_lists, st.integers(min_value=0))
def test_poseidon_merkle_proof_verifies_for_all_leaves(leaves: list[bytes], seed: int):
    """Every leaf in a Poseidon Merkle tree must have a valid inclusion proof."""
    from protocol.poseidon import poseidon_hash_bn128
    from protocol.poseidon_tree import _to_field_int

    tree = PoseidonMerkleTree(leaves)

    # Test a random leaf
    leaf_index = seed % len(leaves)
    path_elements, path_indices = tree.get_proof(leaf_index)

    # Get the leaf value with position binding
    leaf_int = _to_field_int(leaves[leaf_index], index=leaf_index)

    # Reconstruct root from proof using plain Poseidon (matching circuit)
    current = leaf_int
    for sibling, is_left in zip(path_elements, path_indices):
        sibling_int = int(sibling)
        if is_left == 0:  # Current node is left child
            current = poseidon_hash_bn128(current, sibling_int)
        else:  # Current node is right child
            current = poseidon_hash_bn128(sibling_int, current)
        current %= SNARK_SCALAR_FIELD

    reconstructed_root = str(current % SNARK_SCALAR_FIELD)
    assert reconstructed_root == tree.get_root(), "Poseidon proof must reconstruct the root"
