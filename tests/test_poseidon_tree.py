import pytest

from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element
from protocol.poseidon_bn128 import poseidon_hash_bn128
from protocol.poseidon_tree import (
    POSEIDON_DOMAIN_NODE,
    PoseidonMerkleTree,
    _to_field_int,
    build_poseidon_witness_inputs,
    poseidon_hash_with_domain,
)


def test_blake3_to_field_element_deterministic_and_bounded():
    data = b"olympus-doc"
    val1 = int(blake3_to_field_element(data))
    val2 = int(blake3_to_field_element(data))
    assert val1 == val2
    assert 0 <= val1 < SNARK_SCALAR_FIELD


def _recompute_root(leaf: int, path_elements: list[str], path_indices: list[int]) -> int:
    """Recompute Merkle root using domain-separated Poseidon hashing."""
    current = leaf
    for sibling, idx in zip(path_elements, path_indices):
        sib = int(sibling)
        if idx == 0:
            current = poseidon_hash_with_domain(current, sib, POSEIDON_DOMAIN_NODE)
        else:
            current = poseidon_hash_with_domain(sib, current, POSEIDON_DOMAIN_NODE)
        current %= SNARK_SCALAR_FIELD
    return current % SNARK_SCALAR_FIELD


@pytest.mark.parametrize("leaves", [(b"a", b"b"), (b"a", b"b", b"c")])
def test_poseidon_merkle_proof_roundtrip(leaves):
    tree = PoseidonMerkleTree(list(leaves))
    root = int(tree.get_root())

    target_index = 1 if len(leaves) > 1 else 0
    path_elements, path_indices = tree.get_proof(target_index)
    reconstructed = _recompute_root(
        _to_field_int(leaves[target_index], index=target_index),
        path_elements,
        path_indices,
    )
    assert reconstructed == root


def test_build_poseidon_witness_inputs_matches_tree():
    leaves = [b"alpha", b"beta"]
    proof = build_poseidon_witness_inputs(leaves, target_index=0)
    root = int(proof.root)

    recomputed = _recompute_root(int(proof.leaf), proof.path_elements, proof.path_indices)
    assert recomputed == root
    # The leaf value should match the position-bound normalization
    assert proof.leaf == str(_to_field_int(leaves[0], index=0))


def test_to_field_int_with_int():
    """_to_field_int normalizes an integer to the BN128 field."""
    val = 42
    assert _to_field_int(val) == val % SNARK_SCALAR_FIELD


def test_to_field_int_with_string():
    """_to_field_int reduces a decimal string modulo SNARK_SCALAR_FIELD."""
    val = "1234567890"
    assert _to_field_int(val) == int(val) % SNARK_SCALAR_FIELD


def test_to_field_int_rejects_invalid_type():
    """_to_field_int raises TypeError for unsupported types."""
    with pytest.raises(TypeError, match="Unsupported leaf type"):
        _to_field_int([1, 2, 3])  # type: ignore[arg-type]


def test_poseidon_merkle_tree_rejects_empty_leaves():
    """PoseidonMerkleTree raises ValueError when given no leaves."""
    with pytest.raises(ValueError, match="no leaves"):
        PoseidonMerkleTree([])


def test_poseidon_merkle_tree_with_depth_pads_leaves():
    """PoseidonMerkleTree with depth pads to 2**depth leaves."""
    tree = PoseidonMerkleTree([b"a", b"b"], depth=2)
    root = tree.get_root()
    assert root  # non-empty root means the tree built successfully


def test_poseidon_merkle_tree_depth_rejects_too_many_leaves():
    """PoseidonMerkleTree raises ValueError when leaves exceed capacity."""
    with pytest.raises(ValueError, match="depth"):
        PoseidonMerkleTree([b"a", b"b", b"c"], depth=1)


def test_poseidon_merkle_tree_single_leaf():
    """PoseidonMerkleTree with a single leaf returns a valid root."""
    tree = PoseidonMerkleTree([b"solo"])
    root = tree.get_root()
    assert root


def test_poseidon_merkle_tree_get_proof_rejects_invalid_index():
    """PoseidonMerkleTree.get_proof raises ValueError for out-of-range index."""
    tree = PoseidonMerkleTree([b"a", b"b"])
    with pytest.raises(ValueError, match="Invalid leaf index"):
        tree.get_proof(-1)


def test_identical_bytes_at_different_positions_produce_different_field_elements():
    """
    Identical byte payloads at different positions must produce different field elements.

    This prevents order-insensitivity bugs in symmetric trees like [A, B, A].
    """
    # Two identical payloads at positions 0 and 2
    payload = b"\x00\x00"

    # Normalize the same payload at different indices
    fe_at_0 = _to_field_int(payload, index=0)
    fe_at_1 = _to_field_int(payload, index=1)
    fe_at_2 = _to_field_int(payload, index=2)

    # All must be different due to position binding
    assert fe_at_0 != fe_at_1, "Same payload at indices 0 and 1 must produce different field elements"
    assert fe_at_0 != fe_at_2, "Same payload at indices 0 and 2 must produce different field elements"
    assert fe_at_1 != fe_at_2, "Same payload at indices 1 and 2 must produce different field elements"

    # Also verify that this prevents order collision in asymmetric trees
    # Use [A, A, B] which is different from [B, A, A] after reversal
    leaves = [b"\x00\x00", b"\x00\x00", b"\x00"]
    tree1 = PoseidonMerkleTree(leaves)
    root1 = tree1.get_root()

    reversed_leaves = list(reversed(leaves))
    tree2 = PoseidonMerkleTree(reversed_leaves)
    root2 = tree2.get_root()

    assert root1 != root2, "Trees with different orderings must have different roots"

