import pytest

from poseidon_py.poseidon_hash import poseidon_hash

from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element
from protocol.poseidon_tree import PoseidonMerkleTree, build_poseidon_witness_inputs


def test_blake3_to_field_element_deterministic_and_bounded():
    data = b"olympus-doc"
    val1 = int(blake3_to_field_element(data))
    val2 = int(blake3_to_field_element(data))
    assert val1 == val2
    assert 0 <= val1 < SNARK_SCALAR_FIELD


def _recompute_root(leaf: int, path_elements: list[str], path_indices: list[int]) -> int:
    current = leaf
    for sibling, idx in zip(path_elements, path_indices):
        sib = int(sibling)
        if idx == 0:
            current = poseidon_hash(current, sib)
        else:
            current = poseidon_hash(sib, current)
        current %= SNARK_SCALAR_FIELD
    return current % SNARK_SCALAR_FIELD


@pytest.mark.parametrize("leaves", [(b"a", b"b"), (b"a", b"b", b"c")])
def test_poseidon_merkle_proof_roundtrip(leaves):
    tree = PoseidonMerkleTree(list(leaves))
    root = int(tree.get_root())

    target_index = 1 if len(leaves) > 1 else 0
    path_elements, path_indices = tree.get_proof(target_index)
    reconstructed = _recompute_root(
        int(blake3_to_field_element(leaves[target_index])),
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
    assert proof.leaf == blake3_to_field_element(leaves[0])
