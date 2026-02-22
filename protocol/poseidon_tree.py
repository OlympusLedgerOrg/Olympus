"""Poseidon Merkle utilities for bridging BLAKE3 data into ZK circuits."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from poseidon_py.poseidon_hash import poseidon_hash

from .hashes import SNARK_SCALAR_FIELD, blake3_to_field_element


def _to_field_int(value: int | str | bytes) -> int:
    """
    Normalize a value into the BN128 field as an integer.
    """
    if isinstance(value, bytes):
        return int(blake3_to_field_element(value))
    if isinstance(value, str):
        return int(value) % SNARK_SCALAR_FIELD
    if isinstance(value, int):
        return value % SNARK_SCALAR_FIELD
    raise TypeError(f"Unsupported leaf type: {type(value)!r}")


def _poseidon_hash(left: int, right: int) -> int:
    """Hash two field elements with Poseidon(2), returning an in-field int."""
    return poseidon_hash(left % SNARK_SCALAR_FIELD, right % SNARK_SCALAR_FIELD) % SNARK_SCALAR_FIELD


@dataclass
class PoseidonProof:
    """Poseidon Merkle inclusion proof."""

    root: str
    leaf: str
    leaf_index: int
    path_elements: list[str]
    path_indices: list[int]


class PoseidonMerkleTree:
    """
    Poseidon-based binary Merkle tree.

    Leaves may be provided as raw bytes (hashed with BLAKE3 then reduced into
    the BN128 field), decimal strings, or integers already inside the field.
    """

    def __init__(self, leaves: Iterable[int | str | bytes], depth: int | None = None) -> None:
        normalized = [_to_field_int(leaf) for leaf in leaves]
        if not normalized:
            raise ValueError("Cannot create Poseidon Merkle tree with no leaves")

        if depth is not None:
            width = 1 << depth
            if len(normalized) > width:
                raise ValueError(
                    f"Provided {len(normalized)} leaves but depth {depth} only supports {width}"
                )
            padding = [0] * (width - len(normalized))
            self._leaves: list[int] = normalized + padding
        else:
            self._leaves = normalized

    def _build_level(self, level: Sequence[int]) -> list[int]:
        """Hash a level upwards, duplicating the final leaf when odd."""
        if len(level) == 1:
            return [level[0]]

        padded = list(level)
        if len(padded) % 2 == 1:
            padded.append(padded[-1])

        next_level = []
        for i in range(0, len(padded), 2):
            next_level.append(_poseidon_hash(padded[i], padded[i + 1]))
        return next_level

    def get_root(self) -> str:
        """Return the Merkle root as a decimal string."""
        level = list(self._leaves)
        while len(level) > 1:
            level = self._build_level(level)
        return str(level[0] % SNARK_SCALAR_FIELD)

    def get_proof(self, leaf_index: int) -> tuple[list[str], list[int]]:
        """
        Return (pathElements, pathIndices) for the given leaf.

        pathIndices follows the circom convention: 0 when the current node is a
        left child, 1 when it is a right child.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise ValueError(f"Invalid leaf index {leaf_index}")

        path_elements: list[str] = []
        path_indices: list[int] = []

        level = list(self._leaves)
        index = leaf_index

        while len(level) > 1:
            padded = list(level)
            if len(padded) % 2 == 1:
                padded.append(padded[-1])

            if index % 2 == 0:
                sibling = padded[index + 1]
                path_indices.append(0)
            else:
                sibling = padded[index - 1]
                path_indices.append(1)

            path_elements.append(str(sibling % SNARK_SCALAR_FIELD))

            parents: list[int] = []
            for i in range(0, len(padded), 2):
                parents.append(_poseidon_hash(padded[i], padded[i + 1]))

            level = parents
            index //= 2

        return path_elements, path_indices


def build_poseidon_witness_inputs(
    document_leaves: list[bytes], target_index: int, *, depth: int | None = None
) -> PoseidonProof:
    """
    Prepare Poseidon Merkle inputs for circom/snarkjs witnesses.

    Args:
        document_leaves: Raw document chunks (bytes) to commit.
        target_index: Zero-based index of the leaf to prove.
        depth: Optional fixed depth. Pads with zeros to 2**depth leaves when set.

    Returns:
        PoseidonProof with root, leaf, path elements, and indices ready for witness JSON.
    """
    leaves = [blake3_to_field_element(chunk) for chunk in document_leaves]
    tree = PoseidonMerkleTree(leaves, depth=depth)
    path_elements, path_indices = tree.get_proof(target_index)

    return PoseidonProof(
        root=tree.get_root(),
        leaf=leaves[target_index],
        leaf_index=target_index,
        path_elements=path_elements,
        path_indices=path_indices,
    )
