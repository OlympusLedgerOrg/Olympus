"""Poseidon Merkle utilities for bridging BLAKE3 data into ZK circuits."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .hashes import SNARK_SCALAR_FIELD, blake3_to_field_element
from .poseidon_bn128 import poseidon_hash_bn128


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


def _poseidon_hash_pairs(pairs: list[tuple[int, int]]) -> list[int]:
    """
    Hash a list of (left, right) field-element pairs with BN128 Poseidon(2).

    Default backend: ``protocol.poseidon_bn128.poseidon_hash_bn128`` — a pure
    Python implementation using the exact same round constants and MDS matrix
    as circomlibjs / the circom circuit, so Python Merkle roots are
    bit-for-bit identical to what the circuit computes.

    When ``OLY_POSEIDON_BACKEND=js`` is set, all pairs are sent to the
    persistent Node.js process in a **single IPC round-trip** via
    ``batch_hash2``, keeping the JS backend at O(depth) calls for a full tree.

    Zero-leaf sentinel semantics are **not** affected by either backend; zero
    leaves remain the raw field element 0, never Poseidon(0, 0).
    """
    from . import poseidon_js  # local import avoids circular imports at module load

    if poseidon_js.backend_enabled():
        reduced = [(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD) for a, b in pairs]
        return poseidon_js.batch_compute_poseidon2(reduced)

    return [poseidon_hash_bn128(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD) for a, b in pairs]


def _poseidon_hash(left: int, right: int) -> int:
    """Single-pair convenience wrapper around :func:`_poseidon_hash_pairs`."""
    return _poseidon_hash_pairs([(left, right)])[0]


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
        """
        Initialize a Poseidon Merkle tree.

        Args:
            leaves: Leaf values (bytes hashed with BLAKE3, decimal strings, or field ints)
            depth: Optional fixed depth; pads with zeros to 2**depth leaves

        Raises:
            ValueError: If no leaves provided or too many leaves for specified depth
        """
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
        """
        Hash a level upwards, duplicating the final leaf when odd.

        All pairs in the level are hashed in a single backend call so that
        the JS backend needs only one subprocess per level, not one per pair.
        """
        if len(level) == 1:
            return [level[0]]

        padded = list(level)
        if len(padded) % 2 == 1:
            padded.append(padded[-1])

        pairs = [(padded[i], padded[i + 1]) for i in range(0, len(padded), 2)]
        return _poseidon_hash_pairs(pairs)

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

        All pairs at each level are hashed in a single backend call, keeping
        the JS backend at O(depth) subprocess calls for the entire proof.
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

            # Hash all pairs in the level in one batch call.
            pairs = [(padded[i], padded[i + 1]) for i in range(0, len(padded), 2)]
            level = _poseidon_hash_pairs(pairs)
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
