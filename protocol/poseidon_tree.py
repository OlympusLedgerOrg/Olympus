"""
Poseidon Merkle Tree for document commitments - Rust-backed.

This module provides Poseidon-based Merkle tree operations using the
Rust Poseidon implementation from olympus_core.

Note: This is a compatibility layer. The actual Poseidon computation
is done in Rust via olympus_core.poseidon.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from protocol.poseidon import (
    POSEIDON_DOMAIN_LEAF,
    POSEIDON_DOMAIN_NODE,
    SNARK_SCALAR_FIELD,
    poseidon_hash,
    poseidon_node_hash,
)


# Domain separation constant for document commitments
POSEIDON_DOMAIN_COMMITMENT = 2


def _to_field_int(value: bytes | int) -> int:
    """Convert bytes or int to a field element."""
    if isinstance(value, bytes):
        return int.from_bytes(value, "big") % SNARK_SCALAR_FIELD
    return value % SNARK_SCALAR_FIELD


def poseidon_hash_with_domain(domain: int, value: int) -> int:
    """Compute Poseidon hash with domain separation.

    Args:
        domain: Domain separation constant
        value: Value to hash as field element

    Returns:
        Hash result as field element
    """
    return poseidon_hash(domain, value)


def build_poseidon_witness_inputs(
    tree: PoseidonMerkleTree,
    leaf_index: int,
) -> dict[str, Any]:
    """Build witness inputs for a Poseidon Merkle proof circuit.

    Args:
        tree: The Poseidon Merkle tree
        leaf_index: Index of the leaf to prove

    Returns:
        Dictionary with witness inputs for the circuit
    """
    proof = tree.get_proof(leaf_index)
    return {
        "leaf": str(proof.leaf_hash),
        "pathElements": [str(s) for s in proof.siblings],
        "pathIndices": proof.path_indices,
        "root": str(proof.root),
    }


@dataclass
class PoseidonProof:
    """Merkle inclusion proof using Poseidon hashes."""

    leaf_hash: int
    siblings: list[int]  # Sibling hashes along path to root
    path_indices: list[int]  # 0 = left, 1 = right
    root: int


class PoseidonMerkleTree:
    """Binary Merkle tree using Poseidon hashes.

    This is used for document commitment trees, not the sparse Merkle tree.
    For the 256-height SMT, use PoseidonSMT instead.
    """

    def __init__(self, leaves: list[int] | None = None) -> None:
        """Initialize with optional leaf values.

        Args:
            leaves: List of field elements to use as leaves
        """
        self._leaves: list[int] = list(leaves) if leaves else []
        self._tree: list[list[int]] = []
        if self._leaves:
            self._build_tree()

    def _build_tree(self) -> None:
        """Build the tree from leaves."""
        if not self._leaves:
            self._tree = []
            return

        # Pad to power of 2
        n = len(self._leaves)
        next_pow2 = 1
        while next_pow2 < n:
            next_pow2 *= 2

        padded = self._leaves + [0] * (next_pow2 - n)

        self._tree = [padded]
        current = padded

        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else 0
                parent = poseidon_node_hash(left, right)
                next_level.append(parent)
            self._tree.append(next_level)
            current = next_level

    def add_leaf(self, value: int) -> None:
        """Add a leaf and rebuild the tree."""
        self._leaves.append(value)
        self._build_tree()

    def get_root(self) -> int:
        """Get the root hash."""
        if not self._tree:
            return 0
        return self._tree[-1][0]

    @property
    def root(self) -> int:
        """Alias for get_root()."""
        return self.get_root()

    def get_proof(self, index: int) -> PoseidonProof:
        """Generate a Merkle proof for the leaf at index.

        Args:
            index: Leaf index (0-based)

        Returns:
            PoseidonProof with siblings and path

        Raises:
            IndexError: If index is out of bounds
        """
        if not self._tree or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of bounds")

        siblings = []
        path_indices = []
        current_idx = index

        for level in self._tree[:-1]:  # All levels except root
            sibling_idx = current_idx ^ 1  # XOR to get sibling
            if sibling_idx < len(level):
                siblings.append(level[sibling_idx])
            else:
                siblings.append(0)
            path_indices.append(current_idx & 1)  # 0 if left, 1 if right
            current_idx //= 2

        # Pad to next power of 2 levels
        n = len(self._leaves)
        next_pow2 = 1
        depth = 0
        while next_pow2 < n:
            next_pow2 *= 2
            depth += 1

        leaf_hash = self._tree[0][index]

        return PoseidonProof(
            leaf_hash=leaf_hash,
            siblings=siblings,
            path_indices=path_indices,
            root=self.get_root(),
        )

    @staticmethod
    def verify_proof(proof: PoseidonProof) -> bool:
        """Verify a Merkle proof.

        Args:
            proof: The proof to verify

        Returns:
            True if valid, False otherwise
        """
        current = proof.leaf_hash

        for sibling, is_right in zip(proof.siblings, proof.path_indices):
            if is_right:
                current = poseidon_node_hash(sibling, current)
            else:
                current = poseidon_node_hash(current, sibling)

        return current == proof.root


def compute_poseidon_commitment(data: bytes) -> int:
    """Compute a Poseidon commitment for document data.

    Uses domain separation for commitments.

    Args:
        data: Document data to commit

    Returns:
        Commitment as field element
    """
    data_field = _to_field_int(data)
    domain = POSEIDON_DOMAIN_COMMITMENT
    return poseidon_hash(domain, data_field)


__all__ = [
    "POSEIDON_DOMAIN_COMMITMENT",
    "POSEIDON_DOMAIN_LEAF",
    "POSEIDON_DOMAIN_NODE",
    "PoseidonMerkleTree",
    "PoseidonProof",
    "build_poseidon_witness_inputs",
    "compute_poseidon_commitment",
    "poseidon_hash_with_domain",
    "_to_field_int",
]
