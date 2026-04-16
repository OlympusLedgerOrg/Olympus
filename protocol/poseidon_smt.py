"""
Poseidon Sparse Merkle Tree for ZK witness generation - Rust-backed.

This module provides a thin Python wrapper around the Rust Poseidon implementation.
For witness generation in ZK circuits, this delegates to olympus_core.poseidon.

IMPORTANT: This is NOT the authoritative ledger state. protocol/ssmf.py
(BLAKE3 SMT via Rust) is the source of truth. This module is exclusively for
generating witness inputs for non_existence.circom.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from protocol.poseidon import (
    POSEIDON_DOMAIN_LEAF,
    POSEIDON_DOMAIN_NODE,
    SNARK_SCALAR_FIELD,
    poseidon_leaf_hash,
    poseidon_node_hash,
)


if TYPE_CHECKING:
    pass


# Precompute empty hashes for Poseidon sparse Merkle tree (256 levels)
def _precompute_poseidon_empty_hashes(height: int = 256) -> list[int]:
    """Precompute empty node hashes for Poseidon sparse tree."""
    empty = [0]  # Empty leaf sentinel = 0
    for _ in range(height):
        empty.append(poseidon_node_hash(empty[-1], empty[-1]))
    return empty


POSEIDON_EMPTY_HASHES = _precompute_poseidon_empty_hashes()


def _key_to_path_bits(key: bytes) -> list[int]:
    """Convert 32-byte key to 256-bit path (list of 0s and 1s, MSB first)."""
    path = []
    for byte in key:
        for i in range(8):
            bit = (byte >> (7 - i)) & 1
            path.append(bit)
    return path


@dataclass
class PoseidonExistenceProof:
    """Proof that a key-value pair exists in the Poseidon tree."""

    key: bytes
    value: int  # Field element
    siblings: list[int]  # 256 sibling hashes as field elements
    root: int  # Root hash as field element


@dataclass
class PoseidonNonExistenceProof:
    """Proof that a key does not exist in the Poseidon tree."""

    key: bytes
    siblings: list[int]  # 256 sibling hashes
    root: int


class PoseidonSMT:
    """Poseidon Sparse Merkle Tree for ZK witness generation.

    This is a 256-height sparse Merkle tree using Poseidon hashes
    for compatibility with Circom circuits.
    """

    def __init__(self) -> None:
        self._leaves: dict[bytes, int] = {}  # key -> value (field element)
        self._nodes: dict[tuple[int, ...], int] = {}  # path -> hash

    @property
    def leaves(self) -> dict[bytes, int]:
        """Return the leaf store."""
        return self._leaves

    def get_root(self) -> int:
        """Get the current root hash."""
        if not self._nodes:
            return POSEIDON_EMPTY_HASHES[256]
        return self._nodes.get((), POSEIDON_EMPTY_HASHES[256])

    def get(self, key: bytes) -> int | None:
        """Get value for key, or None if not present."""
        return self._leaves.get(key)

    def update(self, key: bytes, value: int) -> None:
        """Insert or update a key-value pair.

        Args:
            key: 32-byte key
            value: Value as field element (integer)
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        self._leaves[key] = value
        path = tuple(_key_to_path_bits(key))

        # Compute key as field element for leaf hash
        key_int = int.from_bytes(key, "big") % SNARK_SCALAR_FIELD

        # Compute leaf hash
        leaf_hash = poseidon_leaf_hash(key_int, value)
        self._nodes[path] = leaf_hash

        # Recompute path to root
        current_hash = leaf_hash
        for level in range(255, -1, -1):
            current_path = path[:level + 1]
            bit = path[level]

            # Get sibling hash
            sibling_path = current_path[:-1] + (1 - bit,)
            sibling_hash = self._nodes.get(sibling_path, POSEIDON_EMPTY_HASHES[255 - level])

            # Compute parent hash
            if bit == 0:
                parent_hash = poseidon_node_hash(current_hash, sibling_hash)
            else:
                parent_hash = poseidon_node_hash(sibling_hash, current_hash)

            # Store parent
            parent_path = current_path[:-1]
            self._nodes[parent_path] = parent_hash
            current_hash = parent_hash

    def prove_existence(self, key: bytes) -> PoseidonExistenceProof:
        """Generate an existence proof for a key.

        Args:
            key: 32-byte key that must exist in the tree

        Returns:
            PoseidonExistenceProof with siblings

        Raises:
            ValueError: If key does not exist
        """
        if key not in self._leaves:
            raise ValueError(f"Key {key.hex()} does not exist in tree")

        value = self._leaves[key]
        path = tuple(_key_to_path_bits(key))

        siblings = []
        for level in range(256):
            current_path = path[:level + 1]
            bit = path[level]
            sibling_path = current_path[:-1] + (1 - bit,)
            sibling_hash = self._nodes.get(sibling_path, POSEIDON_EMPTY_HASHES[255 - level])
            siblings.append(sibling_hash)

        return PoseidonExistenceProof(
            key=key,
            value=value,
            siblings=siblings,
            root=self.get_root(),
        )

    def prove_nonexistence(self, key: bytes) -> PoseidonNonExistenceProof:
        """Generate a non-existence proof for a key.

        Args:
            key: 32-byte key that must NOT exist in the tree

        Returns:
            PoseidonNonExistenceProof with siblings

        Raises:
            ValueError: If key exists
        """
        if key in self._leaves:
            raise ValueError(f"Key {key.hex()} exists in tree")

        path = tuple(_key_to_path_bits(key))

        siblings = []
        for level in range(256):
            current_path = path[:level + 1]
            bit = path[level]
            sibling_path = current_path[:-1] + (1 - bit,)
            sibling_hash = self._nodes.get(sibling_path, POSEIDON_EMPTY_HASHES[255 - level])
            siblings.append(sibling_hash)

        return PoseidonNonExistenceProof(
            key=key,
            siblings=siblings,
            root=self.get_root(),
        )


__all__ = [
    "POSEIDON_EMPTY_HASHES",
    "POSEIDON_DOMAIN_LEAF",
    "POSEIDON_DOMAIN_NODE",
    "PoseidonSMT",
    "PoseidonExistenceProof",
    "PoseidonNonExistenceProof",
]
