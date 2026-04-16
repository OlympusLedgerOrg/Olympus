"""
Poseidon Sparse Merkle Tree for ZK witness generation.

This module implements a 256-height Poseidon SMT using domain-separated
Poseidon(2) hashes for leaf and internal node computations, matching the
circuit behavior in non_existence.circom exactly. It is a parallel tree
to protocol/ssmf.py (BLAKE3 SMT) — built from the same key/value pairs
to generate ZK witness inputs.

IMPORTANT: This is NOT the authoritative ledger state. protocol/ssmf.py
(BLAKE3 SMT) is the source of truth. This module is exclusively for
generating witness inputs for non_existence.circom.

Key properties:
- Tree height: 256
- Key path: MSB-first bit decomposition (identical to ssmf._key_to_path_bits)
- Empty leaf sentinel: 0 (matches non_existence.circom: merkle.leaf <== 0)
- Node hash: domain-separated Poseidon — Poseidon(Poseidon(DOMAIN_NODE, left), right)
- Leaf hash: domain-separated Poseidon — Poseidon(Poseidon(DOMAIN_LEAF, key_int), value_int)
"""

from __future__ import annotations

from dataclasses import dataclass

from .hashes import SNARK_SCALAR_FIELD
from .poseidon_bn128 import poseidon_hash_bn128


# Domain separation constants for Poseidon hashing.
# These MUST match the corresponding constants in the Circom circuits
# (proofs/circuits/lib/merkleProof.circom and non_existence.circom).
POSEIDON_DOMAIN_LEAF = 0
POSEIDON_DOMAIN_NODE = 1


def _poseidon_hash_leaf(a: int, b: int) -> int:
    """Domain-separated Poseidon leaf hash: Poseidon(Poseidon(DOMAIN_LEAF, a), b)."""
    return poseidon_hash_bn128(poseidon_hash_bn128(POSEIDON_DOMAIN_LEAF, a), b)


def _poseidon_hash_node(left: int, right: int) -> int:
    """Domain-separated Poseidon node hash: Poseidon(Poseidon(DOMAIN_NODE, left), right)."""
    return poseidon_hash_bn128(poseidon_hash_bn128(POSEIDON_DOMAIN_NODE, left), right)


# Precompute empty hashes for Poseidon sparse Merkle tree (256 levels)
# EMPTY[i] = hash of empty subtree at height i
def _precompute_poseidon_empty_hashes(height: int = 256) -> list[int]:
    """Precompute empty node hashes for Poseidon sparse tree."""
    empty = [0]  # Empty leaf sentinel (matches non_existence.circom)
    for i in range(height):
        empty.append(_poseidon_hash_node(empty[i], empty[i]))
    return empty


POSEIDON_EMPTY_HASHES = _precompute_poseidon_empty_hashes()


def _key_to_path_bits(key: bytes) -> list[int]:
    """
    Convert 32-byte key to 256-bit path (list of 0s and 1s).

    MSB-first bit extraction — identical to protocol/ssmf._key_to_path_bits
    and matching the derivation logic in non_existence.circom.
    """
    path = []
    for byte in key:
        for i in range(8):
            # Extract bit (MSB first)
            bit = (byte >> (7 - i)) & 1
            path.append(bit)
    return path


@dataclass
class PoseidonNonExistenceWitness:
    """Witness inputs for non_existence.circom."""

    root: str  # Poseidon SMT root as decimal string
    key: list[str]  # 32 field elements, each in [0, 255]
    path_elements: list[str]  # 256 sibling hashes as decimal strings


class PoseidonSMT:
    """
    A 256-height Poseidon sparse Merkle tree for ZK witness generation.

    Keys are 32 bytes, values are field elements (int).
    All hashing uses domain-separated Poseidon(2) matching non_existence.circom.
    """

    def __init__(self) -> None:
        """Initialize an empty Poseidon sparse Merkle tree."""
        # Store only non-empty nodes: path -> hash (int)
        self.nodes: dict[tuple[int, ...], int] = {}
        # Store leaves: key -> value (int)
        self.leaves: dict[bytes, int] = {}

    def get_root(self) -> int:
        """Get the root hash of the tree as a field element."""
        if not self.nodes and not self.leaves:
            # Empty tree
            return POSEIDON_EMPTY_HASHES[256]

        # Compute root by traversing from stored nodes
        if () in self.nodes:
            return self.nodes[()]
        return POSEIDON_EMPTY_HASHES[256]

    def get(self, key: bytes) -> int | None:
        """
        Get the value for a key.

        Args:
            key: 32-byte key

        Returns:
            Field element value if exists, None otherwise
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        return self.leaves.get(key)

    def update(self, key: bytes, value: int) -> None:
        """
        Update or insert a key-value pair.

        Args:
            key: 32-byte key
            value: Field element value (int)
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        # Reduce value to field
        value = value % SNARK_SCALAR_FIELD

        # Store leaf
        self.leaves[key] = value

        # Compute path from key (each bit determines left/right)
        path = self._key_to_path(key)

        # Compute leaf hash: DomainPoseidon(DOMAIN_LEAF, key_int, value_int)
        key_int = int.from_bytes(key, byteorder="big") % SNARK_SCALAR_FIELD
        current_hash = _poseidon_hash_leaf(key_int, value)

        # Go from leaf level (255) up to root (0)
        for level in range(256):
            # At level L (counting from leaf=0), we need sibling at height L
            # The sibling's path differs in the bit at position (255-level)
            bit_pos = 255 - level
            if bit_pos < 0:
                break  # We've reached the root

            sibling_path = self._sibling_path(path[: bit_pos + 1])
            sibling_hash = (
                self.nodes[sibling_path]
                if sibling_path in self.nodes
                else POSEIDON_EMPTY_HASHES[level]
            )

            # Compute parent hash using domain-separated Poseidon(2)
            if path[bit_pos] == 0:
                # Current is left child
                parent_hash = _poseidon_hash_node(current_hash, sibling_hash)
            else:
                # Current is right child
                parent_hash = _poseidon_hash_node(sibling_hash, current_hash)

            # Store parent at path up to bit_pos
            parent_path = () if bit_pos == 0 else path[:bit_pos]
            self.nodes[parent_path] = parent_hash % SNARK_SCALAR_FIELD
            current_hash = parent_hash % SNARK_SCALAR_FIELD

    def prove_nonexistence(self, key: bytes) -> PoseidonNonExistenceWitness:
        """
        Generate witness inputs for non_existence.circom.

        Args:
            key: 32-byte key to prove non-existence

        Returns:
            Witness with root, key bytes, and path elements

        Raises:
            ValueError: If key exists in tree
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        if key in self.leaves:
            raise ValueError("Key exists in tree, cannot prove non-existence")

        path = self._key_to_path(key)
        siblings = self._collect_siblings(path)

        # Convert key to 32 field elements (one per byte)
        key_fields = [str(b) for b in key]

        return PoseidonNonExistenceWitness(
            root=str(self.get_root()),
            key=key_fields,
            path_elements=[str(s) for s in siblings],
        )

    def _collect_siblings(self, path: tuple[int, ...]) -> list[int]:
        """
        Collect sibling hashes along a path from leaf to root.

        Args:
            path: Path as tuple of bits

        Returns:
            List of 256 sibling hashes (field elements)
        """
        siblings = []
        for level in range(256):
            bit_pos = 255 - level
            if bit_pos < 0:
                break

            sibling_path = self._sibling_path(path[: bit_pos + 1])
            if sibling_path in self.nodes:
                siblings.append(self.nodes[sibling_path])
            else:
                siblings.append(POSEIDON_EMPTY_HASHES[level])
        return siblings

    def _key_to_path(self, key: bytes) -> tuple[int, ...]:
        """Convert 32-byte key to 256-bit path (tuple of 0s and 1s)."""
        return tuple(_key_to_path_bits(key))

    def _sibling_path(self, path: tuple[int, ...]) -> tuple[int, ...]:
        """Get the path of the sibling node."""
        if not path:
            raise ValueError("Cannot get sibling of root")
        # Flip the last bit
        return path[:-1] + (1 - path[-1],)


def verify_poseidon_nonexistence_witness(witness: PoseidonNonExistenceWitness) -> bool:
    """
    Verify a Poseidon non-existence witness using circuit-style reconstruction.

    This is the critical soundness test: if this passes, a real snarkjs proof
    generated from the witness will verify on-chain.

    Args:
        witness: Non-existence witness to verify

    Returns:
        True if witness reconstructs root correctly, False otherwise
    """
    if len(witness.key) != 32:
        return False
    if len(witness.path_elements) != 256:
        return False

    # Convert key bytes back to path bits (MSB-first)
    key_bytes = bytes(int(k) for k in witness.key)
    path_bits = _key_to_path_bits(key_bytes)

    # Start with empty leaf sentinel (0)
    current = 0

    # Reconstruct root using exact circuit logic (domain-separated)
    # Siblings are ordered from leaf to root (level 0, 1, 2...)
    # Path bits are ordered from root to leaf (bit 0, 1, 2...)
    for level in range(256):
        sibling = int(witness.path_elements[level])
        bit_pos = 255 - level  # Map from level to bit position
        bit = path_bits[bit_pos]

        if bit == 0:
            current = _poseidon_hash_node(current, sibling)
        else:
            current = _poseidon_hash_node(sibling, current)
        current %= SNARK_SCALAR_FIELD

    return str(current) == witness.root
