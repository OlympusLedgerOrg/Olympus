"""
Sparse Merkle Forest implementation for Olympus

This module implements a 256-height sparse Merkle tree with precomputed empty hashes
for efficient storage and proof generation.

IMPORTANT: Non-existence semantics
----------------------------------
The `prove()` method treats non-existence as a valid cryptographic response,
not as an error. This is critical for API/service layers that need to return
deterministic proofs without raising exceptions for missing keys.

- Use `prove(key)` for unified proof generation (returns ExistenceProof or NonExistenceProof)
- Use `prove_existence(key)` only when you know the key exists (raises ValueError if not)
- Use `prove_nonexistence(key)` only when you know the key doesn't exist (raises ValueError if it does)
"""

from dataclasses import dataclass

import blake3

from .hashes import leaf_hash, node_hash


# Domain-separated empty leaf sentinel.  This replaces the former all-zeros
# sentinel to prevent confusion with naturally-occurring zero values.
EMPTY_LEAF = blake3.blake3(b"OLY:EMPTY-LEAF:V1").digest()


# Precompute empty hashes for sparse Merkle tree (256 levels)
# EMPTY[i] = hash of empty subtree at height i
def _precompute_empty_hashes(height: int = 256) -> list[bytes]:
    """Precompute empty node hashes for sparse tree."""
    empty = [EMPTY_LEAF]
    for i in range(height):
        empty.append(node_hash(empty[i], empty[i]))
    return empty


EMPTY_HASHES = _precompute_empty_hashes()


def _key_to_path_bits(key: bytes) -> list[int]:
    """Convert 32-byte key to 256-bit path (list of 0s and 1s)."""
    path = []
    for byte in key:
        for i in range(8):
            # Extract bit (MSB first)
            bit = (byte >> (7 - i)) & 1
            path.append(bit)
    return path


@dataclass
class ExistenceProof:
    """Proof that a key-value pair exists in the tree."""

    key: bytes  # 32-byte key
    value_hash: bytes  # 32-byte hash of the value
    siblings: list[bytes]  # Sibling hashes along path to root (256 siblings)
    root_hash: bytes  # 32-byte root hash

    def to_dict(self) -> dict[str, bool | str | list[str]]:
        """Convert proof to dictionary for JSON serialization."""
        return {
            "exists": True,
            "key": self.key.hex(),
            "value_hash": self.value_hash.hex(),
            "siblings": [s.hex() for s in self.siblings],
            "root_hash": self.root_hash.hex(),
        }


@dataclass
class NonExistenceProof:
    """Proof that a key does not exist in the tree."""

    key: bytes  # 32-byte key
    siblings: list[bytes]  # Sibling hashes along path to empty leaf
    root_hash: bytes  # 32-byte root hash

    def to_dict(self) -> dict[str, bool | str | list[str]]:
        """Convert proof to dictionary for JSON serialization."""
        return {
            "exists": False,
            "key": self.key.hex(),
            "siblings": [s.hex() for s in self.siblings],
            "root_hash": self.root_hash.hex(),
        }


@dataclass(frozen=True)
class SparseMerkleDiffEntry:
    """A single key-level difference between two sparse Merkle tree states."""

    key: bytes
    before_value_hash: bytes | None
    after_value_hash: bytes | None

    def to_dict(self) -> dict[str, str | None]:
        """Convert diff entry to a JSON-serializable dictionary."""
        return {
            "key": self.key.hex(),
            "before_value_hash": None
            if self.before_value_hash is None
            else self.before_value_hash.hex(),
            "after_value_hash": None
            if self.after_value_hash is None
            else self.after_value_hash.hex(),
        }


class SparseMerkleTree:
    """
    A 256-height sparse Merkle tree for efficient key-value storage.

    Keys are 32 bytes, values are 32-byte hashes.
    The tree is append-only: versioning is handled by incorporating
    version into the key derivation (via record_key from hashes module).
    """

    def __init__(self) -> None:
        """Initialize an empty sparse Merkle tree."""
        # Store only non-empty nodes: path -> hash
        self.nodes: dict[tuple[int, ...], bytes] = {}
        # Store leaves: key -> value_hash
        self.leaves: dict[bytes, bytes] = {}

    def get_root(self) -> bytes:
        """Get the root hash of the tree."""
        if not self.nodes and not self.leaves:
            # Empty tree
            return EMPTY_HASHES[256]

        # Compute root by traversing from stored nodes
        if () in self.nodes:
            return self.nodes[()]
        return EMPTY_HASHES[256]

    def get(self, key: bytes) -> bytes | None:
        """
        Get the value hash for a key.

        Args:
            key: 32-byte key

        Returns:
            32-byte value hash if exists, None otherwise
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        return self.leaves.get(key)

    def update(self, key: bytes, value_hash: bytes) -> None:
        """
        Update or insert a key-value pair.

        Args:
            key: 32-byte key
            value_hash: 32-byte hash of the value
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        if len(value_hash) != 32:
            raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")

        # Store leaf
        self.leaves[key] = value_hash

        # Compute path from key (each bit determines left/right)
        path = self._key_to_path(key)

        # Update tree from leaf to root
        # Level 0 = first bit, Level 255 = last bit (leaf level)
        current_hash = leaf_hash(key, value_hash)

        # Go from leaf level (255) up to root (0)
        for level in range(256):
            # At level L (counting from leaf=0), we need sibling at height L
            # The sibling's path differs in the bit at position (255-level)
            bit_pos = 255 - level
            if bit_pos < 0:
                break  # We've reached the root

            sibling_path = self._sibling_path(path[: bit_pos + 1])
            sibling_hash = (
                self.nodes[sibling_path] if sibling_path in self.nodes else EMPTY_HASHES[level]
            )

            # Compute parent hash
            if path[bit_pos] == 0:
                # Current is left child
                parent_hash = node_hash(current_hash, sibling_hash)
            else:
                # Current is right child
                parent_hash = node_hash(sibling_hash, current_hash)

            # Store parent at path up to bit_pos
            parent_path = () if bit_pos == 0 else path[:bit_pos]
            self.nodes[parent_path] = parent_hash
            current_hash = parent_hash

    def prove_existence(self, key: bytes) -> ExistenceProof:
        """
        Generate a proof that a key exists in the tree.

        Args:
            key: 32-byte key to prove

        Returns:
            Existence proof

        Raises:
            ValueError: If key does not exist
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        if key not in self.leaves:
            raise ValueError("Key does not exist in tree")

        value_hash = self.leaves[key]
        path = self._key_to_path(key)
        siblings = self._collect_siblings(path)

        return ExistenceProof(
            key=key, value_hash=value_hash, siblings=siblings, root_hash=self.get_root()
        )

    def prove_nonexistence(self, key: bytes) -> NonExistenceProof:
        """
        Generate a proof that a key does not exist in the tree.

        Args:
            key: 32-byte key to prove

        Returns:
            Non-existence proof

        Raises:
            ValueError: If key exists
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        if key in self.leaves:
            raise ValueError("Key exists in tree, cannot prove non-existence")

        path = self._key_to_path(key)
        siblings = self._collect_siblings(path)

        return NonExistenceProof(key=key, siblings=siblings, root_hash=self.get_root())

    def prove(self, key: bytes) -> ExistenceProof | NonExistenceProof:
        """
        Generate a proof for a key (existence or non-existence).

        This is the recommended interface for proof generation as it treats
        non-existence as a valid response rather than an error condition.

        Args:
            key: 32-byte key to prove

        Returns:
            ExistenceProof if key exists, NonExistenceProof if key does not exist

        Raises:
            ValueError: Only for invalid inputs (e.g., wrong key length)
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        if key in self.leaves:
            # Key exists - return existence proof
            value_hash = self.leaves[key]
            path = self._key_to_path(key)
            siblings = self._collect_siblings(path)

            return ExistenceProof(
                key=key, value_hash=value_hash, siblings=siblings, root_hash=self.get_root()
            )
        else:
            # Key does not exist - return non-existence proof
            path = self._key_to_path(key)
            siblings = self._collect_siblings(path)

            return NonExistenceProof(key=key, siblings=siblings, root_hash=self.get_root())

    def _collect_siblings(self, path: tuple[int, ...]) -> list[bytes]:
        """
        Collect sibling hashes along a path from leaf to root.

        Args:
            path: Path as tuple of bits

        Returns:
            List of 256 sibling hashes
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
                siblings.append(EMPTY_HASHES[level])
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


def diff_sparse_merkle_trees(
    before: SparseMerkleTree,
    after: SparseMerkleTree,
    key_range_start: bytes | None = None,
    key_range_end: bytes | None = None,
) -> dict[str, list[SparseMerkleDiffEntry]]:
    """
    Compare two sparse Merkle tree states at the leaf level.

    For large trees with millions of leaves, use key_range_start and key_range_end
    to compute diffs in bounded batches to avoid memory exhaustion.

    Args:
        before: Earlier tree state
        after: Later tree state
        key_range_start: Inclusive lower bound for key range (default: all keys >= 0x00...00)
        key_range_end: Exclusive upper bound for key range (default: all keys < 0xFF...FF)

    Returns:
        Dictionary containing deterministic lists of added, changed, and removed leaves
        within the specified key range
    """

    # Apply key range filter if specified
    def in_range(key: bytes) -> bool:
        if key_range_start is not None and key < key_range_start:
            return False
        if key_range_end is not None and key >= key_range_end:
            return False
        return True

    before_keys = {k for k in before.leaves if in_range(k)}
    after_keys = {k for k in after.leaves if in_range(k)}

    added = [
        SparseMerkleDiffEntry(key=key, before_value_hash=None, after_value_hash=after.leaves[key])
        for key in sorted(after_keys - before_keys)
    ]
    changed = [
        SparseMerkleDiffEntry(
            key=key,
            before_value_hash=before.leaves[key],
            after_value_hash=after.leaves[key],
        )
        for key in sorted(before_keys & after_keys)
        if before.leaves[key] != after.leaves[key]
    ]
    removed = [
        SparseMerkleDiffEntry(key=key, before_value_hash=before.leaves[key], after_value_hash=None)
        for key in sorted(before_keys - after_keys)
    ]

    return {
        "added": added,
        "changed": changed,
        "removed": removed,
    }


def verify_proof(proof: ExistenceProof) -> bool:
    """
    Verify an existence proof.

    Args:
        proof: Existence proof to verify

    Returns:
        True if proof is valid, False otherwise
    """
    if len(proof.key) != 32:
        return False
    if len(proof.value_hash) != 32:
        return False
    if len(proof.siblings) != 256:
        return False
    if len(proof.root_hash) != 32:
        return False

    # Check all siblings are 32 bytes
    for sibling in proof.siblings:
        if len(sibling) != 32:
            return False

    # Compute path from key using shared function
    path = _key_to_path_bits(proof.key)

    # Compute root from leaf
    # Siblings are ordered from leaf to root (level 0, 1, 2...)
    # Path bits are ordered from root to leaf (bit 0, 1, 2...)
    current_hash = leaf_hash(proof.key, proof.value_hash)

    for level in range(256):
        sibling = proof.siblings[level]
        bit_pos = 255 - level  # Map from level to bit position
        current_hash = (
            node_hash(current_hash, sibling)
            if path[bit_pos] == 0
            else node_hash(sibling, current_hash)
        )

    return current_hash == proof.root_hash


def verify_nonexistence_proof(proof: NonExistenceProof) -> bool:
    """
    Verify a non-existence proof using the default hash chain.

    The proof demonstrates that the leaf at the given key position is the
    domain-separated empty sentinel ``EMPTY_LEAF``. Verification reconstructs
    the root by hashing upward from the empty leaf through the provided sibling
    chain and checks that the result matches ``proof.root_hash``.

    The precomputed ``EMPTY_HASHES`` chain ensures that default (empty)
    subtrees have deterministic hashes at every level of the sparse tree.

    Args:
        proof: Non-existence proof to verify

    Returns:
        True if proof is valid, False otherwise
    """
    if len(proof.key) != 32:
        return False
    if len(proof.siblings) != 256:
        return False
    if len(proof.root_hash) != 32:
        return False

    # Check all siblings are 32 bytes
    for sibling in proof.siblings:
        if len(sibling) != 32:
            return False

    # Compute path from key using shared function
    path = _key_to_path_bits(proof.key)

    # For non-existence, we start with empty leaf hash (default hash chain)
    current_hash = EMPTY_HASHES[0]

    for level in range(256):
        sibling = proof.siblings[level]
        bit_pos = 255 - level  # Map from level to bit position
        current_hash = (
            node_hash(current_hash, sibling)
            if path[bit_pos] == 0
            else node_hash(sibling, current_hash)
        )

    return current_hash == proof.root_hash


def verify_unified_proof(proof: ExistenceProof | NonExistenceProof) -> bool:
    """
    Verify a proof (existence or non-existence).

    This is a unified verification function that works with both proof types.

    Args:
        proof: Existence or non-existence proof to verify

    Returns:
        True if proof is valid, False otherwise
    """
    if isinstance(proof, ExistenceProof):
        return verify_proof(proof)
    elif isinstance(proof, NonExistenceProof):
        return verify_nonexistence_proof(proof)
    else:
        return False


def is_existence_proof(proof: ExistenceProof | NonExistenceProof) -> bool:
    """
    Check if a proof is an existence proof.

    Args:
        proof: Proof to check

    Returns:
        True if proof is an ExistenceProof, False if NonExistenceProof
    """
    return isinstance(proof, ExistenceProof)


def is_nonexistence_proof(proof: ExistenceProof | NonExistenceProof) -> bool:
    """
    Check if a proof is a non-existence proof.

    Args:
        proof: Proof to check

    Returns:
        True if proof is a NonExistenceProof, False if ExistenceProof
    """
    return isinstance(proof, NonExistenceProof)
