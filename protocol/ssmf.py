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

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

import blake3

from .hashes import leaf_hash, node_hash


# ---------------------------------------------------------------------------
# Optional Rust SMT acceleration — import from olympus_core if built,
# fall back to the pure-Python SparseMerkleTree defined below.
# ---------------------------------------------------------------------------
try:
    from olympus_core import RustSparseMerkleTree as _RustSMT

    _RUST_SMT_AVAILABLE = True
except ImportError:
    _RUST_SMT_AVAILABLE = False


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
    parser_id: str  # Parser identity bound into leaf hash (ADR-0003)
    canonical_parser_version: str  # Canonical parser version bound into leaf hash (ADR-0003)
    siblings: list[bytes]  # Sibling hashes along path to root (256 siblings)
    root_hash: bytes  # 32-byte root hash

    def to_dict(self) -> dict[str, bool | str | list[str]]:
        """Convert proof to dictionary for JSON serialization."""
        return {
            "exists": True,
            "key": self.key.hex(),
            "value_hash": self.value_hash.hex(),
            "parser_id": self.parser_id,
            "canonical_parser_version": self.canonical_parser_version,
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
        # Store leaves: key -> (value_hash, parser_id, canonical_parser_version).
        # The parser fields are bound into the leaf hash domain per ADR-0003.
        self._leaf_records: dict[bytes, tuple[bytes, str, str]] = {}
        # Cached snapshot of ``leaves`` (key -> value_hash) to avoid rebuilding
        # on every read. Invalidated by ``update`` when ``_leaf_records``
        # changes; see ADR-0003 review feedback. Wrapped in a read-only
        # MappingProxyType before exposure so callers cannot mutate internal
        # state.
        self._leaves_cache: MappingProxyType[bytes, bytes] | None = None

    @property
    def leaves(self) -> Mapping[bytes, bytes]:
        """Read-only snapshot mapping of key → value_hash.

        Returned for backward compatibility; per-leaf parser metadata is held
        separately in ``_leaf_records`` and surfaced via proofs.

        The snapshot is cached and returned directly on subsequent reads
        until ``update`` mutates ``_leaf_records``. The returned mapping is
        a read-only view (``MappingProxyType``); callers that need a mutable
        or stable-across-writes copy must call ``dict(tree.leaves)``.
        """
        cache = self._leaves_cache
        if cache is None:
            cache = MappingProxyType({k: v for k, (v, _, _) in self._leaf_records.items()})
            self._leaves_cache = cache
        return cache

    def get_root(self) -> bytes:
        """Get the root hash of the tree."""
        if not self.nodes and not self._leaf_records:
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
        record = self._leaf_records.get(key)
        if record is None:
            return None
        return record[0]

    def update(
        self,
        key: bytes,
        value_hash: bytes,
        parser_id: str,
        canonical_parser_version: str,
    ) -> None:
        """
        Update or insert a key-value pair.

        Per ADR-0003, ``parser_id`` and ``canonical_parser_version`` are
        bound into the leaf hash domain and must both be non-empty.

        Args:
            key: 32-byte key
            value_hash: 32-byte hash of the value
            parser_id: Parser identity, e.g. ``"docling@2.3.1"``.
            canonical_parser_version: Operator-controlled stable version,
                e.g. ``"v1"``.
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        if len(value_hash) != 32:
            raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")
        if not parser_id:
            raise ValueError("parser_id must be a non-empty string")
        if not canonical_parser_version:
            raise ValueError("canonical_parser_version must be a non-empty string")

        # Store leaf together with the parser provenance bound into the
        # leaf hash domain (ADR-0003).
        self._leaf_records[key] = (value_hash, parser_id, canonical_parser_version)
        # Invalidate the ``leaves`` snapshot cache; it will be lazily
        # rebuilt on the next read.
        self._leaves_cache = None

        # Compute path from key (each bit determines left/right)
        path = self._key_to_path(key)

        # Update tree from leaf to root
        # Level 0 = first bit, Level 255 = last bit (leaf level)
        current_hash = leaf_hash(key, value_hash, parser_id, canonical_parser_version)

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

        record = self._leaf_records.get(key)
        if record is None:
            raise ValueError("Key does not exist in tree")

        value_hash, parser_id, canonical_parser_version = record
        path = self._key_to_path(key)
        siblings = self._collect_siblings(path)

        return ExistenceProof(
            key=key,
            value_hash=value_hash,
            parser_id=parser_id,
            canonical_parser_version=canonical_parser_version,
            siblings=siblings,
            root_hash=self.get_root(),
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

        if key in self._leaf_records:
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

        record = self._leaf_records.get(key)
        if record is not None:
            value_hash, parser_id, canonical_parser_version = record
            path = self._key_to_path(key)
            siblings = self._collect_siblings(path)

            return ExistenceProof(
                key=key,
                value_hash=value_hash,
                parser_id=parser_id,
                canonical_parser_version=canonical_parser_version,
                siblings=siblings,
                root_hash=self.get_root(),
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


# Preserve pure-Python implementation for tests that need internal methods.
PurePythonSparseMerkleTree = SparseMerkleTree


# ---------------------------------------------------------------------------
# Rust-backed drop-in replacement (when the extension is available)
# ---------------------------------------------------------------------------
if _RUST_SMT_AVAILABLE:

    class _RustBackedSparseMerkleTree:
        """Drop-in replacement for SparseMerkleTree backed by Rust via PyO3."""

        def __init__(self) -> None:
            self._inner = _RustSMT()

        @property
        def leaves(self) -> dict[bytes, bytes]:
            return self._inner.leaves  # type: ignore[no-any-return]

        @property
        def nodes(self) -> dict[tuple[int, ...], bytes]:
            return self._inner.nodes  # type: ignore[no-any-return]

        def get_root(self) -> bytes:
            return self._inner.get_root()  # type: ignore[no-any-return]

        def get(self, key: bytes) -> bytes | None:
            return self._inner.get(key)  # type: ignore[no-any-return]

        def update(
            self,
            key: bytes,
            value_hash: bytes,
            parser_id: str,
            canonical_parser_version: str,
        ) -> None:
            self._inner.update(key, value_hash, parser_id, canonical_parser_version)

        def prove_existence(self, key: bytes) -> ExistenceProof:
            (
                value_hash,
                parser_id,
                canonical_parser_version,
                siblings,
                root_hash,
            ) = self._inner.prove_existence(key)
            return ExistenceProof(
                key=key,
                value_hash=value_hash,
                parser_id=parser_id,
                canonical_parser_version=canonical_parser_version,
                siblings=siblings,
                root_hash=root_hash,
            )

        def prove_nonexistence(self, key: bytes) -> NonExistenceProof:
            siblings, root_hash = self._inner.prove_nonexistence(key)
            return NonExistenceProof(
                key=key,
                siblings=siblings,
                root_hash=root_hash,
            )

        def prove(self, key: bytes) -> ExistenceProof | NonExistenceProof:
            if self.get(key) is not None:
                return self.prove_existence(key)
            return self.prove_nonexistence(key)

    # Shadow the pure-Python class so all importers get the Rust-backed version.
    SparseMerkleTree = _RustBackedSparseMerkleTree  # type: ignore[assignment,misc]


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

    before_leaves = before.leaves
    after_leaves = after.leaves

    before_keys = {k for k in before_leaves if in_range(k)}
    after_keys = {k for k in after_leaves if in_range(k)}

    added = [
        SparseMerkleDiffEntry(key=key, before_value_hash=None, after_value_hash=after_leaves[key])
        for key in sorted(after_keys - before_keys)
    ]
    changed = [
        SparseMerkleDiffEntry(
            key=key,
            before_value_hash=before_leaves[key],
            after_value_hash=after_leaves[key],
        )
        for key in sorted(before_keys & after_keys)
        if before_leaves[key] != after_leaves[key]
    ]
    removed = [
        SparseMerkleDiffEntry(key=key, before_value_hash=before_leaves[key], after_value_hash=None)
        for key in sorted(before_keys - after_keys)
    ]

    return {
        "added": added,
        "changed": changed,
        "removed": removed,
    }


def verify_proof(
    proof: ExistenceProof,
    expected_root: bytes | None = None,
) -> bool:
    """
    Verify an existence proof.

    Args:
        proof: Existence proof to verify
        expected_root: When provided, the proof's root_hash is checked against
            this value before path reconstruction. If they don't match, the
            function returns False immediately. Callers should pass the root
            from a signed shard header to ensure the proof is anchored to an
            authenticated root.

    Returns:
        True if proof is valid, False otherwise
    """
    if expected_root is not None and proof.root_hash != expected_root:
        return False

    if len(proof.key) != 32:
        return False
    if len(proof.value_hash) != 32:
        return False
    if not proof.parser_id:
        return False
    if not proof.canonical_parser_version:
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
    current_hash = leaf_hash(
        proof.key,
        proof.value_hash,
        proof.parser_id,
        proof.canonical_parser_version,
    )

    for level in range(256):
        sibling = proof.siblings[level]
        bit_pos = 255 - level  # Map from level to bit position
        current_hash = (
            node_hash(current_hash, sibling)
            if path[bit_pos] == 0
            else node_hash(sibling, current_hash)
        )

    return current_hash == proof.root_hash


def verify_nonexistence_proof(
    proof: NonExistenceProof,
    expected_root: bytes | None = None,
) -> bool:
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
        expected_root: When provided, the proof's root_hash is checked against
            this value before path reconstruction. If they don't match, the
            function returns False immediately. Callers should pass the root
            from a signed shard header to ensure the proof is anchored to an
            authenticated root.

    Security contract:
        This function verifies mathematical consistency only. Callers MUST
        additionally verify that ``proof.root_hash`` is an authenticated root
        (for example, by matching it against a signed shard header) before
        treating non-existence as authoritative. When ``expected_root`` is
        provided, this check is performed automatically.

    Returns:
        True if proof is valid, False otherwise
    """
    if expected_root is not None and proof.root_hash != expected_root:
        return False

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


def verify_unified_proof(
    proof: ExistenceProof | NonExistenceProof,
    expected_root: bytes | None = None,
) -> bool:
    """
    Verify a proof (existence or non-existence).

    This is a unified verification function that works with both proof types.

    Args:
        proof: Existence or non-existence proof to verify
        expected_root: When provided, the proof's root_hash is checked against
            this value before path reconstruction. Passed through to the
            underlying verification function.

    Returns:
        True if proof is valid, False otherwise
    """
    if isinstance(proof, ExistenceProof):
        return verify_proof(proof, expected_root=expected_root)
    elif isinstance(proof, NonExistenceProof):
        return verify_nonexistence_proof(proof, expected_root=expected_root)
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
