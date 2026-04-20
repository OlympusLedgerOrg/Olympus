"""
Constant-Depth Hierarchical Sparse Tree (CD-HS-ST)

Design rationale
----------------
The original SSMF design used *two* authenticated structures:

1. A 256-level per-shard SMT (keyed by ``record_key``).
2. A separate forest layer (a Merkle tree over sorted shard header hashes)
   that committed the set of known shard roots.

Maintaining two structures caused a whole class of concurrency and consistency
bugs (BUG-03, BUG-10) because every append required updating *both* trees
atomically.

The CD-HS-ST collapses the hierarchy into **one** 256-level SMT by pushing the
shard identity into the key space via domain-separated hashing::

    global_key = blake3_derive_key(
        <global SMT context string>,
        len(shard_id) || shard_id || len(record_key) || record_key,
    )

All records across all shards are leaves in a single global SMT.  Shards are
now first-class *namespaces* rather than separate authenticated structures:

* **One tree, one root** — a single ``global_root`` commits to every shard and
  every record.
* **One 256-step walk per append** — half the hashing cost of the old design.
* **No two-tree sync** — the entire BUG-03/BUG-10 class of divergence bugs
  disappears by construction.

Shards still exist as logical entities (in DB columns, API surfaces, indexes,
shard-header metadata), but their *cryptographic* identity is just a namespace
prefix inside the unified key space.

Public API
----------
``CdhssmfTree`` wraps the existing ``SparseMerkleTree`` with shard-aware
methods.  All proof types (``ExistenceProof``, ``NonExistenceProof``) and
verification functions (``verify_proof``, ``verify_nonexistence_proof``,
``verify_unified_proof``) from ``protocol.ssmf`` remain compatible — the only
change is that the 32-byte ``key`` embedded in each proof is a ``global_key``
rather than a bare ``record_key``.
"""

from dataclasses import dataclass

from .hashes import global_key as _derive_global_key, record_key as _derive_record_key
from .ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    diff_sparse_merkle_trees,
    verify_nonexistence_proof,
    verify_proof,
    verify_unified_proof,
)


@dataclass(frozen=True)
class ShardRecord:
    """Logical address of a single record within a shard."""

    shard_id: str
    record_type: str
    record_id: str
    version: int

    def to_global_key(self) -> bytes:
        """Derive the 32-byte global SMT key for this record."""
        rec_key = _derive_record_key(self.record_type, self.record_id, self.version)
        return _derive_global_key(self.shard_id, rec_key)


class CdhssmfTree:
    """
    Single-tree CD-HS-ST: one 256-level SMT covering all shards.

    Usage::

        tree = CdhssmfTree()
        tree.update("acme:2025:budget", record_key_bytes, value_hash_bytes)
        root = tree.get_root()          # single global root
        proof = tree.prove("acme:2025:budget", record_key_bytes)

    The underlying ``SparseMerkleTree`` is accessible via ``tree._smt`` if
    low-level access is required, but callers should prefer the shard-aware
    methods on this class.
    """

    def __init__(self) -> None:
        self._smt = SparseMerkleTree()

    # ------------------------------------------------------------------
    # Core read/write
    # ------------------------------------------------------------------

    def update(
        self,
        shard_id: str,
        rec_key: bytes,
        value_hash: bytes,
        parser_id: str = "fallback@1.0.0",
        canonical_parser_version: str = "v1",
    ) -> None:
        """
        Insert or update a record under a shard namespace.

        Args:
            shard_id:   Logical shard identifier (arbitrary UTF-8 string).
            rec_key:    32-byte record key (from :func:`~protocol.hashes.record_key`).
            value_hash: 32-byte hash of the canonical record bytes.
            parser_id:  Non-empty string identifying the ingest parser and version
                (e.g. ``"docling@2.3.1"``). Defaults to ``"fallback@1.0.0"``.
            canonical_parser_version: Non-empty opaque operator string
                (e.g. ``"v1"``). Defaults to ``"v1"``.
        """
        gk = _derive_global_key(shard_id, rec_key)
        self._smt.update(gk, value_hash, parser_id, canonical_parser_version)

    def get(self, shard_id: str, rec_key: bytes) -> bytes | None:
        """
        Retrieve the stored value hash for a (shard_id, record_key) pair.

        Args:
            shard_id: Logical shard identifier.
            rec_key:  32-byte record key.

        Returns:
            32-byte value hash if the record exists, ``None`` otherwise.
        """
        gk = _derive_global_key(shard_id, rec_key)
        return self._smt.get(gk)

    def get_root(self) -> bytes:
        """
        Return the current 32-byte global root of the unified SMT.

        This single root commits to *all* shards and *all* records.
        """
        return self._smt.get_root()

    # ------------------------------------------------------------------
    # Proofs
    # ------------------------------------------------------------------

    def prove(self, shard_id: str, rec_key: bytes) -> ExistenceProof | NonExistenceProof:
        """
        Generate a proof for a record (existence or non-existence).

        This is the recommended entry point — it treats non-existence as a
        valid cryptographic response rather than an error condition.

        Args:
            shard_id: Logical shard identifier.
            rec_key:  32-byte record key.

        Returns:
            :class:`~protocol.ssmf.ExistenceProof` if the record exists,
            :class:`~protocol.ssmf.NonExistenceProof` otherwise.

        Raises:
            ValueError: Only for invalid inputs (e.g., wrong key length).
        """
        gk = _derive_global_key(shard_id, rec_key)
        return self._smt.prove(gk)

    def prove_existence(self, shard_id: str, rec_key: bytes) -> ExistenceProof:
        """
        Generate a proof that a record exists.

        Raises:
            ValueError: If the record does not exist or inputs are invalid.
        """
        gk = _derive_global_key(shard_id, rec_key)
        return self._smt.prove_existence(gk)

    def prove_nonexistence(self, shard_id: str, rec_key: bytes) -> NonExistenceProof:
        """
        Generate a proof that a record does not exist.

        Raises:
            ValueError: If the record exists or inputs are invalid.
        """
        gk = _derive_global_key(shard_id, rec_key)
        return self._smt.prove_nonexistence(gk)

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(
        self,
        other: "CdhssmfTree",
        key_range_start: bytes | None = None,
        key_range_end: bytes | None = None,
    ) -> dict:
        """
        Compare this tree against *other* at the leaf level.

        Delegates to :func:`~protocol.ssmf.diff_sparse_merkle_trees`.  Returned
        ``SparseMerkleDiffEntry.key`` values are global keys (not shard-prefixed
        record keys).

        Args:
            other:            The tree to compare against.
            key_range_start:  Optional inclusive lower bound for diffing.
            key_range_end:    Optional exclusive upper bound for diffing.

        Returns:
            Dict with ``"added"``, ``"changed"``, ``"removed"`` lists.
        """
        return diff_sparse_merkle_trees(
            self._smt,
            other._smt,
            key_range_start=key_range_start,
            key_range_end=key_range_end,
        )


__all__ = [
    "CdhssmfTree",
    "ShardRecord",
    # Re-export proof types and verifiers so callers can work
    # entirely within the cdhssmf module.
    "ExistenceProof",
    "NonExistenceProof",
    "verify_proof",
    "verify_nonexistence_proof",
    "verify_unified_proof",
]
