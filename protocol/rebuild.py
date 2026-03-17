"""
Deterministic Merkle rebuild helpers for ledger journal recovery.
"""

from __future__ import annotations

from .canonical_json import canonical_json_bytes
from .ledger import LedgerEntry
from .merkle import MerkleTree, ct_merkle_root, merkle_leaf_hash


def _entry_canonical_bytes(entry: LedgerEntry) -> bytes:
    """Return canonical bytes for a ledger entry."""
    return canonical_json_bytes(entry.to_dict())


def rebuild_merkle_from_journal(entries: list[LedgerEntry]) -> tuple[bytes, MerkleTree]:
    """
    Rebuild a Merkle tree from ordered ledger journal entries.

    Args:
        entries: Ordered append-only ledger entries.

    Returns:
        Tuple of (recomputed root bytes, MerkleTree instance).

    Raises:
        ValueError: If entries is empty.
    """
    if not entries:
        raise ValueError("Cannot rebuild Merkle tree from empty journal")
    leaf_payloads = [_entry_canonical_bytes(entry) for entry in entries]
    leaf_hashes = [merkle_leaf_hash(payload) for payload in leaf_payloads]
    recomputed_root = ct_merkle_root(leaf_hashes)
    tree = MerkleTree(leaf_payloads)
    assert tree.get_root() == recomputed_root
    return recomputed_root, tree


def verify_rebuild(entries: list[LedgerEntry], expected_root: bytes) -> bool:
    """
    Verify rebuilt Merkle root against an expected root.

    Args:
        entries: Ordered append-only ledger entries.
        expected_root: Expected Merkle root bytes.

    Returns:
        True if the rebuilt root matches expected_root.
    """
    if not entries:
        return expected_root == b""
    try:
        rebuilt_root, _tree = rebuild_merkle_from_journal(entries)
    except ValueError:
        return False
    return rebuilt_root == expected_root
