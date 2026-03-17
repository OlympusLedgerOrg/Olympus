"""Deterministic Merkle rebuild utilities for ledger journal recovery."""

from .canonical_json import canonical_json_bytes
from .ledger import Ledger, LedgerEntry
from .merkle import MerkleTree


def rebuild_merkle_from_journal(entries: list[LedgerEntry]) -> tuple[bytes, MerkleTree]:
    """
    Rebuild a MerkleTree from an ordered list of ledger entries.

    Args:
        entries: Ordered list of LedgerEntry instances in append order.

    Returns:
        Tuple of ``(recomputed_root, tree)``.

    Raises:
        ValueError: If entries are empty or chain linkage is broken.
    """
    if not entries:
        raise ValueError("entries list cannot be empty")
    if entries[0].prev_entry_hash != "":
        raise ValueError("broken chain linkage: genesis prev_entry_hash must be empty")
    for index in range(1, len(entries)):
        if entries[index].prev_entry_hash != entries[index - 1].entry_hash:
            raise ValueError(f"broken chain linkage at index {index}")

    leaf_payloads = [canonical_json_bytes(entry.to_dict()) for entry in entries]
    tree = MerkleTree(leaf_payloads)
    return tree.get_root(), tree


def verify_rebuild(entries: list[LedgerEntry], expected_root: bytes) -> bool:
    """
    Verify deterministic rebuild from journal entries against an expected root.

    Args:
        entries: Ordered ledger entries.
        expected_root: Expected Merkle root.

    Returns:
        ``True`` if chain integrity is valid and rebuilt root matches.
    """
    if not isinstance(expected_root, bytes) or len(expected_root) != 32:
        return False

    ledger = Ledger()
    ledger.entries = entries.copy()
    if not ledger.verify_chain():
        return False

    try:
        rebuilt_root, _ = rebuild_merkle_from_journal(entries)
    except ValueError:
        return False
    return rebuilt_root == expected_root
