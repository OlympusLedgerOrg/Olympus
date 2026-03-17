"""Tests for deterministic Merkle rebuild from journal entries."""

import pytest

from protocol.canonical import CANONICAL_VERSION
from protocol.canonicalizer import canonicalization_provenance
from protocol.ledger import Ledger
from protocol.rebuild import rebuild_merkle_from_journal, verify_rebuild


def _canonicalization() -> dict[str, str]:
    return canonicalization_provenance("application/json", CANONICAL_VERSION)


def _build_ledger(count: int) -> Ledger:
    ledger = Ledger()
    for i in range(count):
        ledger.append(
            record_hash=f"record-{i}",
            shard_id="shard-a",
            shard_root=f"root-{i}",
            canonicalization=_canonicalization(),
        )
    return ledger


def test_rebuild_empty_journal() -> None:
    with pytest.raises(ValueError, match="empty journal"):
        rebuild_merkle_from_journal([])


def test_rebuild_single_entry() -> None:
    ledger = _build_ledger(1)
    rebuilt_root, tree = rebuild_merkle_from_journal(ledger.entries)
    assert rebuilt_root == tree.get_root()
    assert verify_rebuild(ledger.entries, rebuilt_root)


def test_rebuild_multi_entry_matches_original_tree() -> None:
    ledger = _build_ledger(5)
    rebuilt_root, tree = rebuild_merkle_from_journal(ledger.entries)
    assert rebuilt_root == tree.get_root()
    assert verify_rebuild(ledger.entries, rebuilt_root)


def test_rebuild_corrupted_entry_detection() -> None:
    ledger = _build_ledger(4)
    original_root, _tree = rebuild_merkle_from_journal(ledger.entries)
    ledger.entries[2].record_hash = "corrupted-record-hash"
    assert not verify_rebuild(ledger.entries, original_root)


def test_rebuild_matches_ledger_chain_verification() -> None:
    ledger = _build_ledger(3)
    assert ledger.verify_chain()
    rebuilt_root, _tree = rebuild_merkle_from_journal(ledger.entries)
    assert verify_rebuild(ledger.entries, rebuilt_root)
