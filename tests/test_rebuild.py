"""Tests for deterministic journal rebuild utilities."""

from dataclasses import replace

import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleTree
from protocol.rebuild import rebuild_merkle_from_journal, verify_rebuild


def _canonicalization() -> dict[str, str]:
    return {"format": "json", "version": "1.0"}


def _build_ledger(count: int) -> Ledger:
    ledger = Ledger()
    for index in range(count):
        ledger.append(
            record_hash=f"{index:064x}",
            shard_id="4F3A",
            shard_root=f"{index + 1:064x}",
            canonicalization=_canonicalization(),
        )
    return ledger


def test_empty_journal_raises() -> None:
    with pytest.raises(ValueError, match="entries list cannot be empty"):
        rebuild_merkle_from_journal([])


def test_single_entry_rebuild_matches_tree() -> None:
    ledger = _build_ledger(1)
    entries = ledger.get_all_entries()

    rebuilt_root, _ = rebuild_merkle_from_journal(entries)
    expected_tree = MerkleTree([canonical_json_bytes(entries[0].to_dict())])

    assert rebuilt_root == expected_tree.get_root()


def test_multi_entry_rebuild_matches_original_root() -> None:
    ledger = _build_ledger(4)
    entries = ledger.get_all_entries()

    rebuilt_root, _ = rebuild_merkle_from_journal(entries)
    expected_tree = MerkleTree([canonical_json_bytes(entry.to_dict()) for entry in entries])

    assert rebuilt_root == expected_tree.get_root()


def test_corrupted_entry_hash_returns_false() -> None:
    ledger = _build_ledger(3)
    entries = ledger.get_all_entries()
    tampered_entries = entries.copy()
    tampered_entries[1] = replace(entries[1], entry_hash="00" * 32)
    expected_root, _ = rebuild_merkle_from_journal(entries)

    assert not verify_rebuild(tampered_entries, expected_root)


def test_broken_chain_linkage_detected() -> None:
    ledger = _build_ledger(3)
    entries = ledger.get_all_entries()
    tampered_entries = entries.copy()
    tampered_entries[2] = replace(entries[2], prev_entry_hash="bad-link")

    with pytest.raises(ValueError, match="broken chain linkage"):
        rebuild_merkle_from_journal(tampered_entries)


def test_rebuild_is_deterministic() -> None:
    ledger = _build_ledger(5)
    entries = ledger.get_all_entries()

    root_a, _ = rebuild_merkle_from_journal(entries)
    root_b, _ = rebuild_merkle_from_journal(entries)

    assert root_a == root_b


def test_round_trip_append_then_rebuild_matches_root() -> None:
    ledger = _build_ledger(6)
    entries = ledger.get_all_entries()
    expected_root, _ = rebuild_merkle_from_journal(entries)

    assert verify_rebuild(entries, expected_root)
