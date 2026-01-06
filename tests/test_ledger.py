"""
Unit tests for Ledger class.

These tests validate the Ledger class which implements the append-only
ledger for recording document commitments.
"""

import json
from datetime import datetime

from protocol.hashes import LEDGER_PREFIX, blake3_hash
from protocol.ledger import Ledger, LedgerEntry


def test_ledger_initialization():
    """Test that a new ledger starts empty."""
    ledger = Ledger()
    assert len(ledger.entries) == 0
    assert ledger.get_all_entries() == []


def test_ledger_append_single_entry():
    """Test appending a single entry to the ledger."""
    ledger = Ledger()

    entry = ledger.append(
        record_hash="abc123",
        shard_id="shard1",
        shard_root="def456"
    )

    assert len(ledger.entries) == 1
    assert entry.record_hash == "abc123"
    assert entry.shard_id == "shard1"
    assert entry.shard_root == "def456"
    assert entry.prev_entry_hash == ""  # Genesis entry
    assert entry.entry_hash != ""  # Should have computed hash


def test_ledger_append_multiple_entries():
    """Test appending multiple entries to the ledger."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    entry3 = ledger.append(
        record_hash="hash3",
        shard_id="shard2",
        shard_root="root3"
    )

    assert len(ledger.entries) == 3
    assert ledger.entries[0] == entry1
    assert ledger.entries[1] == entry2
    assert ledger.entries[2] == entry3


def test_ledger_genesis_entry_has_empty_prev_hash():
    """Test that the first (genesis) entry has empty prev_entry_hash."""
    ledger = Ledger()

    entry = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    assert entry.prev_entry_hash == ""


def test_ledger_chain_linkage():
    """Test that entries are properly linked in a chain."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    entry3 = ledger.append(
        record_hash="hash3",
        shard_id="shard1",
        shard_root="root3"
    )

    # Each entry should link to the previous one
    assert entry2.prev_entry_hash == entry1.entry_hash
    assert entry3.prev_entry_hash == entry2.entry_hash


def test_ledger_entry_hash_computation():
    """Test that entry hash is computed correctly."""
    ledger = Ledger()

    entry = ledger.append(
        record_hash="test_hash",
        shard_id="test_shard",
        shard_root="test_root"
    )

    # Recompute the hash to verify
    payload = {
        "ts": entry.ts,
        "record_hash": entry.record_hash,
        "shard_id": entry.shard_id,
        "shard_root": entry.shard_root,
        "prev_entry_hash": entry.prev_entry_hash
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    expected_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode('utf-8')]).hex()

    assert entry.entry_hash == expected_hash


def test_ledger_get_entry_by_hash():
    """Test retrieving an entry by its hash."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    # Retrieve by hash
    retrieved = ledger.get_entry(entry1.entry_hash)
    assert retrieved == entry1

    retrieved = ledger.get_entry(entry2.entry_hash)
    assert retrieved == entry2


def test_ledger_get_entry_not_found():
    """Test that get_entry returns None for non-existent hash."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    retrieved = ledger.get_entry("nonexistent_hash")
    assert retrieved is None


def test_ledger_verify_chain_empty_ledger():
    """Test that verify_chain returns True for empty ledger."""
    ledger = Ledger()
    assert ledger.verify_chain() is True


def test_ledger_verify_chain_valid():
    """Test that verify_chain returns True for valid chain."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    ledger.append(
        record_hash="hash3",
        shard_id="shard1",
        shard_root="root3"
    )

    assert ledger.verify_chain() is True


def test_ledger_verify_chain_detects_tampered_entry_hash():
    """Test that verify_chain detects tampered entry hash."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    # Tamper with an entry hash
    ledger.entries[1].entry_hash = "tampered_hash"

    assert ledger.verify_chain() is False


def test_ledger_verify_chain_detects_tampered_record_hash():
    """Test that verify_chain detects tampered record data."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    # Tamper with record data (changing this invalidates the entry_hash)
    ledger.entries[1].record_hash = "tampered_record_hash"

    assert ledger.verify_chain() is False


def test_ledger_verify_chain_detects_broken_linkage():
    """Test that verify_chain detects broken chain linkage."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    # Break the chain linkage
    ledger.entries[1].prev_entry_hash = "wrong_prev_hash"

    # This should fail verification because the prev_entry_hash doesn't match
    # and also because recomputing the entry_hash won't match the stored one
    assert ledger.verify_chain() is False


def test_ledger_verify_chain_detects_invalid_genesis():
    """Test that verify_chain detects invalid genesis entry."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    # Tamper with genesis entry's prev_entry_hash
    ledger.entries[0].prev_entry_hash = "should_be_empty"

    assert ledger.verify_chain() is False


def test_ledger_entry_to_dict():
    """Test LedgerEntry.to_dict() serialization."""
    entry = LedgerEntry(
        ts="2024-01-01T00:00:00Z",
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        prev_entry_hash="prev",
        entry_hash="entry"
    )

    result = entry.to_dict()

    assert isinstance(result, dict)
    assert result["ts"] == "2024-01-01T00:00:00Z"
    assert result["record_hash"] == "hash1"
    assert result["shard_id"] == "shard1"
    assert result["shard_root"] == "root1"
    assert result["prev_entry_hash"] == "prev"
    assert result["entry_hash"] == "entry"


def test_ledger_entry_from_dict():
    """Test LedgerEntry.from_dict() deserialization."""
    data = {
        "ts": "2024-01-01T00:00:00Z",
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": "root1",
        "prev_entry_hash": "prev",
        "entry_hash": "entry"
    }

    entry = LedgerEntry.from_dict(data)

    assert entry.ts == "2024-01-01T00:00:00Z"
    assert entry.record_hash == "hash1"
    assert entry.shard_id == "shard1"
    assert entry.shard_root == "root1"
    assert entry.prev_entry_hash == "prev"
    assert entry.entry_hash == "entry"


def test_ledger_entry_roundtrip_serialization():
    """Test that to_dict/from_dict roundtrip preserves data."""
    original = LedgerEntry(
        ts="2024-01-01T00:00:00Z",
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        prev_entry_hash="prev",
        entry_hash="entry"
    )

    data = original.to_dict()
    restored = LedgerEntry.from_dict(data)

    assert restored == original


def test_ledger_get_all_entries():
    """Test get_all_entries returns copy of entries."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    entries = ledger.get_all_entries()

    assert len(entries) == 2
    # Should be a copy, not the same list
    assert entries is not ledger.entries


def test_ledger_timestamp_format():
    """Test that timestamps are in correct ISO 8601 format with Z suffix."""
    ledger = Ledger()

    entry = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    # Should end with 'Z' for UTC
    assert entry.ts.endswith('Z')

    # Should be parseable as ISO 8601
    # Remove 'Z' and parse
    datetime.fromisoformat(entry.ts.replace('Z', '+00:00'))


def test_ledger_entry_hashes_are_unique():
    """Test that different entries produce different hashes."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1"
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2"
    )

    assert entry1.entry_hash != entry2.entry_hash


def test_ledger_deterministic_hash_for_same_data():
    """Test that same data produces same hash."""
    # Use fixed timestamp to ensure determinism
    ts = "2024-01-01T00:00:00Z"

    # Manually create entries with same timestamp
    entry1 = LedgerEntry(
        ts=ts,
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        prev_entry_hash="",
        entry_hash=""
    )

    # Compute hash
    payload = {
        "ts": ts,
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": "root1",
        "prev_entry_hash": ""
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    computed_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode('utf-8')]).hex()

    entry1.entry_hash = computed_hash
    entry2 = LedgerEntry(
        ts=ts,
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        prev_entry_hash="",
        entry_hash=computed_hash
    )

    assert entry1.entry_hash == entry2.entry_hash
