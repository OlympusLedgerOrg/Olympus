"""
Unit tests for Ledger class.

These tests validate the Ledger class which implements the append-only
ledger for recording document commitments.
"""

from datetime import datetime

import pytest

from protocol.canonical import CANONICAL_VERSION
from protocol.canonical_json import canonical_json_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import LEDGER_PREFIX, blake3_hash
from protocol.ledger import Ledger, LedgerEntry


def _canonicalization():
    return canonicalization_provenance("application/json", CANONICAL_VERSION)


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
        shard_root="def456",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
    )

    entry3 = ledger.append(
        record_hash="hash3",
        shard_id="shard2",
        shard_root="root3",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    assert entry.prev_entry_hash == ""


def test_ledger_chain_linkage():
    """Test that entries are properly linked in a chain."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
    )

    entry3 = ledger.append(
        record_hash="hash3",
        shard_id="shard1",
        shard_root="root3",
        canonicalization=_canonicalization(),
    )

    # Each entry should link to the previous one
    assert entry2.prev_entry_hash == entry1.entry_hash
    assert entry3.prev_entry_hash == entry2.entry_hash


def test_ledger_entry_hash_computation():
    """Test that entry hash is computed correctly (including HLC bytes)."""
    ledger = Ledger()

    entry = ledger.append(
        record_hash="test_hash",
        shard_id="test_shard",
        shard_root="test_root",
        canonicalization=_canonicalization(),
    )

    # Recompute the hash to verify — new entries include HLC bytes
    payload = {
        "ts": entry.ts,
        "record_hash": entry.record_hash,
        "shard_id": entry.shard_id,
        "shard_root": entry.shard_root,
        "canonicalization": entry.canonicalization,
        "prev_entry_hash": entry.prev_entry_hash,
        "poseidon_root": None,
    }
    from protocol.hashes import _SEP

    hlc_raw = bytes.fromhex(entry.hlc_bytes)
    expected_hash = blake3_hash(
        [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, b"", _SEP, hlc_raw]
    ).hex()

    assert entry.entry_hash == expected_hash


def test_ledger_entry_hash_includes_federation_quorum_certificate_when_present():
    """Quorum certificate metadata should be part of ledger entry hash commitment."""
    ledger = Ledger()

    certificate = {
        "shard_id": "records.city-a",
        "header_hash": "ab" * 32,
        "timestamp": "2026-03-09T00:00:00Z",
        "event_id": "ef" * 32,
        "scheme": "ed25519",
        "signer_bitmap": "10",
        "quorum_threshold": 2,
        "signatures": [{"node_id": "olympus-node-1", "signature": "cd" * 64}],
    }
    entry = ledger.append(
        record_hash="test_hash",
        shard_id="records.city-a",
        shard_root="test_root",
        canonicalization=_canonicalization(),
        federation_quorum_certificate=certificate,
    )

    payload = {
        "ts": entry.ts,
        "record_hash": entry.record_hash,
        "shard_id": entry.shard_id,
        "shard_root": entry.shard_root,
        "canonicalization": entry.canonicalization,
        "prev_entry_hash": entry.prev_entry_hash,
        "poseidon_root": None,
        "federation_quorum_certificate": entry.federation_quorum_certificate,
    }
    from protocol.hashes import _SEP

    hlc_raw = bytes.fromhex(entry.hlc_bytes)
    expected_hash = blake3_hash(
        [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, b"", _SEP, hlc_raw]
    ).hex()
    assert entry.entry_hash == expected_hash


def test_ledger_canonicalizes_quorum_certificate_signature_order_before_hashing():
    """Entry hash commitment should be stable regardless of signature ordering."""
    ledger = Ledger()
    certificate = {
        "shard_id": "records.city-a",
        "header_hash": "ab" * 32,
        "timestamp": "2026-03-09T00:00:00Z",
        "event_id": "ef" * 32,
        "scheme": "ed25519",
        "signer_bitmap": "11",
        "quorum_threshold": 2,
        "signatures": [
            {"node_id": "olympus-node-2", "signature": "ef" * 64},
            {"node_id": "olympus-node-1", "signature": "cd" * 64},
        ],
    }

    entry = ledger.append(
        record_hash="test_hash",
        shard_id="records.city-a",
        shard_root="test_root",
        canonicalization=_canonicalization(),
        federation_quorum_certificate=certificate,
    )

    assert [sig["node_id"] for sig in entry.federation_quorum_certificate["signatures"]] == [
        "olympus-node-1",
        "olympus-node-2",
    ]
    assert ledger.verify_chain() is True


def test_ledger_get_entry_by_hash():
    """Test retrieving an entry by its hash."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    retrieved = ledger.get_entry("nonexistent_hash")
    assert retrieved is None


def test_ledger_get_entry_empty_returns_none():
    """Test that get_entry returns None for empty ledger."""
    ledger = Ledger()

    assert ledger.get_entry("missing_hash") is None


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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash3",
        shard_id="shard1",
        shard_root="root3",
        canonicalization=_canonicalization(),
    )

    assert ledger.verify_chain() is True


def test_ledger_verify_chain_detects_tampered_entry_hash():
    """Test that verify_chain detects tampered entry hash."""
    ledger = Ledger()

    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
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
        canonicalization=_canonicalization(),
        prev_entry_hash="prev",
        entry_hash="entry",
    )

    result = entry.to_dict()

    assert isinstance(result, dict)
    assert result["ts"] == "2024-01-01T00:00:00Z"
    assert result["record_hash"] == "hash1"
    assert result["shard_id"] == "shard1"
    assert result["shard_root"] == "root1"
    assert result["canonicalization"] == _canonicalization()
    assert result["prev_entry_hash"] == "prev"
    assert result["entry_hash"] == "entry"


def test_ledger_entry_from_dict():
    """Test LedgerEntry.from_dict() deserialization."""
    data = {
        "ts": "2024-01-01T00:00:00Z",
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": "root1",
        "canonicalization": _canonicalization(),
        "prev_entry_hash": "prev",
        "entry_hash": "entry",
    }

    entry = LedgerEntry.from_dict(data)

    assert entry.ts == "2024-01-01T00:00:00Z"
    assert entry.record_hash == "hash1"
    assert entry.shard_id == "shard1"
    assert entry.shard_root == "root1"
    assert entry.canonicalization == _canonicalization()
    assert entry.prev_entry_hash == "prev"
    assert entry.entry_hash == "entry"


def test_ledger_entry_roundtrip_serialization():
    """Test that to_dict/from_dict roundtrip preserves data."""
    original = LedgerEntry(
        ts="2024-01-01T00:00:00Z",
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
        prev_entry_hash="prev",
        entry_hash="entry",
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    # Should end with 'Z' for UTC
    assert entry.ts.endswith("Z")

    # Should be parseable as ISO 8601
    # Remove 'Z' and parse
    datetime.fromisoformat(entry.ts.replace("Z", "+00:00"))


def test_ledger_entry_hashes_are_unique():
    """Test that different entries produce different hashes."""
    ledger = Ledger()

    entry1 = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
    )

    entry2 = ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root="root2",
        canonicalization=_canonicalization(),
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
        canonicalization=_canonicalization(),
        prev_entry_hash="",
        entry_hash="",
    )

    # Compute hash
    payload = {
        "ts": ts,
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": "root1",
        "canonicalization": _canonicalization(),
        "prev_entry_hash": "",
    }
    computed_hash = blake3_hash([LEDGER_PREFIX, canonical_json_bytes(payload)]).hex()

    entry1.entry_hash = computed_hash
    entry2 = LedgerEntry(
        ts=ts,
        record_hash="hash1",
        shard_id="shard1",
        shard_root="root1",
        canonicalization=_canonicalization(),
        prev_entry_hash="",
        entry_hash=computed_hash,
    )

    assert entry1.entry_hash == entry2.entry_hash


# ---------------------------------------------------------------------------
# Dual-root commitment ledger tests
# ---------------------------------------------------------------------------

_SAMPLE_BLAKE3_ROOT = "a" * 64  # 32-byte hex-encoded test value (all 0xaa bytes)
# A valid BN128 field element (decimal string)
_SAMPLE_POSEIDON_ROOT = "12345678901234567890"


def _poseidon_root_bytes(decimal: str) -> bytes:
    return int(decimal).to_bytes(32, byteorder="big")


def test_ledger_append_with_poseidon_root_sets_field():
    """Appending with poseidon_root must populate LedgerEntry.poseidon_root."""
    ledger = Ledger()
    entry = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    assert entry.poseidon_root == _SAMPLE_POSEIDON_ROOT


def test_ledger_append_without_poseidon_root_field_is_none():
    """Omitting poseidon_root must leave LedgerEntry.poseidon_root as None."""
    ledger = Ledger()
    entry = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
    )
    assert entry.poseidon_root is None


def test_ledger_dual_root_entry_hash_uses_dual_commitment():
    """Entry hash for dual-root entries must hash payload plus poseidon bytes."""
    from protocol.hashes import _SEP, LEDGER_PREFIX, blake3_hash, canonical_json_bytes

    ledger = Ledger()
    entry = ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    payload = {
        "ts": entry.ts,
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": _SAMPLE_BLAKE3_ROOT,
        "canonicalization": _canonicalization(),
        "prev_entry_hash": "",
        "poseidon_root": _SAMPLE_POSEIDON_ROOT,
    }
    hlc_raw = bytes.fromhex(entry.hlc_bytes)
    expected = blake3_hash(
        [
            LEDGER_PREFIX,
            canonical_json_bytes(payload),
            _SEP,
            _poseidon_root_bytes(_SAMPLE_POSEIDON_ROOT),
            _SEP,
            hlc_raw,
        ]
    ).hex()
    assert entry.entry_hash == expected


def test_ledger_dual_root_entry_hash_differs_from_legacy_hash():
    """Dual-root entry hash must differ from the legacy canonical-JSON hash."""
    ledger_dual = Ledger()
    entry_dual = ledger_dual.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )

    ledger_legacy = Ledger()
    entry_legacy = ledger_legacy.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
    )

    assert entry_dual.entry_hash != entry_legacy.entry_hash


def test_ledger_verify_chain_valid_with_dual_root_entries():
    """verify_chain must return True for a chain containing dual-root entries."""
    ledger = Ledger()
    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    assert ledger.verify_chain() is True


def test_ledger_verify_chain_mixed_legacy_and_dual_root():
    """verify_chain must handle chains with a mix of legacy and dual-root entries."""
    ledger = Ledger()
    # First entry: legacy (no poseidon_root)
    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
    )
    # Second entry: new format (with poseidon_root)
    ledger.append(
        record_hash="hash2",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    assert ledger.verify_chain() is True


def test_ledger_verify_chain_detects_tampered_poseidon_root():
    """verify_chain must fail if poseidon_root is tampered with after commit."""
    ledger = Ledger()
    ledger.append(
        record_hash="hash1",
        shard_id="shard1",
        shard_root=_SAMPLE_BLAKE3_ROOT,
        canonicalization=_canonicalization(),
        poseidon_root=_SAMPLE_POSEIDON_ROOT,
    )
    # Tamper with the poseidon_root after insertion
    ledger.entries[0].poseidon_root = "99999999999999999999"
    assert ledger.verify_chain() is False


def test_ledger_append_with_poseidon_root_rejects_invalid_field_element():
    """Appending with a poseidon_root outside the BN128 field must raise ValueError."""
    from protocol.hashes import SNARK_SCALAR_FIELD

    ledger = Ledger()
    out_of_range = str(SNARK_SCALAR_FIELD)  # >= field prime -> invalid
    with pytest.raises(ValueError, match="BN128 field element"):
        ledger.append(
            record_hash="hash1",
            shard_id="shard1",
            shard_root=_SAMPLE_BLAKE3_ROOT,
            canonicalization=_canonicalization(),
            poseidon_root=out_of_range,
        )


def test_ledger_entry_from_dict_backward_compatible_without_poseidon_root():
    """LedgerEntry.from_dict must work for old entries that lack poseidon_root."""
    data = {
        "ts": "2024-01-01T00:00:00Z",
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": "root1",
        "canonicalization": _canonicalization(),
        "prev_entry_hash": "",
        "entry_hash": "somehash",
        "federation_quorum_certificate": None,
    }
    entry = LedgerEntry.from_dict(data)
    assert entry.poseidon_root is None


def test_ledger_entry_from_dict_with_poseidon_root():
    """LedgerEntry.from_dict must preserve poseidon_root when present."""
    data = {
        "ts": "2024-01-01T00:00:00Z",
        "record_hash": "hash1",
        "shard_id": "shard1",
        "shard_root": _SAMPLE_BLAKE3_ROOT,
        "canonicalization": _canonicalization(),
        "prev_entry_hash": "",
        "entry_hash": "somehash",
        "federation_quorum_certificate": None,
        "poseidon_root": _SAMPLE_POSEIDON_ROOT,
    }
    entry = LedgerEntry.from_dict(data)
    assert entry.poseidon_root == _SAMPLE_POSEIDON_ROOT
