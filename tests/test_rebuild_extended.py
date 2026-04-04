"""Extended tests for protocol.rebuild covering uncovered code paths."""

import pytest

from protocol.ledger import Ledger, LedgerEntry
from protocol.rebuild import (
    _canonicalize_quorum_certificate,
    _verify_entry_chain,
    rebuild_merkle_from_journal,
    verify_rebuild,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entries(count: int = 3) -> list[LedgerEntry]:
    """Create a valid chain of ledger entries via Ledger.append."""
    ledger = Ledger()
    for i in range(count):
        ledger.append(
            record_hash=f"record_{i}",
            shard_id="test-shard",
            shard_root="aa" * 32,
            canonicalization={"method": "canonical_json"},
        )
    return list(ledger.entries)


# ---------------------------------------------------------------------------
# _verify_entry_chain – genesis prev_entry_hash not empty
# ---------------------------------------------------------------------------


def test_verify_entry_chain_genesis_nonempty_prev_hash():
    """Genesis entry with non-empty prev_entry_hash must fail."""
    entries = _make_entries(1)
    # Mutate genesis to have a non-empty prev_entry_hash
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="not_empty",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root=entries[0].poseidon_root,
        hlc_bytes=entries[0].hlc_bytes,
    )
    assert _verify_entry_chain([broken]) is False


# ---------------------------------------------------------------------------
# _verify_entry_chain – invalid poseidon_root (ValueError/OverflowError)
# ---------------------------------------------------------------------------


def test_verify_entry_chain_invalid_poseidon_root_not_numeric():
    """Non-numeric poseidon_root triggers ValueError → returns False."""
    entries = _make_entries(1)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root="not_a_number",
        hlc_bytes=entries[0].hlc_bytes,
    )
    assert _verify_entry_chain([broken]) is False


def test_verify_entry_chain_poseidon_root_negative():
    """Negative poseidon_root is outside BN128 range → returns False."""
    entries = _make_entries(1)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root="-1",
        hlc_bytes=entries[0].hlc_bytes,
    )
    assert _verify_entry_chain([broken]) is False


def test_verify_entry_chain_poseidon_root_exceeds_field():
    """poseidon_root >= SNARK_SCALAR_FIELD → returns False."""
    from protocol.hashes import SNARK_SCALAR_FIELD

    entries = _make_entries(1)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root=str(SNARK_SCALAR_FIELD),
        hlc_bytes=entries[0].hlc_bytes,
    )
    assert _verify_entry_chain([broken]) is False


# ---------------------------------------------------------------------------
# _verify_entry_chain – HLC bytes paths
# ---------------------------------------------------------------------------


def test_verify_entry_chain_valid_hlc_bytes():
    """Entries created by Ledger.append have hlc_bytes and should verify."""
    entries = _make_entries(3)
    assert _verify_entry_chain(entries) is True


def test_verify_entry_chain_invalid_hlc_bytes_hex():
    """Corrupt hlc_bytes hex → returns False."""
    entries = _make_entries(1)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root=entries[0].poseidon_root,
        hlc_bytes="zzzz_not_hex",
    )
    assert _verify_entry_chain([broken]) is False


def test_verify_entry_chain_hlc_non_monotonic():
    """HLC timestamps must be strictly monotonic; reversed order → False."""
    entries = _make_entries(2)
    # Swap HLC bytes to break monotonicity (second entry gets first entry's HLC)
    broken_second = LedgerEntry(
        ts=entries[1].ts,
        record_hash=entries[1].record_hash,
        shard_id=entries[1].shard_id,
        shard_root=entries[1].shard_root,
        canonicalization=entries[1].canonicalization,
        prev_entry_hash=entries[1].prev_entry_hash,
        entry_hash=entries[1].entry_hash,
        federation_quorum_certificate=entries[1].federation_quorum_certificate,
        poseidon_root=entries[1].poseidon_root,
        hlc_bytes=entries[0].hlc_bytes,  # use first entry's (earlier) HLC
    )
    assert _verify_entry_chain([entries[0], broken_second]) is False


def test_verify_entry_chain_empty_list():
    """Empty entries list should return True."""
    assert _verify_entry_chain([]) is True


# ---------------------------------------------------------------------------
# _canonicalize_quorum_certificate – signatures not a list
# ---------------------------------------------------------------------------


def test_canonicalize_qc_signatures_not_list():
    """When signatures is not a list, sorted_signatures should be []."""
    cert = {
        "event_id": "ev1",
        "federation_epoch": 1,
        "height": 10,
        "header_hash": "abc",
        "membership_hash": "def",
        "validator_count": 2,
        "quorum_threshold": 2,
        "round": 1,
        "scheme": "ed25519",
        "shard_id": "shard-1",
        "signatures": "not-a-list",
        "signer_bitmap": "11",
        "timestamp": "2026-01-01T00:00:00Z",
        "validator_set_hash": "ghi",
    }
    result = _canonicalize_quorum_certificate(cert)
    assert result is not None
    assert result["signatures"] == []


def test_canonicalize_qc_none():
    """None certificate returns None."""
    assert _canonicalize_quorum_certificate(None) is None


def test_canonicalize_qc_filters_invalid_items():
    """Items that are not dicts or lack required keys are filtered out."""
    cert = {
        "event_id": "ev1",
        "federation_epoch": 1,
        "height": 10,
        "header_hash": "abc",
        "membership_hash": "def",
        "validator_count": 2,
        "quorum_threshold": 2,
        "round": 1,
        "scheme": "ed25519",
        "shard_id": "shard-1",
        "signatures": [
            {"node_id": "node-1", "signature": "sig1"},
            "not_a_dict",
            {"node_id": "node-2"},  # missing "signature"
            {"signature": "sig3"},  # missing "node_id"
            42,
        ],
        "signer_bitmap": "11",
        "timestamp": "2026-01-01T00:00:00Z",
        "validator_set_hash": "ghi",
    }
    result = _canonicalize_quorum_certificate(cert)
    assert result is not None
    assert len(result["signatures"]) == 1
    assert result["signatures"][0]["node_id"] == "node-1"


# ---------------------------------------------------------------------------
# rebuild_merkle_from_journal – broken chain linkage
# ---------------------------------------------------------------------------


def test_rebuild_merkle_empty_entries():
    """Empty entries list raises ValueError."""
    with pytest.raises(ValueError, match="entries list cannot be empty"):
        rebuild_merkle_from_journal([])


def test_rebuild_merkle_broken_genesis():
    """Genesis entry with non-empty prev_entry_hash raises ValueError."""
    entries = _make_entries(1)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="some_hash",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root=entries[0].poseidon_root,
        hlc_bytes=entries[0].hlc_bytes,
    )
    with pytest.raises(ValueError, match="genesis prev_entry_hash must be empty"):
        rebuild_merkle_from_journal([broken])


def test_rebuild_merkle_broken_linkage_at_index():
    """Broken chain linkage at index > 0 raises ValueError."""
    entries = _make_entries(3)
    broken = LedgerEntry(
        ts=entries[2].ts,
        record_hash=entries[2].record_hash,
        shard_id=entries[2].shard_id,
        shard_root=entries[2].shard_root,
        canonicalization=entries[2].canonicalization,
        prev_entry_hash="wrong_hash",
        entry_hash=entries[2].entry_hash,
        federation_quorum_certificate=entries[2].federation_quorum_certificate,
        poseidon_root=entries[2].poseidon_root,
        hlc_bytes=entries[2].hlc_bytes,
    )
    with pytest.raises(ValueError, match="broken chain linkage at index 2"):
        rebuild_merkle_from_journal([entries[0], entries[1], broken])


def test_rebuild_merkle_valid_chain():
    """Valid chain should return root and tree successfully."""
    entries = _make_entries(3)
    root, tree = rebuild_merkle_from_journal(entries)
    assert isinstance(root, bytes)
    assert len(root) == 32


# ---------------------------------------------------------------------------
# verify_rebuild – wrong expected_root length and broken chain
# ---------------------------------------------------------------------------


def test_verify_rebuild_wrong_root_length():
    """Expected root of wrong length returns False."""
    entries = _make_entries(2)
    assert verify_rebuild(entries, b"\x00" * 16) is False


def test_verify_rebuild_not_bytes():
    """Expected root that is not bytes returns False."""
    entries = _make_entries(2)
    assert verify_rebuild(entries, "not_bytes") is False  # type: ignore[arg-type]


def test_verify_rebuild_broken_chain():
    """Entries with broken chain return False."""
    entries = _make_entries(2)
    broken = LedgerEntry(
        ts=entries[0].ts,
        record_hash=entries[0].record_hash,
        shard_id=entries[0].shard_id,
        shard_root=entries[0].shard_root,
        canonicalization=entries[0].canonicalization,
        prev_entry_hash="not_empty",
        entry_hash=entries[0].entry_hash,
        federation_quorum_certificate=entries[0].federation_quorum_certificate,
        poseidon_root=entries[0].poseidon_root,
        hlc_bytes=entries[0].hlc_bytes,
    )
    assert verify_rebuild([broken], b"\x00" * 32) is False


def test_verify_rebuild_matching_root():
    """Valid entries with matching root return True."""
    entries = _make_entries(3)
    root, _ = rebuild_merkle_from_journal(entries)
    assert verify_rebuild(entries, root) is True


def test_verify_rebuild_mismatched_root():
    """Valid entries with wrong root return False."""
    entries = _make_entries(3)
    assert verify_rebuild(entries, b"\xff" * 32) is False
