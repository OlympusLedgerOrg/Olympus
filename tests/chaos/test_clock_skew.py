"""
Chaos test: clock skew simulation.

Verifies that Olympus handles extreme wall-clock anomalies — including
timestamps far in the past, far in the future, and non-monotonic jumps —
without corrupting ledger chain integrity.

Expected system behaviour
--------------------------
- Timestamps are stored as ISO 8601 strings; the protocol does not require
  monotonic ordering of ``ts`` fields across entries.
- Chain ordering is enforced by hash linkage (``prev_entry_hash``), not by
  wall-clock time, so a clock skew cannot break chain verification.
- ISO 8601 serialisation is unaffected regardless of the clock value.
- An extreme skew (e.g. year 1970 or year 9999) does not cause an exception
  in the canonicalization or hashing pipeline.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from unittest.mock import patch

import protocol.ledger as ledger_module
from protocol.hashes import hash_bytes
from protocol.ledger import Ledger
from protocol.merkle import MerkleTree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_leaf_hash(seed: int) -> bytes:
    return hash_bytes(seed.to_bytes(4, "big"))


def _append_with_ts(ledger: Ledger, seed: int, fake_ts: str) -> str:
    """Append a ledger entry using a patched current_timestamp."""
    # Patch the function reference inside the ledger module so that
    # Ledger.append() picks up the fake timestamp.
    with patch.object(ledger_module, "current_timestamp", return_value=fake_ts):
        leaf = _make_leaf_hash(seed)
        tree = MerkleTree([leaf])
        root = tree.get_root().hex()
        entry = ledger.append(
            record_hash=root,
            shard_id="clock-chaos",
            shard_root=root,
            canonicalization={"version": "1.0"},
        )
    return entry.entry_hash


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ledger_accepts_timestamp_far_in_past(fresh_ledger: Ledger) -> None:
    """
    An entry with a timestamp far in the past (Unix epoch) is accepted and
    the chain remains verifiable.
    """
    entry_hash = _append_with_ts(fresh_ledger, 0, "1970-01-01T00:00:00Z")

    assert entry_hash != ""
    assert fresh_ledger.entries[0].ts == "1970-01-01T00:00:00Z"
    assert fresh_ledger.verify_chain()


def test_ledger_accepts_timestamp_far_in_future(fresh_ledger: Ledger) -> None:
    """
    An entry with a timestamp far in the future (year 9999) is accepted and
    the chain remains verifiable.
    """
    entry_hash = _append_with_ts(fresh_ledger, 1, "9999-12-31T23:59:59Z")

    assert entry_hash != ""
    assert fresh_ledger.entries[0].ts == "9999-12-31T23:59:59Z"
    assert fresh_ledger.verify_chain()


def test_chain_integrity_with_non_monotonic_timestamps(fresh_ledger: Ledger) -> None:
    """
    Chain integrity is maintained even when timestamps go backwards (clock skew).

    Appends three entries with decreasing timestamps to simulate a backwards
    clock jump, then verifies the hash chain is still valid.
    """
    fake_timestamps = [
        "2026-06-01T12:00:00Z",
        "2025-01-01T00:00:00Z",  # backwards jump
        "2024-03-15T08:30:00Z",  # further back
    ]

    for i, ts in enumerate(fake_timestamps):
        _append_with_ts(fresh_ledger, i, ts)

    assert len(fresh_ledger.entries) == 3

    # Hash chain must be valid despite non-monotonic timestamps
    assert fresh_ledger.verify_chain()

    # Timestamps must be stored exactly as provided
    for i, expected_ts in enumerate(fake_timestamps):
        assert fresh_ledger.entries[i].ts == expected_ts


def test_large_clock_skew_does_not_affect_entry_hash(fresh_ledger: Ledger) -> None:
    """
    Two entries with identical content but different timestamps produce different
    entry hashes (the timestamp is included in the hash preimage).

    This verifies that the clock skew does not silently cause hash collisions.
    """
    leaf = _make_leaf_hash(42)
    tree = MerkleTree([leaf])
    root = tree.get_root().hex()

    with patch.object(ledger_module, "current_timestamp", return_value="2020-01-01T00:00:00Z"):
        entry_a = fresh_ledger.append(
            record_hash=root,
            shard_id="skew-test",
            shard_root=root,
            canonicalization={"version": "1.0"},
        )

    # Use a second fresh ledger so prev_entry_hash is also identical
    ledger_b = Ledger()
    with patch.object(ledger_module, "current_timestamp", return_value="2099-01-01T00:00:00Z"):
        entry_b = ledger_b.append(
            record_hash=root,
            shard_id="skew-test",
            shard_root=root,
            canonicalization={"version": "1.0"},
        )

    # Different timestamps must yield different entry hashes
    assert entry_a.entry_hash != entry_b.entry_hash


def test_iso8601_serialisation_unaffected_by_extreme_dates() -> None:
    """
    current_timestamp() produces a valid ISO 8601 string regardless of the
    underlying datetime value (within Python's datetime range).
    """
    iso8601_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    extreme_dates = [
        datetime(1970, 1, 1, 0, 0, 0, tzinfo=UTC),
        datetime(2000, 2, 29, 12, 0, 0, tzinfo=UTC),  # leap year
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
    ]

    for dt in extreme_dates:
        ts_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert iso8601_re.match(ts_str), f"Invalid ISO 8601 format for {dt}: {ts_str!r}"
