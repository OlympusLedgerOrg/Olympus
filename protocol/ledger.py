"""
Ledger protocol implementation for Olympus

This module implements the append-only ledger for recording document commitments.

v1.0 SCOPE: Single-node operation with cryptographic signatures and hash-chain integrity.
Phase 1+ ONLY: Multi-node Guardian replication, Byzantine fault tolerance.

For Guardian Replication specification (Phase 1+), see docs/04_ledger_protocol.md.
"""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from .hashes import LEDGER_PREFIX, blake3_hash


@dataclass
class LedgerEntry:
    """An entry in the Olympus ledger."""
    ts: str  # ISO 8601 timestamp
    record_hash: str  # Hex-encoded record hash
    shard_id: str  # Shard identifier
    shard_root: str  # Hex-encoded shard root hash
    prev_entry_hash: str  # Hex-encoded previous entry hash, empty string for genesis
    entry_hash: str  # Hex-encoded hash of this entry

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'LedgerEntry':
        """Create from dictionary."""
        return cls(**data)


class Ledger:
    """
    Append-only ledger for Olympus.

    The ledger maintains a chain of entries where each entry includes
    a hash of the previous entry, creating a tamper-evident log.
    """

    def __init__(self) -> None:
        """Initialize an empty ledger."""
        self.entries: list[LedgerEntry] = []

    def append(
        self,
        record_hash: str,
        shard_id: str,
        shard_root: str
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger.

        Args:
            record_hash: Hash of the record
            shard_id: Identifier for the shard
            shard_root: Root hash of the shard

        Returns:
            The newly created entry
        """
        ts = datetime.now(UTC).isoformat().replace('+00:00', 'Z')
        prev_entry_hash = self.entries[-1].entry_hash if self.entries else ""

        # Create payload for hashing
        payload = {
            "ts": ts,
            "record_hash": record_hash,
            "shard_id": shard_id,
            "shard_root": shard_root,
            "prev_entry_hash": prev_entry_hash
        }

        # Compute entry hash using LEDGER_PREFIX + canonical JSON
        canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode('utf-8')]).hex()

        entry = LedgerEntry(
            ts=ts,
            record_hash=record_hash,
            shard_id=shard_id,
            shard_root=shard_root,
            prev_entry_hash=prev_entry_hash,
            entry_hash=entry_hash
        )

        self.entries.append(entry)
        return entry

    def get_entry(self, entry_hash: str) -> LedgerEntry | None:
        """
        Retrieve an entry by its hash.

        Args:
            entry_hash: Hash of the entry to retrieve

        Returns:
            The entry if found, None otherwise
        """
        for entry in self.entries:
            if entry.entry_hash == entry_hash:
                return entry
        return None

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire ledger chain.

        Returns:
            True if chain is valid
        """
        if not self.entries:
            return True

        # Check genesis entry
        if self.entries[0].prev_entry_hash != "":
            return False

        # Check each entry
        for i, entry in enumerate(self.entries):
            # Recompute entry hash
            payload = {
                "ts": entry.ts,
                "record_hash": entry.record_hash,
                "shard_id": entry.shard_id,
                "shard_root": entry.shard_root,
                "prev_entry_hash": entry.prev_entry_hash
            }
            canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            expected_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode('utf-8')]).hex()

            if entry.entry_hash != expected_hash:
                return False

            # Verify chain linkage
            if i > 0 and entry.prev_entry_hash != self.entries[i - 1].entry_hash:
                return False

        return True

    def get_all_entries(self) -> list[LedgerEntry]:
        """Get all entries in the ledger."""
        return self.entries.copy()
