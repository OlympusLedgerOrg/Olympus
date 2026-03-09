"""
Ledger protocol implementation for Olympus

This module implements the append-only ledger for recording document commitments.
"""

from dataclasses import asdict, dataclass
from typing import Any

from .canonical_json import canonical_json_bytes
from .hashes import LEDGER_PREFIX, blake3_hash
from .timestamps import current_timestamp


@dataclass
class LedgerEntry:
    """An entry in the Olympus ledger."""

    ts: str  # ISO 8601 timestamp
    record_hash: str  # Hex-encoded record hash
    shard_id: str  # Shard identifier
    shard_root: str  # Hex-encoded shard root hash
    canonicalization: dict[str, Any]  # Canonicalization provenance for commitments
    prev_entry_hash: str  # Hex-encoded previous entry hash, empty string for genesis
    entry_hash: str  # Hex-encoded hash of this entry
    federation_quorum_certificate: dict[str, Any] | None = (
        None  # Optional signed federation quorum certificate
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LedgerEntry":
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

    @staticmethod
    def _canonicalize_quorum_certificate(
        certificate: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Normalize quorum certificate metadata before hash commitment.

        Rebuilds the certificate from a fixed set of known fields only, ensuring
        that extra or unrecognized fields are excluded from the hash payload and
        that all field types are explicit. The acknowledgments list is sorted
        lexicographically by (node_id, signature) for determinism.
        """
        if certificate is None:
            return None
        acknowledgments = certificate.get("acknowledgments")
        if isinstance(acknowledgments, list):
            signature_items = [
                {"node_id": str(item["node_id"]), "signature": str(item["signature"])}
                for item in acknowledgments
                if isinstance(item, dict) and "node_id" in item and "signature" in item
            ]
            sorted_acknowledgments: list[dict[str, str]] = sorted(
                signature_items,
                key=lambda item: (item["node_id"], item["signature"]),
            )
        else:
            sorted_acknowledgments = []
        return {
            "acknowledgments": sorted_acknowledgments,
            "event_id": str(certificate.get("event_id", "")),
            "federation_epoch": int(certificate.get("federation_epoch", 0)),
            "header_hash": str(certificate.get("header_hash", "")),
            "membership_hash": str(certificate.get("membership_hash", "")),
            "quorum_threshold": int(certificate.get("quorum_threshold", 0)),
            "shard_id": str(certificate.get("shard_id", "")),
            "timestamp": str(certificate.get("timestamp", "")),
        }

    def append(
        self,
        record_hash: str,
        shard_id: str,
        shard_root: str,
        canonicalization: dict[str, Any],
        federation_quorum_certificate: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger.

        Args:
            record_hash: Hash of the record
            shard_id: Identifier for the shard
            shard_root: Root hash of the shard
            canonicalization: Canonicalization provenance metadata for the commitment
            federation_quorum_certificate: Optional signed federation quorum certificate
                proving 2/3 federation agreement for the shard header

        Returns:
            The newly created entry
        """
        ts = current_timestamp()
        prev_entry_hash = self.entries[-1].entry_hash if self.entries else ""

        normalized_certificate = self._canonicalize_quorum_certificate(
            federation_quorum_certificate
        )

        # Create payload for hashing
        payload = {
            "ts": ts,
            "record_hash": record_hash,
            "shard_id": shard_id,
            "shard_root": shard_root,
            "canonicalization": canonicalization,
            "prev_entry_hash": prev_entry_hash,
        }
        if normalized_certificate is not None:
            payload["federation_quorum_certificate"] = normalized_certificate

        # Compute entry hash using LEDGER_PREFIX + canonical JSON
        entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json_bytes(payload)]).hex()

        entry = LedgerEntry(
            ts=ts,
            record_hash=record_hash,
            shard_id=shard_id,
            shard_root=shard_root,
            canonicalization=canonicalization,
            federation_quorum_certificate=normalized_certificate,
            prev_entry_hash=prev_entry_hash,
            entry_hash=entry_hash,
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
                "canonicalization": entry.canonicalization,
                "prev_entry_hash": entry.prev_entry_hash,
            }
            normalized_certificate = self._canonicalize_quorum_certificate(
                entry.federation_quorum_certificate
            )
            if normalized_certificate is not None:
                payload["federation_quorum_certificate"] = normalized_certificate
            expected_hash = blake3_hash([LEDGER_PREFIX, canonical_json_bytes(payload)]).hex()

            if entry.entry_hash != expected_hash:
                return False

            # Verify chain linkage
            if i > 0 and entry.prev_entry_hash != self.entries[i - 1].entry_hash:
                return False

        return True

    def get_all_entries(self) -> list[LedgerEntry]:
        """Get all entries in the ledger."""
        return self.entries.copy()
