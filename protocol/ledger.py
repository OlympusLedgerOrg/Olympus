"""
Ledger protocol implementation for Olympus

This module implements the append-only ledger for recording document commitments.
"""

from dataclasses import asdict, dataclass
from typing import Any

from .canonical_json import canonical_json_bytes
from .hashes import _SEP, LEDGER_PREFIX, blake3_hash
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
    poseidon_root: str | None = None  # Optional Poseidon Merkle root (decimal string)

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
        self._index: dict[str, LedgerEntry] = {}

    @staticmethod
    def _canonicalize_quorum_certificate(
        certificate: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Normalize quorum certificate metadata before hash commitment.

        Rebuilds the certificate from a fixed set of known fields only, ensuring
        that extra or unrecognized fields are excluded from the hash payload and
        that all field types are explicit. The signatures list is sorted
        lexicographically by (node_id, signature) for determinism.
        """
        if certificate is None:
            return None
        signatures = certificate.get("signatures")
        if isinstance(signatures, list):
            signature_items = [
                {"node_id": str(item["node_id"]), "signature": str(item["signature"])}
                for item in signatures
                if isinstance(item, dict) and "node_id" in item and "signature" in item
            ]
            sorted_signatures: list[dict[str, str]] = sorted(
                signature_items,
                key=lambda item: (item["node_id"], item["signature"]),
            )
        else:
            sorted_signatures = []
        return {
            "event_id": str(certificate.get("event_id", "")),
            "federation_epoch": int(certificate.get("federation_epoch", 0)),
            "height": int(certificate.get("height", 0)),
            "header_hash": str(certificate.get("header_hash", "")),
            "membership_hash": str(certificate.get("membership_hash", "")),
            "validator_count": int(certificate.get("validator_count", 0)),
            "quorum_threshold": int(certificate.get("quorum_threshold", 0)),
            "round": int(certificate.get("round", 0)),
            "scheme": str(certificate.get("scheme", "")),
            "shard_id": str(certificate.get("shard_id", "")),
            "signatures": sorted_signatures,
            "signer_bitmap": str(certificate.get("signer_bitmap", "")),
            "timestamp": str(certificate.get("timestamp", "")),
            "validator_set_hash": str(certificate.get("validator_set_hash", "")),
        }

    def append(
        self,
        record_hash: str,
        shard_id: str,
        shard_root: str,
        canonicalization: dict[str, Any],
        federation_quorum_certificate: dict[str, Any] | None = None,
        poseidon_root: str | None = None,
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger.

        When *poseidon_root* is supplied the entry hash is computed as a
        dual-root commitment that atomically binds both the BLAKE3 shard root
        and the Poseidon Merkle root.  Entries without a Poseidon root use the
        legacy hash formula for backward compatibility.

        Args:
            record_hash: Hash of the record
            shard_id: Identifier for the shard
            shard_root: Root hash of the shard (hex-encoded BLAKE3 root)
            canonicalization: Canonicalization provenance metadata for the commitment
            federation_quorum_certificate: Optional signed federation quorum certificate
                proving 2/3 federation agreement for the shard header
            poseidon_root: Optional Poseidon Merkle root as a decimal string
                (BN128 field element).  When provided, the entry hash uses the
                dual-root commitment formula instead of the legacy payload hash.

        Returns:
            The newly created entry
        """
        ts = current_timestamp()
        prev_entry_hash = self.entries[-1].entry_hash if self.entries else ""
        if self.entries:
            from datetime import datetime

            last_ts = self.entries[-1].ts
            last_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            current_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if current_dt <= last_dt:
                raise ValueError("Ledger timestamps must be strictly increasing")

        normalized_certificate = self._canonicalize_quorum_certificate(
            federation_quorum_certificate
        )

        # Create payload for hashing
        payload: dict[str, Any] = {
            "ts": ts,
            "record_hash": record_hash,
            "shard_id": shard_id,
            "shard_root": shard_root,
            "canonicalization": canonicalization,
            "prev_entry_hash": prev_entry_hash,
            "poseidon_root": poseidon_root,
        }
        if normalized_certificate is not None:
            payload["federation_quorum_certificate"] = normalized_certificate

        if poseidon_root is not None:
            from .hashes import SNARK_SCALAR_FIELD

            poseidon_int = int(poseidon_root)
            if not (0 <= poseidon_int < SNARK_SCALAR_FIELD):
                raise ValueError(
                    f"poseidon_root {poseidon_root!r} is not a valid BN128 field element"
                )
            poseidon_bytes = poseidon_int.to_bytes(32, byteorder="big")
        else:
            poseidon_bytes = b""

        entry_hash = blake3_hash(
            [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, poseidon_bytes]
        ).hex()

        entry = LedgerEntry(
            ts=ts,
            record_hash=record_hash,
            shard_id=shard_id,
            shard_root=shard_root,
            canonicalization=canonicalization,
            federation_quorum_certificate=normalized_certificate,
            prev_entry_hash=prev_entry_hash,
            entry_hash=entry_hash,
            poseidon_root=poseidon_root,
        )

        self.entries.append(entry)
        self._index[entry.entry_hash] = entry
        return entry

    def get_entry(self, entry_hash: str) -> LedgerEntry | None:
        """
        Retrieve an entry by its hash.

        Args:
            entry_hash: Hash of the entry to retrieve

        Returns:
            The entry if found, None otherwise
        """
        entry = self._index.get(entry_hash)
        if entry is not None:
            return entry

        # Fallback for ledgers populated via direct list assignment (tests/fixtures)
        for item in self.entries:
            if item.entry_hash not in self._index:
                self._index[item.entry_hash] = item
            if item.entry_hash == entry_hash:
                return item
        return None

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire ledger chain.

        Supports both legacy entries (single BLAKE3 root) and new entries
        that use the dual-root commitment formula.

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
            payload: dict[str, Any] = {
                "ts": entry.ts,
                "record_hash": entry.record_hash,
                "shard_id": entry.shard_id,
                "shard_root": entry.shard_root,
                "canonicalization": entry.canonicalization,
                "prev_entry_hash": entry.prev_entry_hash,
                "poseidon_root": entry.poseidon_root,
            }
            normalized_certificate = self._canonicalize_quorum_certificate(
                entry.federation_quorum_certificate
            )
            if normalized_certificate is not None:
                payload["federation_quorum_certificate"] = normalized_certificate

            if entry.poseidon_root is not None:
                try:
                    from .hashes import SNARK_SCALAR_FIELD

                    poseidon_int = int(entry.poseidon_root)
                    if not (0 <= poseidon_int < SNARK_SCALAR_FIELD):
                        return False
                    poseidon_bytes = poseidon_int.to_bytes(32, byteorder="big")
                except (ValueError, OverflowError):
                    return False
            else:
                poseidon_bytes = b""

            expected_hash = blake3_hash(
                [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, poseidon_bytes]
            ).hex()

            if entry.entry_hash != expected_hash:
                return False

            # Verify chain linkage
            if i > 0 and entry.prev_entry_hash != self.entries[i - 1].entry_hash:
                return False

        return True

    def get_all_entries(self) -> list[LedgerEntry]:
        """Get all entries in the ledger."""
        return self.entries.copy()
