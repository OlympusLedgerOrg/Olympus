"""
Key rotation chain utilities for Olympus Ed25519 signing keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import nacl.exceptions
import nacl.signing

from .canonical_json import canonical_json_bytes
from .hashes import KEY_ROTATION_PREFIX, blake3_hash
from .ledger import Ledger, LedgerEntry


def _rotation_payload(
    *,
    old_pubkey: bytes,
    new_pubkey: bytes,
    epoch: int,
    timestamp: str,
) -> bytes:
    """Return canonical payload bytes for key-rotation signing."""
    payload = {
        "old_key": old_pubkey.hex(),
        "new_key": new_pubkey.hex(),
        "epoch": epoch,
        "timestamp": timestamp,
    }
    return canonical_json_bytes(payload)


def key_rotation_payload_hash(
    *,
    old_pubkey: bytes,
    new_pubkey: bytes,
    epoch: int,
    timestamp: str,
) -> bytes:
    """
    Return the deterministic payload hash for a key-rotation record.

    Args:
        old_pubkey: Previous Ed25519 public key (32 bytes).
        new_pubkey: Replacement Ed25519 public key (32 bytes).
        epoch: Rotation epoch.
        timestamp: Rotation timestamp in ISO 8601 format.

    Returns:
        32-byte domain-separated BLAKE3 payload hash.
    """
    return blake3_hash(
        [
            KEY_ROTATION_PREFIX,
            _rotation_payload(
                old_pubkey=old_pubkey,
                new_pubkey=new_pubkey,
                epoch=epoch,
                timestamp=timestamp,
            ),
        ]
    )


@dataclass(frozen=True)
class KeyRotationRecord:
    """
    One signed key-rotation link in an append-only key evolution chain.
    """

    old_pubkey: bytes
    new_pubkey: bytes
    epoch: int
    timestamp: str
    signature_by_old: bytes
    signature_by_new: bytes

    @classmethod
    def create(
        cls,
        *,
        old_signing_key: nacl.signing.SigningKey,
        new_signing_key: nacl.signing.SigningKey,
        epoch: int,
        timestamp: str,
    ) -> KeyRotationRecord:
        """
        Create and sign a key-rotation record using both keys.

        Args:
            old_signing_key: Current signing key being rotated out.
            new_signing_key: Replacement signing key being rotated in.
            epoch: Rotation epoch (must be non-negative).
            timestamp: Rotation timestamp.

        Returns:
            Signed key-rotation record.

        Raises:
            ValueError: If epoch is negative.
        """
        if epoch < 0:
            raise ValueError("epoch must be non-negative")
        old_pubkey = old_signing_key.verify_key.encode()
        new_pubkey = new_signing_key.verify_key.encode()
        payload_hash = key_rotation_payload_hash(
            old_pubkey=old_pubkey,
            new_pubkey=new_pubkey,
            epoch=epoch,
            timestamp=timestamp,
        )
        return cls(
            old_pubkey=old_pubkey,
            new_pubkey=new_pubkey,
            epoch=epoch,
            timestamp=timestamp,
            signature_by_old=old_signing_key.sign(payload_hash).signature,
            signature_by_new=new_signing_key.sign(payload_hash).signature,
        )

    def payload_hash(self) -> bytes:
        """Return the canonical payload hash used for both signatures."""
        return key_rotation_payload_hash(
            old_pubkey=self.old_pubkey,
            new_pubkey=self.new_pubkey,
            epoch=self.epoch,
            timestamp=self.timestamp,
        )

    def verify_signatures(self) -> bool:
        """
        Verify both signatures in this key-rotation record.

        Returns:
            True when both old and new key signatures verify.
        """
        try:
            payload_hash = self.payload_hash()
            nacl.signing.VerifyKey(self.old_pubkey).verify(payload_hash, self.signature_by_old)
            nacl.signing.VerifyKey(self.new_pubkey).verify(payload_hash, self.signature_by_new)
            return True
        except (ValueError, nacl.exceptions.BadSignatureError):
            return False

    def to_dict(self) -> dict[str, str | int]:
        """Serialize this key-rotation record using hex-encoded bytes."""
        return {
            "old_pubkey": self.old_pubkey.hex(),
            "new_pubkey": self.new_pubkey.hex(),
            "epoch": self.epoch,
            "timestamp": self.timestamp,
            "signature_by_old": self.signature_by_old.hex(),
            "signature_by_new": self.signature_by_new.hex(),
        }

    def record_hash(self) -> bytes:
        """
        Return the domain-separated hash commitment of the full rotation record.

        Returns:
            32-byte BLAKE3 record hash for committing into the ledger.
        """
        return blake3_hash([KEY_ROTATION_PREFIX, canonical_json_bytes(self.to_dict())])

    def append_to_ledger(
        self,
        *,
        ledger: Ledger,
        shard_id: str,
        shard_root: str,
        canonicalization: dict[str, object],
    ) -> LedgerEntry:
        """
        Commit this key-rotation record to the append-only ledger.

        Args:
            ledger: Ledger instance to append to.
            shard_id: Shard identifier for the ledger entry.
            shard_root: Shard root hash (hex) associated with this rotation event.
            canonicalization: Canonicalization provenance metadata.

        Returns:
            Newly appended ledger entry.
        """
        return ledger.append(
            record_hash=self.record_hash().hex(),
            shard_id=shard_id,
            shard_root=shard_root,
            canonicalization=canonicalization,
        )


@dataclass
class KeyEvolutionChain:
    """Ordered key-rotation records that evolve from a genesis public key."""

    records: list[KeyRotationRecord] = field(default_factory=list)

    def add_record(self, record: KeyRotationRecord) -> None:
        """Append a rotation record to the chain."""
        self.records.append(record)

    def verify(self, genesis_pubkey: bytes) -> bool:
        """
        Verify this key evolution chain starting from a genesis key.

        Args:
            genesis_pubkey: Genesis Ed25519 public key (32 bytes).

        Returns:
            True if all links are valid and epoch order is strictly increasing.
        """
        current_pubkey = genesis_pubkey
        previous_epoch = -1
        for record in self.records:
            if record.old_pubkey != current_pubkey:
                return False
            if record.epoch <= previous_epoch:
                return False
            if not record.verify_signatures():
                return False
            current_pubkey = record.new_pubkey
            previous_epoch = record.epoch
        return True
