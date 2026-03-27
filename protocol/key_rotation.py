"""Key evolution chain for Ed25519 signing key rotation."""

from dataclasses import dataclass

import nacl.exceptions
import nacl.signing

from .canonical_json import canonical_json_bytes
from .hashes import KEY_ROTATION_PREFIX, blake3_hash
from .timestamps import current_timestamp


def _rotation_payload(
    *, old_pubkey: bytes, new_pubkey: bytes, epoch: int, timestamp: str
) -> dict[str, str | int]:
    """Build deterministic key-rotation payload fields."""
    if len(old_pubkey) != 32:
        raise ValueError(f"old_pubkey must be 32 bytes, got {len(old_pubkey)}")
    if len(new_pubkey) != 32:
        raise ValueError(f"new_pubkey must be 32 bytes, got {len(new_pubkey)}")
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("timestamp must be a non-empty string")
    return {
        "old_key": old_pubkey.hex(),
        "new_key": new_pubkey.hex(),
        "epoch": epoch,
        "timestamp": timestamp,
    }


def _rotation_hash(*, old_pubkey: bytes, new_pubkey: bytes, epoch: int, timestamp: str) -> bytes:
    """Compute the domain-separated key-rotation payload hash."""
    payload = _rotation_payload(
        old_pubkey=old_pubkey,
        new_pubkey=new_pubkey,
        epoch=epoch,
        timestamp=timestamp,
    )
    payload_bytes = canonical_json_bytes(payload)
    return blake3_hash([KEY_ROTATION_PREFIX, payload_bytes])


@dataclass(frozen=True)
class KeyRotationRecord:
    """A signed key-rotation event linking old and new Ed25519 public keys."""

    old_pubkey: bytes
    new_pubkey: bytes
    epoch: int
    timestamp: str
    signature_by_old: bytes
    signature_by_new: bytes
    record_hash: str


class KeyEvolutionChain:
    """Append-only key-rotation chain with dual-signature verification."""

    def __init__(self) -> None:
        """Initialize an empty key evolution chain."""
        self.rotations: list[KeyRotationRecord] = []
        self._genesis_pubkey: bytes | None = None

    def rotate(
        self,
        old_signing_key: nacl.signing.SigningKey,
        new_signing_key: nacl.signing.SigningKey,
        epoch: int,
    ) -> KeyRotationRecord:
        """Create, sign, and append a key-rotation record.

        Args:
            old_signing_key: Current signing key being rotated out.
            new_signing_key: Replacement signing key being rotated in.
            epoch: Monotonic key epoch.

        Returns:
            Appended key-rotation record.

        Raises:
            ValueError: If epoch is non-monotonic relative to existing records.
        """
        if self.rotations and epoch <= self.rotations[-1].epoch:
            raise ValueError(
                f"epoch {epoch} must be greater than previous epoch {self.rotations[-1].epoch}"
            )

        old_pubkey = bytes(old_signing_key.verify_key)
        new_pubkey = bytes(new_signing_key.verify_key)
        timestamp = current_timestamp()
        rotation_hash = _rotation_hash(
            old_pubkey=old_pubkey,
            new_pubkey=new_pubkey,
            epoch=epoch,
            timestamp=timestamp,
        )

        record = KeyRotationRecord(
            old_pubkey=old_pubkey,
            new_pubkey=new_pubkey,
            epoch=epoch,
            timestamp=timestamp,
            signature_by_old=old_signing_key.sign(rotation_hash).signature,
            signature_by_new=new_signing_key.sign(rotation_hash).signature,
            record_hash=rotation_hash.hex(),
        )
        if self._genesis_pubkey is None:
            self._genesis_pubkey = old_pubkey
        self.rotations.append(record)
        return record

    def verify(self, genesis_pubkey: bytes) -> bool:
        """Verify key continuity and signatures from the supplied genesis key.

        Args:
            genesis_pubkey: 32-byte Ed25519 verification key bytes.

        Returns:
            ``True`` if every rotation record links and verifies correctly.
        """
        if len(genesis_pubkey) != 32:
            return False
        self._genesis_pubkey = bytes(genesis_pubkey)
        if not self.rotations:
            return True

        expected_old = bytes(genesis_pubkey)
        previous_epoch = -1

        for rotation in self.rotations:
            if rotation.epoch <= previous_epoch:
                return False
            if rotation.old_pubkey != expected_old:
                return False

            rotation_hash = _rotation_hash(
                old_pubkey=rotation.old_pubkey,
                new_pubkey=rotation.new_pubkey,
                epoch=rotation.epoch,
                timestamp=rotation.timestamp,
            )
            if rotation.record_hash != rotation_hash.hex():
                return False

            try:
                nacl.signing.VerifyKey(rotation.old_pubkey).verify(
                    rotation_hash,
                    rotation.signature_by_old,
                )
                nacl.signing.VerifyKey(rotation.new_pubkey).verify(
                    rotation_hash,
                    rotation.signature_by_new,
                )
            except (nacl.exceptions.BadSignatureError, TypeError, ValueError):
                return False

            expected_old = rotation.new_pubkey
            previous_epoch = rotation.epoch

        return True

    def current_pubkey(self) -> bytes:
        """Return the currently valid public key for this chain."""
        if self.rotations:
            return self.rotations[-1].new_pubkey
        if self._genesis_pubkey is None:
            raise ValueError(
                "genesis pubkey is unknown; establish it via verify() or the first rotation"
            )
        return self._genesis_pubkey
