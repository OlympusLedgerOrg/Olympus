"""
Epoch chaining utilities for Olympus.

Epoch heads provide optional linkage across Merkle roots by hashing the
previous epoch head, the current Merkle root, and associated metadata hash
with a fixed separator for structural disambiguation.
"""

from dataclasses import dataclass
from typing import Any

from .hashes import HASH_SEPARATOR, blake3_hash


_SEP = HASH_SEPARATOR.encode("utf-8")


def _normalize_hash(value: bytes | str, allow_empty: bool = False) -> bytes:
    """Normalize a hash input to raw bytes and validate length."""
    if isinstance(value, str):
        if value == "" and allow_empty:
            return b""
        try:
            hex_input = value
            value = bytes.fromhex(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid hex value: {hex_input}") from exc
    if not isinstance(value, bytes | bytearray):
        raise ValueError("Hash values must be bytes or hex strings")
    if len(value) == 0 and allow_empty:
        return bytes(value)
    if len(value) != 32:
        raise ValueError(f"Hash value must be 32 bytes, got {len(value)}")
    return bytes(value)


def compute_epoch_head(
    previous_head: bytes | str | None, merkle_root: bytes | str, metadata_hash: bytes | str
) -> bytes:
    """
    Compute the epoch head commitment.

    Args:
        previous_head: Previous epoch head (bytes or hex string). Use ``None`` or
            empty string for genesis.
        merkle_root: Current epoch Merkle root (bytes or hex string).
        metadata_hash: Hash of epoch metadata (bytes or hex string).

    Returns:
        32-byte BLAKE3 epoch head.
    """
    if previous_head is None or previous_head == "":
        prev = b""
    else:
        prev = _normalize_hash(previous_head, allow_empty=True)
    root_bytes = _normalize_hash(merkle_root)
    meta_bytes = _normalize_hash(metadata_hash)
    return blake3_hash([prev, _SEP, root_bytes, _SEP, meta_bytes])


@dataclass(frozen=True)
class EpochRecord:
    """
    Append-only epoch linkage record.

    Attributes:
        epoch_index: Monotonic epoch counter.
        merkle_root: Hex-encoded Merkle root for the epoch.
        metadata_hash: Hex-encoded hash of epoch metadata.
        previous_epoch_head: Hex-encoded previous epoch head (empty for genesis).
        epoch_head: Hex-encoded current epoch head.
    """

    epoch_index: int
    merkle_root: str
    metadata_hash: str
    previous_epoch_head: str
    epoch_head: str

    @classmethod
    def create(
        cls,
        *,
        epoch_index: int,
        merkle_root: bytes | str,
        metadata_hash: bytes | str,
        previous_epoch_head: bytes | str | None = None,
    ) -> "EpochRecord":
        """
        Build an :class:`EpochRecord` with validated inputs.

        Args:
            epoch_index: Monotonic epoch number (zero-based recommended).
            merkle_root: Merkle root for this epoch (bytes or hex string).
            metadata_hash: Hash of epoch metadata (bytes or hex string).
            previous_epoch_head: Previous epoch head (bytes, hex, or None for genesis).

        Returns:
            EpochRecord with computed epoch_head.

        Raises:
            ValueError: If inputs are invalid.
        """
        if epoch_index < 0:
            raise ValueError("epoch_index must be non-negative")

        root_bytes = _normalize_hash(merkle_root)
        metadata_bytes = _normalize_hash(metadata_hash)
        if previous_epoch_head is None or previous_epoch_head == "":
            prev_head_bytes = b""
        else:
            prev_head_bytes = _normalize_hash(previous_epoch_head, allow_empty=True)

        epoch_head = compute_epoch_head(prev_head_bytes, root_bytes, metadata_bytes)
        return cls(
            epoch_index=epoch_index,
            merkle_root=root_bytes.hex(),
            metadata_hash=metadata_bytes.hex(),
            previous_epoch_head=prev_head_bytes.hex(),
            epoch_head=epoch_head.hex(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a dictionary."""
        return {
            "epoch_index": self.epoch_index,
            "merkle_root": self.merkle_root,
            "metadata_hash": self.metadata_hash,
            "previous_epoch_head": self.previous_epoch_head,
            "epoch_head": self.epoch_head,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EpochRecord":
        """Deserialize an EpochRecord from a dictionary."""
        return cls(
            epoch_index=int(data["epoch_index"]),
            merkle_root=data["merkle_root"],
            metadata_hash=data["metadata_hash"],
            previous_epoch_head=data.get("previous_epoch_head", ""),
            epoch_head=data["epoch_head"],
        )
