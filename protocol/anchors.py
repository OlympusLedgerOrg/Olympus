"""
Public anchoring helpers for Olympus ledger roots.

Anchors publish Merkle roots or ledger heads to external immutable systems
(blockchains or timestamp services). An :class:`AnchorCommitment` records the
anchored chain, reference (txid or receipt ID), timestamp, and a
domain-separated commitment hash that verifiers can recompute locally.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .canonical_json import canonical_json_bytes
from .hashes import ANCHOR_PREFIX, HASH_SEPARATOR, blake3_hash
from .timestamps import current_timestamp


_SEP = HASH_SEPARATOR.encode("utf-8")


def _normalize_hash(value: bytes | str) -> bytes:
    """Normalize a hex or byte hash to raw bytes."""
    if isinstance(value, str):
        hex_input = value
        try:
            value = bytes.fromhex(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid hex value: {hex_input}") from exc
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError("Hash must be bytes or hex string")
    if len(value) != 32:
        raise ValueError(f"Hash must be 32 bytes, got {len(value)}")
    return bytes(value)


def _normalize_timestamp(value: str | None) -> str:
    """Return an ISO 8601 UTC timestamp with Z suffix."""
    if value is None:
        return current_timestamp()
    ts = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(ts)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AnchorCommitment:
    """
    Commitment to a public anchor publication.

    Attributes:
        anchor_chain: Name of the anchor system (e.g., ``bitcoin``, ``ethereum``).
        merkle_root: Hex-encoded root that was anchored.
        anchor_reference: External reference such as txid, receipt ID, or TSA serial.
        anchored_at: ISO 8601 timestamp when the anchor was published.
        commitment_hash: Domain-separated hash of the anchor payload for inclusion
            in ledger entries or proofs.
        metadata: Optional anchor-specific metadata (e.g., block height).
    """

    anchor_chain: str
    merkle_root: str
    anchor_reference: str
    anchored_at: str
    commitment_hash: str
    metadata: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        anchor_chain: str,
        merkle_root: bytes | str,
        anchor_reference: str,
        anchored_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AnchorCommitment:
        """Build an :class:`AnchorCommitment` with a deterministic commitment hash."""
        root_bytes = _normalize_hash(merkle_root)
        normalized_ts = _normalize_timestamp(anchored_at)
        metadata_payload: dict[str, Any] = metadata or {}
        payload: dict[str, Any] = {
            "anchor_chain": anchor_chain,
            "anchor_reference": anchor_reference,
            "anchored_at": normalized_ts,
            "merkle_root": root_bytes.hex(),
            "metadata": metadata_payload,
        }
        commitment_hash = blake3_hash([ANCHOR_PREFIX, _SEP, canonical_json_bytes(payload)]).hex()
        return cls(
            anchor_chain=anchor_chain,
            merkle_root=root_bytes.hex(),
            anchor_reference=anchor_reference,
            anchored_at=normalized_ts,
            commitment_hash=commitment_hash,
            metadata=metadata_payload,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the anchor commitment to a dictionary."""
        return {
            "anchor_chain": self.anchor_chain,
            "merkle_root": self.merkle_root,
            "anchor_reference": self.anchor_reference,
            "anchored_at": self.anchored_at,
            "commitment_hash": self.commitment_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorCommitment:
        """Deserialize an :class:`AnchorCommitment` from a dictionary."""
        return cls(
            anchor_chain=str(data["anchor_chain"]),
            merkle_root=str(data["merkle_root"]),
            anchor_reference=str(data["anchor_reference"]),
            anchored_at=str(data["anchored_at"]),
            commitment_hash=str(data["commitment_hash"]),
            metadata=data.get("metadata", {}),
        )

    def verify(self, *, expected_root: bytes | str | None = None) -> bool:
        """
        Verify the commitment hash and optional expected root.

        Args:
            expected_root: Optional Merkle root that must match ``merkle_root``.

        Returns:
            True if the commitment hash recomputes and the optional expected
            root matches.
        """
        if expected_root is not None:
            try:
                expected_bytes = _normalize_hash(expected_root)
            except ValueError:
                return False
            if expected_bytes.hex() != self.merkle_root:
                return False

        payload = {
            "anchor_chain": self.anchor_chain,
            "anchor_reference": self.anchor_reference,
            "anchored_at": self.anchored_at,
            "merkle_root": self.merkle_root,
            "metadata": self.metadata,
        }
        recomputed = blake3_hash([ANCHOR_PREFIX, _SEP, canonical_json_bytes(payload)]).hex()
        return recomputed == self.commitment_hash
