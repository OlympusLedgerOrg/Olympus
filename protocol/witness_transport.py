"""
Witness transport helpers for checkpoint gossip and verification.

Packages :class:`~protocol.checkpoints.SignedCheckpoint` objects into
deterministic transport envelopes that witnesses can exchange via HTTP,
DNS, or other broadcast channels. Envelopes are self-verifiable using
BLAKE3 domain separation and canonical JSON encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical_json import canonical_json_bytes
from .checkpoints import SignedCheckpoint, verify_checkpoint
from .federation import FederationRegistry
from .hashes import HASH_SEPARATOR, blake3_hash
from .timestamps import current_timestamp


_TRANSPORT_PREFIX = b"OLY:WITNESS:PKT:V1"
_SEP = HASH_SEPARATOR.encode("utf-8")


def _canonical_payload(
    *, origin: str, observed_at: str, checkpoint: SignedCheckpoint
) -> bytes:
    """Return canonical JSON bytes for a witness announcement payload."""
    payload: dict[str, Any] = {
        "checkpoint": checkpoint.to_dict(),
        "observed_at": observed_at,
        "origin": origin,
    }
    return canonical_json_bytes(payload)


def compute_packet_hash(*, origin: str, observed_at: str, checkpoint: SignedCheckpoint) -> str:
    """
    Compute the BLAKE3 transport hash for a witness announcement.

    The hash domain-separates witness packets from other protocol hashes.
    """
    return blake3_hash([_TRANSPORT_PREFIX, _SEP, _canonical_payload(
        origin=origin, observed_at=observed_at, checkpoint=checkpoint
    )]).hex()


@dataclass(frozen=True)
class WitnessAnnouncement:
    """
    Transport envelope for a signed checkpoint observation.

    Attributes:
        origin: Node identifier or URL where the checkpoint was observed.
        checkpoint: Signed checkpoint being announced.
        observed_at: ISO 8601 timestamp (UTC, Z-suffixed) when observed.
        packet_hash: Domain-separated transport hash covering the payload.
    """

    origin: str
    checkpoint: SignedCheckpoint
    observed_at: str
    packet_hash: str

    @classmethod
    def create(
        cls,
        *,
        origin: str,
        checkpoint: SignedCheckpoint,
        observed_at: str | None = None,
        registry: FederationRegistry | None = None,
    ) -> WitnessAnnouncement:
        """
        Build a new witness announcement for a checkpoint observation.

        Args:
            origin: Source node identifier or URL.
            checkpoint: Signed checkpoint to transport.
            observed_at: Optional observation timestamp. Defaults to current UTC.
            registry: Optional federation registry to validate the checkpoint.

        Raises:
            ValueError: If checkpoint verification fails when a registry is supplied.
        """
        ts = observed_at or current_timestamp()
        if registry is not None and not verify_checkpoint(checkpoint, registry):
            raise ValueError("Checkpoint failed verification against supplied registry")
        packet_hash = compute_packet_hash(origin=origin, observed_at=ts, checkpoint=checkpoint)
        return cls(origin=origin, checkpoint=checkpoint, observed_at=ts, packet_hash=packet_hash)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the announcement to a JSON-safe dictionary."""
        return {
            "origin": self.origin,
            "checkpoint": self.checkpoint.to_dict(),
            "observed_at": self.observed_at,
            "packet_hash": self.packet_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WitnessAnnouncement:
        """Deserialize an announcement from a dictionary."""
        checkpoint = SignedCheckpoint.from_dict(data["checkpoint"])
        return cls(
            origin=str(data["origin"]),
            checkpoint=checkpoint,
            observed_at=str(data["observed_at"]),
            packet_hash=str(data["packet_hash"]),
        )


def verify_announcement(
    announcement: WitnessAnnouncement, *, registry: FederationRegistry | None = None
) -> bool:
    """
    Verify a witness announcement for integrity and (optionally) signatures.

    Args:
        announcement: Announcement to verify.
        registry: Optional federation registry for checkpoint verification.

    Returns:
        True if the packet hash (and optional checkpoint verification) succeed.
    """
    expected_hash = compute_packet_hash(
        origin=announcement.origin,
        observed_at=announcement.observed_at,
        checkpoint=announcement.checkpoint,
    )
    if announcement.packet_hash != expected_hash:
        return False

    if registry is None:
        return True

    return verify_checkpoint(announcement.checkpoint, registry)
