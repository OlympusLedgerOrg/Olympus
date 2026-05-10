"""Gossip scaffolds for split-view detection.

Why this module exists:
    Gossip gives monitors a way to compare signed-root observations from
    independent peers and surface sequencer equivocation evidence publicly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from api.transparency.witness import WitnessCosignature


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SignedRootEnvelope:
    """Signed-root envelope shared between peers and monitors."""

    height: int
    root_hash: str
    sequencer_signature: str
    sequencer_key_id: str
    witness_cosignatures: list[WitnessCosignature]
    timestamp: str


@dataclass(frozen=True, slots=True)
class SplitViewEvidence:
    """Evidence that one sequencer key signed conflicting roots at one height."""

    height: int
    sequencer_key_id: str
    root_a: str
    root_b: str
    signature_a: str
    signature_b: str
    source_peer_a: str
    source_peer_b: str
    detected_at: str


class GossipPeer(Protocol):
    """Peer interface for gossip transport scaffolding."""

    peer_id: str

    async def submit_root(self, envelope: SignedRootEnvelope) -> None:
        """Submit a signed root to this peer."""

    async def fetch_peer_roots(self) -> list[SignedRootEnvelope]:
        """Fetch signed roots observed by this peer."""


async def submit_root(peer: GossipPeer, envelope: SignedRootEnvelope) -> None:
    """Submit a root envelope to a peer with defensive logging."""
    try:
        await peer.submit_root(envelope)
    except Exception:
        logger.error("Failed to submit root to gossip peer %s", peer.peer_id, exc_info=True)
        raise


async def fetch_peer_roots(peer: GossipPeer) -> list[SignedRootEnvelope]:
    """Fetch peer roots with defensive logging."""
    try:
        return await peer.fetch_peer_roots()
    except Exception:
        logger.error("Failed to fetch roots from gossip peer %s", peer.peer_id, exc_info=True)
        raise


def detect_equivocation(
    peer_a_roots: list[SignedRootEnvelope],
    peer_b_roots: list[SignedRootEnvelope],
) -> SplitViewEvidence | None:
    """Detect split-view evidence across two peer root sets."""
    try:
        by_height_a = {entry.height: entry for entry in peer_a_roots}
        by_height_b = {entry.height: entry for entry in peer_b_roots}
        for height in sorted(set(by_height_a).intersection(by_height_b)):
            root_a = by_height_a[height]
            root_b = by_height_b[height]
            if (
                root_a.sequencer_key_id == root_b.sequencer_key_id
                and root_a.root_hash != root_b.root_hash
                and root_a.sequencer_signature
                and root_b.sequencer_signature
            ):
                return SplitViewEvidence(
                    height=height,
                    sequencer_key_id=root_a.sequencer_key_id,
                    root_a=root_a.root_hash,
                    root_b=root_b.root_hash,
                    signature_a=root_a.sequencer_signature,
                    signature_b=root_b.sequencer_signature,
                    source_peer_a="peer_a",
                    source_peer_b="peer_b",
                    detected_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                )
        return None
    except Exception:
        logger.error("Failed to detect gossip equivocation", exc_info=True)
        return None
