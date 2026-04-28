"""Checkpoint fork detection and in-memory registry helpers.

Import note: ``protocol.checkpoints`` imports this module for re-export, so
``protocol.checkpoints`` must **not** be imported at module scope here.
``verify_checkpoint`` and ``verify_checkpoint_chain`` are imported locally
inside the functions that call them to keep the import graph acyclic.
``SignedCheckpoint`` is imported from ``protocol.checkpoint_types``, which has
no cross-module protocol dependencies and is therefore safe to import here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .checkpoint_types import SignedCheckpoint
from .federation import FederationRegistry


def detect_checkpoint_fork(
    checkpoint_a: SignedCheckpoint,
    checkpoint_b: SignedCheckpoint,
) -> bool:
    """
    Detect if two checkpoints represent a fork in the ledger.

    A fork is detected when two checkpoints have:
    1. The same sequence number, OR
    2. The same previous_checkpoint_hash but different checkpoint_hash

    Args:
        checkpoint_a: First checkpoint
        checkpoint_b: Second checkpoint

    Returns:
        True if a fork is detected, False otherwise
    """
    # Same sequence but different content = fork
    if checkpoint_a.sequence == checkpoint_b.sequence:
        return checkpoint_a.checkpoint_hash != checkpoint_b.checkpoint_hash

    # Same parent but different checkpoints = fork
    if (
        checkpoint_a.previous_checkpoint_hash
        and checkpoint_a.previous_checkpoint_hash == checkpoint_b.previous_checkpoint_hash
    ):
        return checkpoint_a.checkpoint_hash != checkpoint_b.checkpoint_hash

    return False


class _ForkAccumulator:
    """Accumulates peer observations for a conflicting sequence/parent pair."""

    def __init__(self, sequence: int, previous_checkpoint_hash: str) -> None:
        self.sequence = sequence
        self.previous_checkpoint_hash = previous_checkpoint_hash
        self.peer_ids: set[str] = set()
        self.checkpoint_hashes: set[str] = set()
        self.peer_observations: dict[str, str] = {}

    def add_observations(self, observations: list[tuple[str, SignedCheckpoint]]) -> None:
        """
        Merge peer observations into this evidence bucket.

        Repeated observations from the same peer with the same checkpoint
        hash are tolerated; conflicting checkpoints from the same peer
        trigger a ValueError to avoid masking equivocation evidence.
        """
        for peer_id, checkpoint in observations:
            existing_hash = self.peer_observations.get(peer_id)
            if existing_hash is not None and existing_hash != checkpoint.checkpoint_hash:
                raise ValueError(
                    f"Peer {peer_id} supplied multiple conflicting checkpoints for the "
                    "same sequence/parent gossip bucket"
                )
            self.peer_observations.setdefault(peer_id, checkpoint.checkpoint_hash)
            self.peer_ids.add(peer_id)
            self.checkpoint_hashes.add(checkpoint.checkpoint_hash)


def _record_conflict(
    sequence: int,
    previous_hash: str,
    observations: list[tuple[str, SignedCheckpoint]],
    accumulators: dict[tuple[int, str], _ForkAccumulator],
) -> None:
    """
    Record a conflicting set of observations for a sequence/parent pair.

    Creates or reuses an accumulator keyed by (sequence, previous_hash) and
    adds all provided peer observations to that evidence bucket.
    """
    key = (sequence, previous_hash)
    accumulator = accumulators.get(key)
    if accumulator is None:
        accumulator = _ForkAccumulator(sequence, previous_hash)
        accumulators[key] = accumulator
    accumulator.add_observations(observations)


@dataclass(frozen=True)
class GossipForkEvidence:
    """
    Fork evidence derived from gossiping checkpoints between peers.

    Attributes:
        sequence: Highest conflicting sequence number for the divergence.
        previous_checkpoint_hash: Parent hash when all conflicting checkpoints
            agree on the parent, or empty string when the parent itself is
            disputed (including genesis disagreements).
        peer_ids: Tuple of peer identifiers that presented conflicting checkpoints.
        checkpoint_hashes: Tuple of conflicting checkpoint hashes observed.
    """

    sequence: int
    previous_checkpoint_hash: str
    peer_ids: tuple[str, ...]
    checkpoint_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if len(self.peer_ids) < 2:
            raise ValueError("peer_ids must include at least two peers")
        if len(set(self.peer_ids)) != len(self.peer_ids):
            raise ValueError("peer_ids must be unique")
        if len(self.checkpoint_hashes) < 2:
            raise ValueError("checkpoint_hashes must include at least two hashes")
        if len(set(self.checkpoint_hashes)) != len(self.checkpoint_hashes):
            raise ValueError("checkpoint_hashes must be unique")


def detect_gossip_checkpoint_forks(
    *,
    observations: Mapping[str, SignedCheckpoint],
    registry: FederationRegistry | None = None,
) -> tuple[GossipForkEvidence, ...]:
    """
    Detect forks by comparing gossiped checkpoints from multiple peers.

    This helper is intended for witness clients that exchange checkpoints
    over a gossip layer. If two peers present checkpoints that conflict
    according to `detect_checkpoint_fork`, fork evidence is emitted that
    identifies the conflicting peers and checkpoint hashes.

    Args:
        observations: Mapping of peer identifier -> SignedCheckpoint observed
        registry: Optional federation registry used to verify each checkpoint

    Returns:
        Tuple of GossipForkEvidence objects describing detected forks.

        Each evidence record captures a single divergence point. The
        `sequence` reflects the highest sequence number among the conflicting
        checkpoints for a shared parent (or the common sequence when hashes
        diverge at the same height). The `previous_checkpoint_hash` is
        populated when all conflicting checkpoints share the same parent;
        otherwise it is the empty string to indicate parent disagreement.

    Raises:
        ValueError: If any provided checkpoint fails verification when a
            registry is supplied.
    """
    if not observations:
        return ()

    peer_items = sorted(observations.items(), key=lambda item: item[0])
    if registry is not None:
        from .checkpoints import verify_checkpoint

        for peer_id, checkpoint in peer_items:
            if not verify_checkpoint(checkpoint, registry):
                raise ValueError(f"Invalid checkpoint from peer {peer_id}")

    accumulators: dict[tuple[int, str], _ForkAccumulator] = {}
    # The accumulators dictionary is keyed by (sequence, previous_hash). An
    # empty previous_hash sentinel indicates that conflicting checkpoints do
    # not agree on the parent hash.

    # Group by sequence to find equivocations at the same height.
    sequence_groups: dict[int, list[tuple[str, SignedCheckpoint]]] = {}
    for peer_id, checkpoint in peer_items:
        sequence_groups.setdefault(checkpoint.sequence, []).append((peer_id, checkpoint))

    for sequence, observations_for_sequence in sequence_groups.items():
        hashes = {checkpoint.checkpoint_hash for _, checkpoint in observations_for_sequence}
        if len(hashes) <= 1:
            continue

        previous_hashes = {
            checkpoint.previous_checkpoint_hash
            for _, checkpoint in observations_for_sequence
            if checkpoint.previous_checkpoint_hash
        }
        previous_hash = next(iter(previous_hashes)) if len(previous_hashes) == 1 else ""
        _record_conflict(sequence, previous_hash, observations_for_sequence, accumulators)

    # Group by parent to find forks that diverge after the same checkpoint, even if
    # the divergent checkpoints have different sequence numbers. Conflicts detected
    # in both passes are merged by the shared accumulator key.
    parent_groups: dict[str, list[tuple[str, SignedCheckpoint]]] = {}
    for peer_id, checkpoint in peer_items:
        # Ignore genesis checkpoints (empty parent) since any genesis equivocation
        # is already captured by sequence-based grouping above.
        if checkpoint.previous_checkpoint_hash:
            parent_groups.setdefault(checkpoint.previous_checkpoint_hash, []).append(
                (peer_id, checkpoint)
            )

    for previous_hash, observations_for_parent in parent_groups.items():
        hashes = {checkpoint.checkpoint_hash for _, checkpoint in observations_for_parent}
        if len(hashes) <= 1:
            continue

        # Report the highest conflicting sequence observed for this parent to
        # capture the latest divergent tip witnesses have seen.
        highest_sequence = max(checkpoint.sequence for _, checkpoint in observations_for_parent)
        _record_conflict(highest_sequence, previous_hash, observations_for_parent, accumulators)

    evidences = [
        GossipForkEvidence(
            sequence=sequence,
            previous_checkpoint_hash=previous_hash,
            peer_ids=tuple(sorted(acc.peer_ids)),
            checkpoint_hashes=tuple(sorted(acc.checkpoint_hashes)),
        )
        for (sequence, previous_hash), acc in sorted(accumulators.items())
        if len(acc.peer_ids) >= 2 and len(acc.checkpoint_hashes) >= 2
    ]
    return tuple(evidences)


class CheckpointRegistry:
    """
    Registry for storing and verifying checkpoint chains.

    This class provides an in-memory store for checkpoints with methods
    to verify chain integrity and detect forks. Verification is bound
    to a federation registry for quorum certificate validation.
    """

    def __init__(self, registry: FederationRegistry) -> None:
        """Initialize an empty checkpoint registry bound to a federation registry."""
        self.checkpoints: list[SignedCheckpoint] = []
        self.registry = registry

    def add_checkpoint(self, checkpoint: SignedCheckpoint) -> bool:
        """
        Add a checkpoint to the registry.

        Args:
            checkpoint: Checkpoint to add

        Returns:
            True if checkpoint was added successfully, False if invalid

        Raises:
            ValueError: If checkpoint would create a fork
        """
        # Verify checkpoint is valid
        from .checkpoints import verify_checkpoint

        if not verify_checkpoint(checkpoint, self.registry):
            return False

        # Check for forks
        for existing in self.checkpoints:
            if detect_checkpoint_fork(checkpoint, existing):
                raise ValueError(
                    f"Fork detected: checkpoint {checkpoint.sequence} conflicts "
                    f"with existing checkpoint {existing.sequence}"
                )

        # Verify it links to the previous checkpoint
        if self.checkpoints:
            latest = self.checkpoints[-1]
            if checkpoint.sequence <= latest.sequence:
                # Allow out-of-order if it's filling a gap
                pass  # pragma: no cover — pass is a no-op; branch exercised by fall-through
            elif checkpoint.previous_checkpoint_hash != latest.checkpoint_hash:
                return False

        self.checkpoints.append(checkpoint)
        self.checkpoints.sort(key=lambda c: c.sequence)
        return True

    def verify_registry(self, finality_anchors: Mapping[int, str] | None = None) -> bool:
        """
        Verify the entire checkpoint registry.

        Returns:
            True if all checkpoints form a valid chain
        """
        from .checkpoints import verify_checkpoint_chain

        return verify_checkpoint_chain(
            self.checkpoints,
            self.registry,
            finality_anchors=finality_anchors,
        )

    def get_checkpoint(self, sequence: int) -> SignedCheckpoint | None:
        """
        Retrieve a checkpoint by sequence number.

        Args:
            sequence: Checkpoint sequence number

        Returns:
            Checkpoint if found, None otherwise
        """
        for checkpoint in self.checkpoints:
            if checkpoint.sequence == sequence:
                return checkpoint
        return None

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        """
        Get the most recent checkpoint.

        Returns:
            Latest checkpoint if registry is non-empty, None otherwise
        """
        return self.checkpoints[-1] if self.checkpoints else None

    def get_all_checkpoints(self) -> list[SignedCheckpoint]:
        """Get all checkpoints in chronological order."""
        return self.checkpoints.copy()
