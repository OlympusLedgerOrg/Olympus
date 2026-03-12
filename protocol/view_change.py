"""View-change watermarks and grace-period validation helpers.

⚠️  **Phase 1+ only — not implemented in v1.0.**

This module models the moving consensus window described in the problem
statement: voting rounds begin with a registry snapshot and allow a short
grace period where recently removed nodes can still participate.  A
watermark tracker keeps only the active window of rounds so replicas can
garbage-collect finalized state.

This module is part of the Guardian replication protocol and is NOT part of the
v1.0 single-node ledger. Civic tech partners should not assume live consensus
is available in production deployments until Phase 1+ is explicitly announced.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .telemetry import VIEW_CHANGE_WATERMARK, get_tracer


# Inclusive grace-period length applied to every voting round unless a custom
# override is provided by the caller.
GRACE_EPOCHS = 2

# Maximum gap allowed between low/high watermarks before old rounds must be
# garbage-collected.
MAX_WATERMARK_WINDOW = 50

_view_tracer = get_tracer("olympus.view_change")


@dataclass(frozen=True)
class RegistryState:
    """Immutable membership snapshot anchored to a registry epoch."""

    epoch: int
    members: frozenset[str]


class RegistrySnapshot:
    """Read-only view of registry membership across epochs.

    The snapshot is populated from the registry's immutable history so callers
    can perform membership checks without mutating shared state.
    """

    def __init__(self, *, history: Sequence[RegistryState], snapshot_epoch: int) -> None:
        if snapshot_epoch < 0:
            raise ValueError("Snapshot epoch must be non-negative")
        if not history:
            raise ValueError("Registry history cannot be empty")
        self._history: tuple[RegistryState, ...] = tuple(
            sorted(history, key=lambda item: item.epoch)
        )
        self.snapshot_epoch = snapshot_epoch

    def _membership_at_epoch(self, epoch: int) -> frozenset[str]:
        if epoch < 0:
            raise ValueError("Epoch must be non-negative")
        members: frozenset[str] = self._history[0].members
        for state in self._history[1:]:
            if state.epoch > epoch:
                break
            members = state.members
        return members

    def is_member_at_epoch(self, node_id: str, epoch: int) -> bool:
        """Return whether a node is a member at the requested epoch."""
        if not node_id:
            raise ValueError("node_id must be a non-empty string")
        return node_id in self._membership_at_epoch(epoch)


class ValidatorRegistry:
    """Mutable registry that tracks membership changes across epochs."""

    def __init__(self, members: Iterable[str], *, epoch: int = 0) -> None:
        initial_members = frozenset(members)
        if not initial_members:
            raise ValueError("Validator registry requires at least one member")
        if epoch < 0:
            raise ValueError("Registry epoch must be non-negative")
        self._history: list[RegistryState] = [RegistryState(epoch=epoch, members=initial_members)]

    @property
    def current_epoch(self) -> int:
        """Return the epoch of the latest registry state."""
        return self._history[-1].epoch

    def apply_change(
        self,
        *,
        epoch: int,
        added_members: Iterable[str] | None = None,
        removed_members: Iterable[str] | None = None,
    ) -> None:
        """Record membership changes effective at ``epoch``."""
        if epoch < self._history[-1].epoch:
            raise ValueError("Registry epochs must be monotonically increasing")
        added = set(added_members or ())
        removed = set(removed_members or ())
        members = set(self._history[-1].members)
        members |= added
        members -= removed
        if not members:
            raise ValueError("Registry cannot drop all members")
        self._history.append(RegistryState(epoch=epoch, members=frozenset(members)))

    def get_snapshot(self, snapshot_epoch: int) -> RegistrySnapshot:
        """Return an immutable snapshot of registry history."""
        return RegistrySnapshot(history=tuple(self._history), snapshot_epoch=snapshot_epoch)


@dataclass
class VotingRound:
    """Voting round bound to a registry snapshot and grace period."""

    round_num: int
    start_epoch: int
    registry_snapshot: RegistrySnapshot
    grace_epochs: int = GRACE_EPOCHS
    grace_period_end: int = field(init=False)

    def __post_init__(self) -> None:
        if self.round_num < 0:
            raise ValueError("round_num must be non-negative")
        if self.start_epoch < 0:
            raise ValueError("start_epoch must be non-negative")
        if self.grace_epochs < 0:
            raise ValueError("grace_epochs must be non-negative")
        self.grace_period_end = self.start_epoch + self.grace_epochs

    def _get_node_id(self, signature: object) -> str:
        node_id = getattr(signature, "node_id", None)
        if node_id is None:
            raise ValueError("Signature object must expose a node_id attribute")
        return str(node_id)

    def is_signature_valid(self, signature: object, current_epoch: int) -> bool:
        """Return whether ``signature`` should be accepted at ``current_epoch``."""
        node_id = self._get_node_id(signature)
        if current_epoch < self.start_epoch:
            raise ValueError("current_epoch cannot precede round start")
        if current_epoch <= self.grace_period_end:
            return self.registry_snapshot.is_member_at_epoch(node_id, self.start_epoch)
        return self.registry_snapshot.is_member_at_epoch(node_id, current_epoch)


@dataclass
class ConsensusState:
    """Track active voting rounds with low/high watermarks.

    All public methods acquire an internal ``threading.Lock`` so the object is
    safe to share across threads.  The lock is reentrant (``RLock``) because
    ``advance_watermark`` may call ``gc_old_rounds`` internally.
    """

    max_watermark_window: int = MAX_WATERMARK_WINDOW
    low_watermark: int = 0
    high_watermark: int = 0
    voting_rounds: dict[int, VotingRound] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def __getstate__(self) -> dict[str, object]:
        """Exclude the unpicklable lock from serialized state."""
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: dict[str, object]) -> None:
        """Restore state and recreate the lock after deserialization."""
        self.__dict__.update(state)
        self._lock = threading.RLock()

    def start_round(
        self,
        *,
        round_num: int,
        start_epoch: int,
        registry: ValidatorRegistry,
        grace_epochs: int | None = None,
    ) -> VotingRound:
        """Create and register a new voting round."""
        with self._lock:
            if round_num in self.voting_rounds:
                raise ValueError(f"Round {round_num} already exists")

            with _view_tracer.start_as_current_span("view_change.start_round") as span:
                span.set_attribute("round_num", round_num)
                span.set_attribute("start_epoch", start_epoch)
                span.set_attribute(
                    "grace_epochs", GRACE_EPOCHS if grace_epochs is None else grace_epochs
                )
                span.set_attribute("registry_epoch", registry.current_epoch)

                snapshot = registry.get_snapshot(start_epoch)
                voting_round = VotingRound(
                    round_num=round_num,
                    start_epoch=start_epoch,
                    registry_snapshot=snapshot,
                    grace_epochs=GRACE_EPOCHS if grace_epochs is None else grace_epochs,
                )
                had_rounds = bool(self.voting_rounds)
                self.voting_rounds[round_num] = voting_round
                if not had_rounds:
                    self.low_watermark = round_num
                else:
                    self.low_watermark = min(self.low_watermark, round_num)
                self.high_watermark = max(self.high_watermark, round_num)

                VIEW_CHANGE_WATERMARK.labels(bound="low").set(self.low_watermark)
                VIEW_CHANGE_WATERMARK.labels(bound="high").set(self.high_watermark)
                return voting_round

    def gc_old_rounds(self, cutoff_round: int) -> None:
        """Drop rounds older than ``cutoff_round`` and advance the low watermark."""
        with self._lock:
            with _view_tracer.start_as_current_span("view_change.gc_old_rounds") as span:
                span.set_attribute("cutoff_round", cutoff_round)

                removable = [
                    round_num for round_num in self.voting_rounds if round_num < cutoff_round
                ]
                span.set_attribute("removed_rounds", len(removable))
                for round_num in removable:
                    self.voting_rounds.pop(round_num, None)
                if self.voting_rounds:
                    self.low_watermark = min(self.voting_rounds.keys())
                else:
                    self.low_watermark = cutoff_round

                VIEW_CHANGE_WATERMARK.labels(bound="low").set(self.low_watermark)
                VIEW_CHANGE_WATERMARK.labels(bound="high").set(self.high_watermark)

    def advance_watermark(self, new_high: int) -> None:
        """Advance the high watermark while enforcing the maximum window size."""
        with self._lock:
            with _view_tracer.start_as_current_span("view_change.advance_watermark") as span:
                span.set_attribute("previous_high", self.high_watermark)
                span.set_attribute("requested_high", new_high)
                if new_high < self.high_watermark:
                    raise ValueError("High watermark cannot move backwards")
                if new_high - self.low_watermark > self.max_watermark_window:
                    cutoff = new_high - self.max_watermark_window
                    span.set_attribute("gc_cutoff", cutoff)
                    self.gc_old_rounds(cutoff)
                self.high_watermark = new_high
                VIEW_CHANGE_WATERMARK.labels(bound="high").set(self.high_watermark)
                VIEW_CHANGE_WATERMARK.labels(bound="low").set(self.low_watermark)
