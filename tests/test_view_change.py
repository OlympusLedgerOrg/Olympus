"""Tests for view-change watermarks and grace-period validation."""

from types import SimpleNamespace

import hypothesis.strategies as st
import pytest
from hypothesis import assume, given, settings

from scaffolding.view_change import (
    GRACE_EPOCHS,
    MAX_WATERMARK_WINDOW,
    ConsensusState,
    ValidatorRegistry,
    VotingRound,
)


def test_grace_period_accepts_recently_removed_node() -> None:
    """Signatures from nodes removed mid-round stay valid during grace period."""
    registry = ValidatorRegistry({"n1", "n2"}, epoch=0)
    registry.apply_change(epoch=6, removed_members={"n2"})

    snapshot = registry.get_snapshot(5)
    signature = SimpleNamespace(node_id="n2")

    # Grace period starts at the round epoch and includes start_epoch + GRACE_EPOCHS.
    assert snapshot.is_member_at_epoch("n2", 5)
    # Within grace window: accept the signature even though the node was removed mid-round.
    round_state = VotingRound(round_num=1, start_epoch=5, registry_snapshot=snapshot)
    assert round_state.is_signature_valid(signature, current_epoch=6)
    assert round_state.is_signature_valid(signature, current_epoch=7)
    # After grace period expires, the same signature should be rejected.
    assert round_state.grace_period_end == 5 + GRACE_EPOCHS
    assert not round_state.is_signature_valid(signature, current_epoch=8)


def test_grace_period_rejects_unknown_nodes() -> None:
    """Unknown nodes are never admitted even during the grace period."""
    registry = ValidatorRegistry({"a", "b"}, epoch=0)
    round_state = ConsensusState().start_round(round_num=0, start_epoch=0, registry=registry)
    assert not round_state.is_signature_valid(SimpleNamespace(node_id="c"), current_epoch=0)


def test_watermark_gc_prunes_old_rounds() -> None:
    """Advancing the high watermark triggers GC to respect the window."""
    registry = ValidatorRegistry({"a", "b"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=3)
    for round_num in range(6):
        consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    assert consensus.low_watermark == 0
    assert consensus.high_watermark == 5

    consensus.advance_watermark(5)
    # Window exceeded: rounds below high-3 should be pruned (rounds 0 and 1).
    assert consensus.low_watermark == 2
    assert set(consensus.voting_rounds) == {2, 3, 4, 5}

    # Advancing within window should not trigger additional GC.
    consensus.advance_watermark(6)
    assert consensus.low_watermark == 3
    assert consensus.high_watermark == 6
    assert set(consensus.voting_rounds) == {3, 4, 5}


def test_watermark_rejects_backward_motion() -> None:
    consensus = ConsensusState(max_watermark_window=MAX_WATERMARK_WINDOW)
    registry = ValidatorRegistry({"x"}, epoch=0)
    consensus.start_round(round_num=0, start_epoch=0, registry=registry)
    consensus.advance_watermark(2)
    with pytest.raises(ValueError):
        consensus.advance_watermark(1)


# Property-based tests for watermark GC, grace period math, and epoch boundary logic


@given(
    round_sequence=st.lists(
        st.integers(min_value=0, max_value=100), min_size=1, max_size=20, unique=True
    ),
    max_window=st.integers(min_value=1, max_value=10),
)
@settings(max_examples=100, deadline=None)
def test_watermark_gc_maintains_window_invariant(
    round_sequence: list[int], max_window: int
) -> None:
    """
    Property: After advancing watermark, low/high gap never exceeds max_watermark_window.
    """
    registry = ValidatorRegistry({"a", "b"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=max_window)

    # Start rounds in sorted order
    for round_num in sorted(round_sequence):
        consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    # Advance to highest round
    highest = max(round_sequence)
    consensus.advance_watermark(highest)

    # Verify window constraint
    gap = consensus.high_watermark - consensus.low_watermark
    assert gap <= max_window, f"Gap {gap} exceeds max_window {max_window}"

    # Verify no rounds below cutoff remain
    cutoff = highest - max_window
    for round_num in consensus.voting_rounds:
        assert round_num >= cutoff, f"Round {round_num} below cutoff {cutoff} should be GC'd"


@given(
    round_sequence=st.lists(
        st.integers(min_value=0, max_value=50), min_size=2, max_size=15, unique=True
    ),
    watermark_advances=st.lists(st.integers(min_value=0, max_value=50), min_size=1, max_size=10),
)
@settings(max_examples=100, deadline=None)
def test_watermark_never_moves_backward(
    round_sequence: list[int], watermark_advances: list[int]
) -> None:
    """
    Property: High watermark must be monotonically increasing.
    """
    registry = ValidatorRegistry({"x", "y"}, epoch=0)
    consensus = ConsensusState()

    sorted_rounds = sorted(round_sequence)
    for round_num in sorted_rounds:
        consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    current_high = consensus.high_watermark
    for new_high in watermark_advances:
        if new_high >= current_high:
            consensus.advance_watermark(new_high)
            assert consensus.high_watermark == new_high
            current_high = new_high
        else:
            # Attempting backward motion should raise
            with pytest.raises(ValueError, match="cannot move backwards"):
                consensus.advance_watermark(new_high)


@given(
    grace_epochs=st.integers(min_value=0, max_value=10),
    start_epoch=st.integers(min_value=0, max_value=50),
    check_epochs=st.lists(st.integers(min_value=0, max_value=60), min_size=1, max_size=10),
)
@settings(max_examples=100, deadline=None)
def test_grace_period_boundary_is_start_plus_grace(
    grace_epochs: int, start_epoch: int, check_epochs: list[int]
) -> None:
    """
    Property: Grace period end is exactly start_epoch + grace_epochs.
    Within grace period (current_epoch <= grace_period_end), check membership at start_epoch.
    After grace period, check membership at current_epoch.
    """
    registry = ValidatorRegistry({"node-a", "node-b"}, epoch=0)
    # Remove node-b at an epoch after start
    removal_epoch = start_epoch + grace_epochs + 2
    registry.apply_change(epoch=removal_epoch, removed_members={"node-b"})

    snapshot = registry.get_snapshot(start_epoch)
    round_state = VotingRound(
        round_num=1, start_epoch=start_epoch, registry_snapshot=snapshot, grace_epochs=grace_epochs
    )

    expected_grace_end = start_epoch + grace_epochs
    assert round_state.grace_period_end == expected_grace_end

    signature_a = SimpleNamespace(node_id="node-a")
    signature_b = SimpleNamespace(node_id="node-b")

    for current_epoch in check_epochs:
        if current_epoch < start_epoch:
            # Before round start is invalid
            with pytest.raises(ValueError, match="cannot precede round start"):
                round_state.is_signature_valid(signature_a, current_epoch)
            continue

        # node-a is always valid (member from epoch 0)
        assert round_state.is_signature_valid(signature_a, current_epoch)

        if current_epoch <= expected_grace_end:
            # During grace period: node-b valid because it was member at start_epoch
            assert round_state.is_signature_valid(signature_b, current_epoch)
        elif current_epoch < removal_epoch:
            # After grace but before removal: node-b still valid
            assert round_state.is_signature_valid(signature_b, current_epoch)
        else:
            # After removal: node-b invalid
            assert not round_state.is_signature_valid(signature_b, current_epoch)


@given(
    membership_changes=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=100),  # epoch
            st.sets(
                st.sampled_from(["n1", "n2", "n3", "n4", "n5"]), min_size=1, max_size=3
            ),  # members
        ),
        min_size=1,
        max_size=10,
    ),
    query_epochs=st.lists(st.integers(min_value=0, max_value=100), min_size=1, max_size=5),
)
@settings(max_examples=100, deadline=None)
def test_registry_snapshot_membership_reflects_history(
    membership_changes: list[tuple[int, set[str]]], query_epochs: list[int]
) -> None:
    """
    Property: RegistrySnapshot.is_member_at_epoch returns membership based on history up to that epoch.
    """
    # Start with initial members
    initial_members = membership_changes[0][1]
    assume(len(initial_members) > 0)

    registry = ValidatorRegistry(initial_members, epoch=0)

    # Apply changes in epoch order
    sorted_changes = sorted(membership_changes[1:], key=lambda x: x[0])
    for change_epoch, new_members in sorted_changes:
        if change_epoch == 0:
            continue
        # Calculate delta
        current = set(registry._history[-1].members)
        added = new_members - current
        removed = current - new_members
        if not (new_members - removed):  # Would empty the registry
            continue
        try:
            registry.apply_change(epoch=change_epoch, added_members=added, removed_members=removed)
        except ValueError:
            # Skip invalid changes (non-monotonic epochs)
            pass

    snapshot = registry.get_snapshot(snapshot_epoch=max(query_epochs, default=0))

    for query_epoch in query_epochs:
        if query_epoch < 0:
            continue

        # Find expected members: use the most recent state <= query_epoch
        expected_members = registry._history[0].members
        for state in registry._history:
            if state.epoch > query_epoch:
                break
            expected_members = state.members

        # Verify snapshot returns correct membership
        for node_id in expected_members:
            assert snapshot.is_member_at_epoch(node_id, query_epoch), (
                f"Node {node_id} should be member at epoch {query_epoch}"
            )


@given(
    rounds_to_start=st.lists(
        st.integers(min_value=0, max_value=20), min_size=5, max_size=15, unique=True
    ),
    window_size=st.integers(min_value=2, max_value=8),
)
@settings(max_examples=100, deadline=None)
def test_gc_old_rounds_removes_only_old_rounds(
    rounds_to_start: list[int], window_size: int
) -> None:
    """
    Property: gc_old_rounds(cutoff) removes exactly those rounds with round_num < cutoff.
    """
    registry = ValidatorRegistry({"node"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=window_size)

    for round_num in sorted(rounds_to_start):
        consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    # Pick a cutoff in the middle of the range
    sorted_rounds = sorted(rounds_to_start)
    cutoff = (
        sorted_rounds[len(sorted_rounds) // 2] if len(sorted_rounds) > 1 else sorted_rounds[0] + 1
    )

    # Determine expected remaining rounds
    expected_remaining = {r for r in rounds_to_start if r >= cutoff}

    # Execute GC
    consensus.gc_old_rounds(cutoff)

    # Verify only rounds >= cutoff remain
    assert set(consensus.voting_rounds.keys()) == expected_remaining

    # Verify low_watermark updated correctly
    if expected_remaining:
        assert consensus.low_watermark == min(expected_remaining)
    else:
        assert consensus.low_watermark == cutoff
