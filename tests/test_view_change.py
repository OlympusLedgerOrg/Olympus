"""Tests for view-change watermarks and grace-period validation."""

from types import SimpleNamespace

import pytest

from protocol.view_change import (
    ConsensusState,
    GRACE_EPOCHS,
    MAX_WATERMARK_WINDOW,
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
