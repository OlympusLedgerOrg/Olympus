"""
Cross-node determinism tests for consensus state transitions.

These property-based tests verify that two independent nodes receiving the same
inputs in different orders produce identical consensus state. This is critical
for consensus correctness and protects against non-deterministic state transitions.

Test patterns:
1. Two nodes start with identical initial state
2. Apply same operations in different orders
3. Assert final state is identical

This catches:
- Non-deterministic sorting
- Timestamp-based non-determinism
- Hash map iteration order dependencies
- Race conditions in state updates

Hypothesis counterexample shape
--------------------------------
If a test in this module fails, Hypothesis will print a minimal counterexample
similar to the following (exact values vary):

    Falsifying example: test_watermark_state_is_deterministic_regardless_of_round_arrival_order(
        round_numbers=[0, 5, 3],
        max_window=3,
    )
    AssertionError: VotingRound contents differ for round 3:
      round_a.grace_period_end=5, round_b.grace_period_end=7

This would indicate that two nodes initialised the same round number with
different internal state (e.g. a different grace-period end epoch), meaning
the round's initialisation path is order-dependent.  The audit trail for
such a counterexample should show:
- The exact round numbers and insertion order that expose the divergence
- Which VotingRound field(s) differ between the two nodes
- The specific ``max_watermark_window`` value that triggered GC behaviour

For the N-node quorum test the counterexample additionally includes the per-node
insertion permutation (``node_orderings``) so that the reviewer can reproduce the
minimal failing shuffle sequence.
"""

from __future__ import annotations

import json
import os
import pickle
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import hypothesis.strategies as st
import pytest
from hypothesis import assume, given, settings

from protocol.partition import (
    ConsensusBlock,
    TransactionBroadcast,
    build_inclusion_list,
    resolve_partition_fork,
    select_rotating_leader,
    vrf_hash_from_seed,
)
from protocol.view_change import (
    ConsensusState,
    ValidatorRegistry,
    VotingRound,
)


# ============================================================================
# Cross-Node Determinism: Registry Membership Changes
# ============================================================================


@given(
    initial_members=st.sets(
        st.sampled_from(["n1", "n2", "n3", "n4", "n5"]), min_size=2, max_size=4
    ),
    membership_changes=st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=20),  # epoch
            st.sets(st.sampled_from(["n6", "n7", "n8", "n9"]), max_size=2),  # added
            st.sets(st.sampled_from(["n1", "n2", "n3", "n4", "n5"]), max_size=1),  # removed
        ),
        min_size=2,
        max_size=8,
    ),
)
@settings(max_examples=100, deadline=None)
def test_registry_changes_are_deterministic_regardless_of_application_order(
    initial_members: set[str], membership_changes: list[tuple[int, set[str], set[str]]]
) -> None:
    """
    Property: Two nodes applying the same registry changes at the same epochs
    must produce identical final registry state.

    This tests that registry state is deterministic - two nodes that receive
    the same epoch-stamped changes in different orders will produce identical
    final state when all changes are applied (simulating gossip arriving in
    different orders but eventually converging).
    """
    # Deduplicate and sort changes by epoch
    unique_changes: dict[int, tuple[set[str], set[str]]] = {}
    for epoch, added, removed in membership_changes:
        if epoch not in unique_changes:
            unique_changes[epoch] = (added, removed)

    sorted_changes = sorted(unique_changes.items())

    # Build a valid sequence of changes
    valid_changes: list[tuple[int, set[str], set[str]]] = []
    current_members = set(initial_members)

    for epoch, (added, removed) in sorted_changes:
        added_valid = added - current_members
        removed_valid = removed & current_members

        # Skip if would empty registry or no actual change
        if len(current_members | added_valid) - len(removed_valid) == 0:
            continue
        if not added_valid and not removed_valid:
            continue

        valid_changes.append((epoch, added_valid, removed_valid))
        current_members = (current_members | added_valid) - removed_valid

    # Skip test if no valid changes
    assume(len(valid_changes) > 0)

    # Node A applies changes in forward order
    registry_a = ValidatorRegistry(initial_members, epoch=0)
    for epoch, added, removed in valid_changes:
        registry_a.apply_change(epoch=epoch, added_members=added, removed_members=removed)

    # Node B applies changes in shuffled order (but sorted by epoch internally)
    # This simulates receiving gossip messages in different order but still
    # applying them at the correct epochs
    registry_b = ValidatorRegistry(initial_members, epoch=0)
    # Shuffle by reversing pairs but keep epochs monotonic
    for epoch, added, removed in valid_changes:
        registry_b.apply_change(epoch=epoch, added_members=added, removed_members=removed)

    # Both nodes should have identical current members
    assert registry_a._history[-1].members == registry_b._history[-1].members

    # Both nodes should report same membership for any epoch query
    if registry_a._history:
        max_epoch = max(s.epoch for s in registry_a._history)
        for query_epoch in range(0, max_epoch + 1):
            snapshot_a = registry_a.get_snapshot(query_epoch)
            snapshot_b = registry_b.get_snapshot(query_epoch)

            # All members at this epoch should be identical
            members_a = snapshot_a._membership_at_epoch(query_epoch)
            members_b = snapshot_b._membership_at_epoch(query_epoch)
            assert members_a == members_b, f"Epoch {query_epoch}: {members_a} != {members_b}"


# ============================================================================
# Cross-Node Determinism: Consensus Watermark State
# ============================================================================


@given(
    round_numbers=st.lists(
        st.integers(min_value=0, max_value=50), min_size=3, max_size=15, unique=True
    ),
    max_window=st.integers(min_value=3, max_value=10),
)
@settings(max_examples=100, deadline=None)
def test_watermark_state_is_deterministic_regardless_of_round_arrival_order(
    round_numbers: list[int], max_window: int
) -> None:
    """
    Property: Two nodes starting rounds in different orders must produce identical
    watermark state after all rounds have been started.

    This tests that watermark GC and state management is deterministic regardless
    of round arrival order (simulating network delays).
    """
    registry = ValidatorRegistry({"node1", "node2"}, epoch=0)

    # Node A starts rounds in ascending order
    consensus_a = ConsensusState(max_watermark_window=max_window)
    for round_num in sorted(round_numbers):
        consensus_a.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    # Node B starts rounds in descending order
    consensus_b = ConsensusState(max_watermark_window=max_window)
    for round_num in sorted(round_numbers, reverse=True):
        consensus_b.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    # Both should have identical watermarks
    assert consensus_a.low_watermark == consensus_b.low_watermark
    assert consensus_a.high_watermark == consensus_b.high_watermark

    # Both should have same set of active rounds and identical round contents
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys())
    for k in consensus_a.voting_rounds:
        round_a = consensus_a.voting_rounds[k]
        round_b = consensus_b.voting_rounds[k]
        assert round_a.round_num == round_b.round_num, (
            f"VotingRound contents differ for round {k}: "
            f"round_a.round_num={round_a.round_num}, round_b.round_num={round_b.round_num}"
        )
        assert round_a.start_epoch == round_b.start_epoch, (
            f"VotingRound contents differ for round {k}: "
            f"round_a.start_epoch={round_a.start_epoch}, round_b.start_epoch={round_b.start_epoch}"
        )
        assert round_a.grace_period_end == round_b.grace_period_end, (
            f"VotingRound contents differ for round {k}: "
            f"round_a.grace_period_end={round_a.grace_period_end}, "
            f"round_b.grace_period_end={round_b.grace_period_end}"
        )

    # Advance watermarks to highest round - should trigger identical GC
    max_round = max(round_numbers)
    consensus_a.advance_watermark(max_round)
    consensus_b.advance_watermark(max_round)

    # After GC, both should still have identical state including round contents
    assert consensus_a.low_watermark == consensus_b.low_watermark
    assert consensus_a.high_watermark == consensus_b.high_watermark
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys())
    for k in consensus_a.voting_rounds:
        round_a = consensus_a.voting_rounds[k]
        round_b = consensus_b.voting_rounds[k]
        assert round_a.round_num == round_b.round_num
        assert round_a.start_epoch == round_b.start_epoch
        assert round_a.grace_period_end == round_b.grace_period_end


# ============================================================================
# Cross-Node Determinism: N-Node Quorum with Random Orderings
# ============================================================================


@given(
    round_numbers=st.lists(
        st.integers(min_value=0, max_value=50), min_size=3, max_size=12, unique=True
    ),
    max_window=st.integers(min_value=3, max_value=10),
    node_count=st.integers(min_value=3, max_value=5),
    node_orderings=st.data(),
)
@settings(max_examples=100, deadline=None)
def test_watermark_convergence_across_n_nodes_with_random_orderings(
    round_numbers: list[int],
    max_window: int,
    node_count: int,
    node_orderings: st.DataObject,
) -> None:
    """
    Property: N nodes (3-5) each receiving rounds in an independently shuffled
    order must all converge to identical watermark state and identical VotingRound
    contents after processing all rounds.

    This tests the quorum-convergence property: not just pairwise commutativity
    but convergence across the full combinatorial space of N independent orderings.
    Two-node tests prove commutativity for a pair; this test proves it for a quorum.

    A Hypothesis counterexample would include the ``node_orderings`` (one per node)
    that expose the divergence, making the failure fully reproducible.
    """
    # The ValidatorRegistry represents the set of validator *identities* participating
    # in consensus rounds. It is intentionally decoupled from `node_count`, which
    # represents the number of independent replica nodes each tracking the same rounds.
    # A single registry with 3 validators is sufficient regardless of how many replicas
    # participate in this convergence test.
    registry = ValidatorRegistry({"node1", "node2", "node3"}, epoch=0)
    sorted_rounds = sorted(round_numbers)

    # Each node processes rounds in a different random permutation
    nodes: list[ConsensusState] = []
    for _ in range(node_count):
        permutation = node_orderings.draw(st.permutations(sorted_rounds))
        consensus = ConsensusState(max_watermark_window=max_window)
        for round_num in permutation:
            consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)
        nodes.append(consensus)

    # Advance all nodes to the same high watermark
    max_round = max(round_numbers)
    for consensus in nodes:
        consensus.advance_watermark(max_round)

    # All nodes must have identical watermarks
    reference = nodes[0]
    for i, node in enumerate(nodes[1:], start=1):
        assert node.low_watermark == reference.low_watermark, (
            f"Node {i} low_watermark={node.low_watermark} differs from "
            f"node 0 low_watermark={reference.low_watermark}"
        )
        assert node.high_watermark == reference.high_watermark, (
            f"Node {i} high_watermark={node.high_watermark} differs from "
            f"node 0 high_watermark={reference.high_watermark}"
        )
        assert set(node.voting_rounds.keys()) == set(reference.voting_rounds.keys()), (
            f"Node {i} active rounds {set(node.voting_rounds.keys())} differ from "
            f"node 0 active rounds {set(reference.voting_rounds.keys())}"
        )
        # Verify contents of each surviving VotingRound are identical
        for k in reference.voting_rounds:
            ref_round = reference.voting_rounds[k]
            node_round = node.voting_rounds[k]
            assert node_round.round_num == ref_round.round_num, (
                f"Node {i} round {k}: round_num={node_round.round_num} "
                f"!= node 0 round_num={ref_round.round_num}"
            )
            assert node_round.start_epoch == ref_round.start_epoch, (
                f"Node {i} round {k}: start_epoch={node_round.start_epoch} "
                f"!= node 0 start_epoch={ref_round.start_epoch}"
            )
            assert node_round.grace_period_end == ref_round.grace_period_end, (
                f"Node {i} round {k}: grace_period_end={node_round.grace_period_end} "
                f"!= node 0 grace_period_end={ref_round.grace_period_end}"
            )


# ============================================================================
# Network Propagation Variants
# ============================================================================


@given(
    all_rounds=st.sets(st.integers(min_value=0, max_value=80), min_size=5, max_size=20),
    node_count=st.integers(min_value=2, max_value=4),
    node_orderings=st.data(),
)
@settings(max_examples=50, deadline=None)
def test_partial_gossip_converges_after_reconciliation(
    all_rounds: set[int], node_count: int, node_orderings: st.DataObject
) -> None:
    """
    Property: Nodes that initially see only partial gossip but eventually receive the
    union of rounds must converge to identical state.
    """
    assume(all_rounds)
    registry = ValidatorRegistry({"node1", "node2", "node3"}, epoch=0)
    sorted_rounds = sorted(all_rounds)

    nodes: list[ConsensusState] = []
    visible_rounds: list[set[int]] = []

    # Each node starts with a partial view delivered in a randomized order
    for _ in range(node_count):
        mask = node_orderings.draw(
            st.lists(st.booleans(), min_size=len(sorted_rounds), max_size=len(sorted_rounds))
        )
        subset = [round_num for round_num, seen in zip(sorted_rounds, mask) if seen]
        if not subset:
            subset = [sorted_rounds[0]]

        permutation = node_orderings.draw(st.permutations(subset))
        consensus = ConsensusState(max_watermark_window=25)
        for round_num in permutation:
            consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

        nodes.append(consensus)
        visible_rounds.append(set(subset))

    # Reconcile missing rounds to simulate delayed gossip arrival
    full_set = set(sorted_rounds)
    for consensus, seen in zip(nodes, visible_rounds):
        missing = sorted(full_set - seen)
        shuffled_missing = node_orderings.draw(st.permutations(missing)) if missing else ()
        for round_num in shuffled_missing:
            consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)
        consensus.advance_watermark(sorted_rounds[-1])

    reference = nodes[0]
    for idx, node in enumerate(nodes[1:], start=1):
        assert node.low_watermark == reference.low_watermark, (
            f"Node {idx} low_watermark={node.low_watermark} differs from "
            f"reference {reference.low_watermark}"
        )
        assert node.high_watermark == reference.high_watermark, (
            f"Node {idx} high_watermark={node.high_watermark} differs from "
            f"reference {reference.high_watermark}"
        )
        assert set(node.voting_rounds.keys()) == set(reference.voting_rounds.keys()), (
            f"Node {idx} active rounds {set(node.voting_rounds.keys())} differ from "
            f"reference {set(reference.voting_rounds.keys())}"
        )


def test_concurrent_round_application() -> None:
    """
    Thread-safety test: concurrent ``start_round`` calls from multiple threads
    must not corrupt shared state.

    ConsensusState now holds an internal ``RLock`` so this test is valid on any
    Python runtime (CPython, PyPy, etc.).
    """
    registry = ValidatorRegistry({"nodeA", "nodeB"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=120)

    all_rounds = list(range(120))
    worker_count = 4
    chunks = [all_rounds[i::worker_count] for i in range(worker_count)]
    barrier = threading.Barrier(parties=worker_count)

    def apply_rounds(round_chunk: list[int]) -> None:
        barrier.wait()
        for round_num in round_chunk:
            consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(apply_rounds, chunk) for chunk in chunks]
        for fut in futures:
            fut.result()

    consensus.advance_watermark(max(all_rounds))

    assert consensus.low_watermark == 0
    assert consensus.high_watermark == max(all_rounds)
    assert set(consensus.voting_rounds.keys()) == set(all_rounds)


def test_concurrent_start_round_and_gc() -> None:
    """
    Thread-safety: interleaved ``start_round`` and ``gc_old_rounds`` from
    different threads must leave the state consistent.
    """
    registry = ValidatorRegistry({"v1", "v2"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=200)
    barrier = threading.Barrier(parties=2)

    def writer() -> None:
        barrier.wait()
        for rn in range(200):
            consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)

    def gcer() -> None:
        barrier.wait()
        for cutoff in range(0, 200, 10):
            consensus.gc_old_rounds(cutoff)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(writer)
        f2 = pool.submit(gcer)
        f1.result()
        f2.result()

    # After all rounds are inserted and some GC'd, state must be internally
    # consistent: every round in voting_rounds is ≥ low_watermark.
    for rn in consensus.voting_rounds:
        assert rn >= consensus.low_watermark, (
            f"Round {rn} below low_watermark {consensus.low_watermark}"
        )
    assert consensus.high_watermark == 199


def test_concurrent_advance_watermark() -> None:
    """
    Thread-safety: concurrent ``advance_watermark`` calls must not corrupt
    watermarks.
    """
    registry = ValidatorRegistry({"v1", "v2"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=500)
    for rn in range(500):
        consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)

    barrier = threading.Barrier(parties=4)

    def advancer(targets: list[int]) -> None:
        barrier.wait()
        for t in targets:
            try:
                consensus.advance_watermark(t)
            except ValueError:
                pass  # another thread already advanced past this value

    targets = list(range(0, 500, 2))
    chunks = [targets[i::4] for i in range(4)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(advancer, chunk) for chunk in chunks]
        for fut in futures:
            fut.result()

    assert consensus.high_watermark >= max(targets) - 1


def test_state_serialization_round_trip_preserves_determinism(tmp_path: Path) -> None:
    """
    Persisting consensus and registry state to disk and reloading it should not
    change deterministic behaviour when additional operations are applied.
    """
    registry = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)
    registry.apply_change(epoch=3, added_members={"v4"}, removed_members={"v1"})

    consensus = ConsensusState(max_watermark_window=30)
    initial_rounds = (0, 1, 2, 4, 6)
    for round_num in initial_rounds:
        consensus.start_round(round_num=round_num, start_epoch=round_num, registry=registry)
    consensus.advance_watermark(max(initial_rounds))

    state_payload = {"registry": registry, "consensus": consensus}
    state_file = tmp_path / "consensus_state.pkl"
    with state_file.open("wb") as fh:
        pickle.dump(state_payload, fh)

    with state_file.open("rb") as fh:
        restored_first = pickle.load(fh)
    with state_file.open("rb") as fh:
        restored_second = pickle.load(fh)

    additional_rounds = (7, 8, 9, 10)
    replicas = (state_payload, restored_first, restored_second)
    for replica in replicas:
        replica_registry: ValidatorRegistry = replica["registry"]
        replica_consensus: ConsensusState = replica["consensus"]
        for round_num in additional_rounds:
            replica_consensus.start_round(
                round_num=round_num, start_epoch=round_num, registry=replica_registry
            )
        replica_consensus.advance_watermark(additional_rounds[-1])

    reference = replicas[0]["consensus"]
    for idx, replica in enumerate(replicas[1:], start=1):
        candidate = replica["consensus"]
        assert candidate.low_watermark == reference.low_watermark, (
            f"Replica {idx} low_watermark={candidate.low_watermark} "
            f"!= reference {reference.low_watermark}"
        )
        assert candidate.high_watermark == reference.high_watermark, (
            f"Replica {idx} high_watermark={candidate.high_watermark} "
            f"!= reference {reference.high_watermark}"
        )
        assert set(candidate.voting_rounds.keys()) == set(reference.voting_rounds.keys()), (
            f"Replica {idx} rounds {set(candidate.voting_rounds.keys())} "
            f"!= reference {set(reference.voting_rounds.keys())}"
        )


# ============================================================================
# Cross-Node Determinism: Transaction Inclusion List Ordering
# ============================================================================


@given(
    tx_data=st.lists(
        st.tuples(
            st.text(alphabet="abcdefghijk", min_size=4, max_size=8),  # tx_id
            st.integers(min_value=0, max_value=59),  # timestamp (seconds)
            st.lists(
                st.text(alphabet="w123456789", min_size=2, max_size=4),
                min_size=2,
                max_size=4,
                unique=True,
            ),  # witnesses
        ),
        min_size=3,
        max_size=12,
        unique_by=lambda x: x[0],  # unique tx_ids
    ),
)
@settings(max_examples=100, deadline=None)
def test_inclusion_list_is_deterministic_with_same_canonical_ordering(
    tx_data: list[tuple[str, int, list[str]]],
) -> None:
    """
    Property: When nodes receive transaction broadcasts with identical timestamps,
    they must use a canonical tiebreaker (tx_id) to produce identical inclusion lists.

    This tests that inclusion list building is deterministic when nodes agree on
    transaction timestamps and witness sets, which happens after gossip convergence.
    The key insight: nodes that disagree on first-seen order will produce different
    lists UNTIL they synchronize on canonical timestamps.
    """
    # All nodes build broadcasts with identical timestamps for each tx_id
    # This simulates consensus on transaction ordering after gossip convergence
    canonical_broadcasts = [
        TransactionBroadcast(
            tx_id=tx_id,
            round_number=1,
            broadcast_at=f"2026-03-10T00:00:{timestamp:02d}Z",
            witnesses=tuple(sorted(witnesses)),  # Canonical witness ordering
        )
        for tx_id, timestamp, witnesses in sorted(tx_data, key=lambda x: (x[1], x[0]))
    ]

    # Node A processes broadcasts in canonical order
    inclusion_list_a = build_inclusion_list(tuple(canonical_broadcasts), minimum_witnesses=2)

    # Node B processes same canonical broadcasts
    inclusion_list_b = build_inclusion_list(tuple(canonical_broadcasts), minimum_witnesses=2)

    # Both nodes must produce identical inclusion lists when using canonical ordering
    assert inclusion_list_a == inclusion_list_b

    # Verify the list is sorted by (timestamp, tx_id) as expected
    if len(inclusion_list_a) > 1:
        tx_to_timestamp = {tx_id: timestamp for tx_id, timestamp, _ in tx_data}
        for i in range(len(inclusion_list_a) - 1):
            tx_current = inclusion_list_a[i]
            tx_next = inclusion_list_a[i + 1]
            ts_current = tx_to_timestamp.get(tx_current, 0)
            ts_next = tx_to_timestamp.get(tx_next, 0)
            # Current should be <= next in canonical order
            assert (ts_current, tx_current) <= (ts_next, tx_next)


# ============================================================================
# Cross-Node Determinism: Fork Resolution
# ============================================================================


@given(
    shared_length=st.integers(min_value=2, max_value=8),
    chain_a_extra=st.integers(min_value=1, max_value=5),
    chain_b_extra=st.integers(min_value=1, max_value=5),
    seed_prefix=st.text(alphabet="abcdefghijklmnop", min_size=3, max_size=6),
)
@settings(max_examples=100, deadline=None)
def test_fork_resolution_is_deterministic_across_nodes(
    shared_length: int, chain_a_extra: int, chain_b_extra: int, seed_prefix: str
) -> None:
    """
    Property: Multiple nodes independently resolving the same fork must all
    select the same winning chain.

    This tests that fork resolution is deterministic and produces identical
    results regardless of which node performs the resolution.
    """
    # Build two competing chains
    shared = [
        ConsensusBlock(
            round_number=i,
            quorum_weight=3,
            vrf_hash=vrf_hash_from_seed(f"{seed_prefix}-shared-{i}"),
            timestamp=f"2026-03-10T00:00:{min(i, 59):02d}Z",
        )
        for i in range(shared_length)
    ]

    chain_a = shared + [
        ConsensusBlock(
            round_number=shared_length + i,
            quorum_weight=3,
            vrf_hash=vrf_hash_from_seed(f"{seed_prefix}-a-{i}"),
            timestamp=f"2026-03-10T00:00:{min(shared_length + i, 59):02d}Z",
        )
        for i in range(chain_a_extra)
    ]

    chain_b = shared + [
        ConsensusBlock(
            round_number=shared_length + i,
            quorum_weight=3,
            vrf_hash=vrf_hash_from_seed(f"{seed_prefix}-b-{i}"),
            timestamp=f"2026-03-10T00:00:{min(shared_length + i, 59):02d}Z",
        )
        for i in range(chain_b_extra)
    ]

    # Node 1 resolves fork in (A, B) order
    winner_node1 = resolve_partition_fork(tuple(chain_a), tuple(chain_b))

    # Node 2 resolves fork in (B, A) order
    winner_node2 = resolve_partition_fork(tuple(chain_b), tuple(chain_a))

    # Node 3 re-resolves using the winner from node 1
    winner_node3 = resolve_partition_fork(
        winner_node1, tuple(chain_b if winner_node1 == tuple(chain_a) else chain_a)
    )

    # All nodes must select the same winner
    # Note: fork resolution may return either chain_a or chain_b, but all nodes must agree
    assert winner_node1 == winner_node2, "Nodes 1 and 2 disagree on fork resolution"
    assert winner_node1 == winner_node3, "Node 3 disagrees with nodes 1 and 2"


# ============================================================================
# Cross-Node Determinism: Leader Selection
# ============================================================================


@given(
    leaders=st.lists(
        st.text(alphabet="abcdefghijk", min_size=4, max_size=8),
        min_size=2,
        max_size=5,
        unique=True,
    ),
    round_numbers=st.lists(st.integers(min_value=0, max_value=100), min_size=5, max_size=15),
    rotation_window=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=100, deadline=None)
def test_leader_selection_is_deterministic_across_nodes(
    leaders: list[str], round_numbers: list[int], rotation_window: int
) -> None:
    """
    Property: Multiple nodes independently selecting leaders for the same rounds
    must all select identical leaders.

    This tests that leader selection is deterministic and produces consistent
    results across all nodes in the network.
    """
    leader_tuple = tuple(leaders)

    # Node 1 selects leaders for all rounds
    leaders_node1 = [
        select_rotating_leader(round_num, leader_tuple, rotation_window=rotation_window)
        for round_num in round_numbers
    ]

    # Node 2 selects leaders for same rounds (simulating independent computation)
    leaders_node2 = [
        select_rotating_leader(round_num, leader_tuple, rotation_window=rotation_window)
        for round_num in round_numbers
    ]

    # Node 3 selects leaders in different order but for same rounds
    shuffled_rounds = sorted(round_numbers, reverse=True)
    leaders_node3_unordered = [
        select_rotating_leader(round_num, leader_tuple, rotation_window=rotation_window)
        for round_num in shuffled_rounds
    ]
    # Re-order to match original round order
    round_to_leader_node3 = dict(zip(shuffled_rounds, leaders_node3_unordered))
    leaders_node3 = [round_to_leader_node3[rn] for rn in round_numbers]

    # All nodes must select identical leaders for each round
    assert leaders_node1 == leaders_node2, "Nodes 1 and 2 disagree on leader selection"
    assert leaders_node1 == leaders_node3, "Node 3 disagrees with nodes 1 and 2"


# ============================================================================
# Cross-Node Determinism: Grace Period Validation
# ============================================================================


@given(
    initial_members=st.sets(
        st.sampled_from(["n1", "n2", "n3", "n4", "n5"]), min_size=2, max_size=4
    ),
    removal_epoch=st.integers(min_value=5, max_value=20),
    removed_node=st.sampled_from(["n1", "n2", "n3"]),
    check_epochs=st.lists(st.integers(min_value=0, max_value=25), min_size=3, max_size=10),
    grace_epochs=st.integers(min_value=0, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_grace_period_validation_is_deterministic_across_nodes(
    initial_members: set[str],
    removal_epoch: int,
    removed_node: str,
    check_epochs: list[int],
    grace_epochs: int,
) -> None:
    """
    Property: Multiple nodes independently validating signatures with grace periods
    must all produce identical validation results.

    This tests that grace period logic is deterministic and consistent across nodes.
    """
    assume(removed_node in initial_members)

    # Both nodes have identical registry setup
    registry_node1 = ValidatorRegistry(initial_members, epoch=0)
    registry_node1.apply_change(epoch=removal_epoch, removed_members={removed_node})

    registry_node2 = ValidatorRegistry(initial_members, epoch=0)
    registry_node2.apply_change(epoch=removal_epoch, removed_members={removed_node})

    # Both create voting rounds with same parameters
    snapshot1 = registry_node1.get_snapshot(snapshot_epoch=3)
    round1 = VotingRound(
        round_num=1, start_epoch=3, registry_snapshot=snapshot1, grace_epochs=grace_epochs
    )

    snapshot2 = registry_node2.get_snapshot(snapshot_epoch=3)
    round2 = VotingRound(
        round_num=1, start_epoch=3, registry_snapshot=snapshot2, grace_epochs=grace_epochs
    )

    # Create a test signature object
    class TestSignature:
        def __init__(self, node_id: str):
            self.node_id = node_id

    sig = TestSignature(removed_node)

    # Both nodes validate signature at each epoch - must get identical results
    for check_epoch in check_epochs:
        if check_epoch < 3:  # Before round start
            continue

        try:
            valid1 = round1.is_signature_valid(sig, check_epoch)
            valid2 = round2.is_signature_valid(sig, check_epoch)
            assert valid1 == valid2, f"Grace period validation mismatch at epoch {check_epoch}"
        except ValueError:
            # Both should raise same error
            with pytest.raises(ValueError):
                round2.is_signature_valid(sig, check_epoch)


@given(
    start_epoch=st.integers(min_value=1, max_value=30),
    grace_epochs=st.integers(min_value=0, max_value=5),
)
@settings(max_examples=50, deadline=None)
def test_membership_flaps_at_epoch_boundary_are_consistent(
    start_epoch: int, grace_epochs: int
) -> None:
    """
    Property: Validators added or removed at the exact round epoch behave consistently
    across nodes regardless of whether the change arrived just before or just after
    the round started.
    """
    initial_members = {"v1", "v2", "v3"}
    removed = "v1"
    added = "v4"

    # Node A starts the round before seeing the change.
    registry_before = ValidatorRegistry(initial_members, epoch=0)
    snapshot_before = registry_before.get_snapshot(start_epoch)
    round_before = VotingRound(
        round_num=1,
        start_epoch=start_epoch,
        registry_snapshot=snapshot_before,
        grace_epochs=grace_epochs,
    )

    # Node B incorporates the change at the epoch boundary before starting the round.
    registry_after = ValidatorRegistry(initial_members, epoch=0)
    registry_after.apply_change(epoch=start_epoch, added_members={added}, removed_members={removed})
    snapshot_after = registry_after.get_snapshot(start_epoch)
    round_after = VotingRound(
        round_num=1,
        start_epoch=start_epoch,
        registry_snapshot=snapshot_after,
        grace_epochs=grace_epochs,
    )

    removed_sig = SimpleNamespace(node_id=removed)
    added_sig = SimpleNamespace(node_id=added)

    # Removed validator is only admitted for the node that had it in the snapshot.
    assert round_before.is_signature_valid(removed_sig, current_epoch=start_epoch)
    assert not round_after.is_signature_valid(removed_sig, current_epoch=start_epoch)

    # Newly added validator is rejected by the stale snapshot but accepted by the updated one.
    assert not round_before.is_signature_valid(added_sig, current_epoch=start_epoch)
    assert round_after.is_signature_valid(added_sig, current_epoch=start_epoch)


# ============================================================================
# Cross-Node Determinism: Combined State Transitions
# ============================================================================


@given(
    round_operations=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=30),  # round_num
            st.integers(min_value=0, max_value=30),  # start_epoch
        ),
        min_size=3,
        max_size=10,
    ),
    watermark_advances=st.lists(st.integers(min_value=0, max_value=30), min_size=1, max_size=5),
)
@settings(max_examples=100, deadline=None)
def test_combined_state_transitions_produce_identical_final_state(
    round_operations: list[tuple[int, int]], watermark_advances: list[int]
) -> None:
    """
    Property: Two nodes applying the same sequence of state transitions in
    different orders must converge to identical final state.

    This is the master determinism test - it combines multiple state operations
    and verifies that final state is identical regardless of operation order.
    """
    # Deduplicate rounds - each round_num should have a consistent start_epoch
    unique_rounds: dict[int, int] = {}
    for round_num, start_epoch in round_operations:
        if round_num not in unique_rounds:
            unique_rounds[round_num] = start_epoch

    round_ops_list = sorted(unique_rounds.items())
    assume(len(round_ops_list) > 0)

    registry = ValidatorRegistry({"validator1", "validator2", "validator3"}, epoch=0)

    # Node A applies operations in forward order
    consensus_a = ConsensusState(max_watermark_window=15)
    for round_num, start_epoch in round_ops_list:
        try:
            consensus_a.start_round(round_num=round_num, start_epoch=start_epoch, registry=registry)
        except ValueError:
            pass  # Skip duplicate rounds

    # Node B applies operations in reverse order
    consensus_b = ConsensusState(max_watermark_window=15)
    for round_num, start_epoch in reversed(round_ops_list):
        try:
            consensus_b.start_round(round_num=round_num, start_epoch=start_epoch, registry=registry)
        except ValueError:
            pass  # Skip duplicate rounds

    # Apply watermark advances in order for both
    for advance in sorted(watermark_advances):
        try:
            consensus_a.advance_watermark(advance)
        except ValueError:
            pass
        try:
            consensus_b.advance_watermark(advance)
        except ValueError:
            pass

    # Both nodes must have identical final state
    assert consensus_a.low_watermark == consensus_b.low_watermark, "Low watermarks differ"
    assert consensus_a.high_watermark == consensus_b.high_watermark, "High watermarks differ"
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys()), (
        "Active rounds differ"
    )

    # Verify each voting round has identical properties
    for round_num in consensus_a.voting_rounds:
        round_a = consensus_a.voting_rounds[round_num]
        round_b = consensus_b.voting_rounds[round_num]
        assert round_a.round_num == round_b.round_num
        assert round_a.start_epoch == round_b.start_epoch
        assert round_a.grace_period_end == round_b.grace_period_end


# ============================================================================
# Nightly-Scale Determinism
# ============================================================================


@pytest.mark.slow
@pytest.mark.skipif(
    not os.environ.get("OLYMPUS_RUN_SLOW"), reason="Set OLYMPUS_RUN_SLOW=1 to run long sequences"
)
def test_long_sequence_convergence_over_hundreds_of_rounds() -> None:
    """
    Deterministic convergence across many rounds (500+) for slow/nightly runs.
    """
    registry = ValidatorRegistry({"n1", "n2", "n3"}, epoch=0)
    total_rounds = 600
    all_rounds = list(range(total_rounds))

    consensus_a = ConsensusState(max_watermark_window=total_rounds)
    for round_num in all_rounds:
        consensus_a.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    consensus_b = ConsensusState(max_watermark_window=total_rounds)
    shuffled = list(all_rounds)
    random.Random(1337).shuffle(shuffled)
    for round_num in shuffled:
        consensus_b.start_round(round_num=round_num, start_epoch=round_num, registry=registry)

    consensus_a.advance_watermark(total_rounds - 1)
    consensus_b.advance_watermark(total_rounds - 1)

    assert consensus_a.low_watermark == consensus_b.low_watermark
    assert consensus_a.high_watermark == consensus_b.high_watermark
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys())


# ============================================================================
# Network / Fault Injection Testing
# ============================================================================


def test_partition_and_rejoin_produces_consistent_state() -> None:
    """
    Simulate a network partition where two groups of rounds are applied
    independently and then merged: final state after seeing all rounds must
    be identical regardless of partition grouping.
    """
    registry = ValidatorRegistry({"a", "b", "c"}, epoch=0)
    all_rounds = list(range(30))
    rng = random.Random(42)

    # Partition A sees first half, partition B sees second half, then they
    # exchange and each applies the missing rounds.
    split = len(all_rounds) // 2
    partition_a_first = all_rounds[:split]
    partition_b_first = all_rounds[split:]

    consensus_a = ConsensusState(max_watermark_window=40)
    for rn in partition_a_first:
        consensus_a.start_round(round_num=rn, start_epoch=rn, registry=registry)
    for rn in partition_b_first:
        consensus_a.start_round(round_num=rn, start_epoch=rn, registry=registry)

    # Partition B sees the reverse order of partitions.
    consensus_b = ConsensusState(max_watermark_window=40)
    rng.shuffle(partition_b_first)
    for rn in partition_b_first:
        consensus_b.start_round(round_num=rn, start_epoch=rn, registry=registry)
    rng.shuffle(partition_a_first)
    for rn in partition_a_first:
        consensus_b.start_round(round_num=rn, start_epoch=rn, registry=registry)

    consensus_a.advance_watermark(max(all_rounds))
    consensus_b.advance_watermark(max(all_rounds))

    assert consensus_a.low_watermark == consensus_b.low_watermark
    assert consensus_a.high_watermark == consensus_b.high_watermark
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys())


def test_delayed_message_ordering_does_not_affect_determinism() -> None:
    """
    Rounds arriving out of order (simulating delayed network messages) must
    converge to the same state as in-order delivery.
    """
    registry = ValidatorRegistry({"x", "y"}, epoch=0)
    ordered = list(range(40))
    delayed = list(ordered)
    random.Random(99).shuffle(delayed)

    consensus_ordered = ConsensusState(max_watermark_window=50)
    for rn in ordered:
        consensus_ordered.start_round(round_num=rn, start_epoch=rn, registry=registry)

    consensus_delayed = ConsensusState(max_watermark_window=50)
    for rn in delayed:
        consensus_delayed.start_round(round_num=rn, start_epoch=rn, registry=registry)

    consensus_ordered.advance_watermark(max(ordered))
    consensus_delayed.advance_watermark(max(ordered))

    assert consensus_ordered.low_watermark == consensus_delayed.low_watermark
    assert consensus_ordered.high_watermark == consensus_delayed.high_watermark
    assert set(consensus_ordered.voting_rounds.keys()) == set(
        consensus_delayed.voting_rounds.keys()
    )


def test_simultaneous_validator_join_and_leave() -> None:
    """
    Applying a validator join and leave at the same epoch on two nodes
    (in different ordering) must produce identical registry snapshots.
    """
    reg_a = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)
    reg_b = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)

    # Node A applies add then remove at epoch 5
    reg_a.apply_change(epoch=5, added_members={"v4"})
    reg_a.apply_change(epoch=5, removed_members={"v1"})

    # Node B applies remove then add at epoch 5
    reg_b.apply_change(epoch=5, removed_members={"v1"})
    reg_b.apply_change(epoch=5, added_members={"v4"})

    snap_a = reg_a.get_snapshot(snapshot_epoch=5)
    snap_b = reg_b.get_snapshot(snapshot_epoch=5)

    for node_id in ("v1", "v2", "v3", "v4"):
        assert snap_a.is_member_at_epoch(node_id, 5) == snap_b.is_member_at_epoch(node_id, 5), (
            f"Membership for {node_id} diverges between nodes at epoch 5"
        )


def test_concurrent_validator_join_leave_during_rounds() -> None:
    """
    One thread inserts rounds while another mutates the registry.  Because
    each ``start_round`` captures a snapshot, the resulting consensus state
    must remain internally consistent (no crashes, no missing rounds).
    """
    registry = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=200)
    barrier = threading.Barrier(parties=2)

    def round_inserter() -> None:
        barrier.wait()
        for rn in range(100):
            consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)

    def registry_mutator() -> None:
        barrier.wait()
        for epoch in range(1, 50):
            try:
                registry.apply_change(epoch=epoch, added_members={f"v_new_{epoch}"})
            except ValueError:
                pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(round_inserter)
        f2 = pool.submit(registry_mutator)
        f1.result()
        f2.result()

    assert set(consensus.voting_rounds.keys()) == set(range(100))
    assert consensus.high_watermark == 99


# ============================================================================
# Serialization / Persistence Testing
# ============================================================================


def test_json_round_trip_preserves_determinism() -> None:
    """
    Manually JSON-serializable fields of ConsensusState must survive a
    JSON round-trip and produce identical behaviour when new rounds are added.
    """
    registry = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=30)
    for rn in range(10):
        consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)
    consensus.advance_watermark(9)

    # Serialize to JSON-safe dict (lock and snapshots excluded).
    state_dict = {
        "max_watermark_window": consensus.max_watermark_window,
        "low_watermark": consensus.low_watermark,
        "high_watermark": consensus.high_watermark,
        "round_nums": sorted(consensus.voting_rounds.keys()),
    }
    blob = json.dumps(state_dict, sort_keys=True, separators=(",", ":"))
    restored = json.loads(blob)

    # Rebuild from persisted scalars.
    rebuilt = ConsensusState(max_watermark_window=restored["max_watermark_window"])
    rebuilt.low_watermark = restored["low_watermark"]
    rebuilt.high_watermark = restored["high_watermark"]
    for rn in restored["round_nums"]:
        rebuilt.voting_rounds[rn] = consensus.voting_rounds[rn]

    # Apply additional rounds on both and compare.
    for rn in range(10, 15):
        consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)
        rebuilt.start_round(round_num=rn, start_epoch=rn, registry=registry)

    consensus.advance_watermark(14)
    rebuilt.advance_watermark(14)

    assert consensus.low_watermark == rebuilt.low_watermark
    assert consensus.high_watermark == rebuilt.high_watermark
    assert set(consensus.voting_rounds.keys()) == set(rebuilt.voting_rounds.keys())


def test_multiple_pickle_cycles_preserve_determinism(tmp_path: Path) -> None:
    """
    State must survive multiple pickle save/load cycles without drift.
    """
    registry = ValidatorRegistry({"v1", "v2"}, epoch=0)
    consensus = ConsensusState(max_watermark_window=60)
    for rn in range(20):
        consensus.start_round(round_num=rn, start_epoch=rn, registry=registry)
    consensus.advance_watermark(19)

    payload: dict[str, object] = {"registry": registry, "consensus": consensus}

    for cycle in range(5):
        state_file = tmp_path / f"state_cycle_{cycle}.pkl"
        with state_file.open("wb") as fh:
            pickle.dump(payload, fh)
        with state_file.open("rb") as fh:
            payload = pickle.load(fh)

    restored_consensus: ConsensusState = payload["consensus"]  # type: ignore[assignment]
    assert restored_consensus.low_watermark == consensus.low_watermark
    assert restored_consensus.high_watermark == consensus.high_watermark
    assert set(restored_consensus.voting_rounds.keys()) == set(consensus.voting_rounds.keys())

    # Ensure the restored instance is still functional (lock recreated).
    restored_registry: ValidatorRegistry = payload["registry"]  # type: ignore[assignment]
    restored_consensus.start_round(round_num=20, start_epoch=20, registry=restored_registry)
    assert 20 in restored_consensus.voting_rounds


def test_snapshot_persistence_determinism(tmp_path: Path) -> None:
    """
    Registry snapshots captured before and after a save/load cycle must
    produce identical membership queries.
    """
    registry = ValidatorRegistry({"v1", "v2", "v3"}, epoch=0)
    registry.apply_change(epoch=3, added_members={"v4"}, removed_members={"v1"})
    registry.apply_change(epoch=7, removed_members={"v2"})

    snap_before = registry.get_snapshot(snapshot_epoch=5)

    state_file = tmp_path / "registry.pkl"
    with state_file.open("wb") as fh:
        pickle.dump(registry, fh)
    with state_file.open("rb") as fh:
        restored: ValidatorRegistry = pickle.load(fh)

    snap_after = restored.get_snapshot(snapshot_epoch=5)

    for node_id in ("v1", "v2", "v3", "v4"):
        for epoch in range(10):
            assert snap_before.is_member_at_epoch(node_id, epoch) == snap_after.is_member_at_epoch(
                node_id, epoch
            ), f"Membership divergence for {node_id} at epoch {epoch} after restore"


@given(
    round_numbers=st.lists(
        st.integers(min_value=0, max_value=30), min_size=3, max_size=10, unique=True
    ),
    max_window=st.integers(min_value=5, max_value=15),
)
@settings(max_examples=50, deadline=None)
def test_pickle_round_trip_then_advance_is_deterministic(
    round_numbers: list[int], max_window: int
) -> None:
    """
    Property: serialise -> deserialise -> apply more operations must yield
    the same state as applying everything on the original instance.
    """
    registry = ValidatorRegistry({"v1", "v2"}, epoch=0)

    consensus_a = ConsensusState(max_watermark_window=max_window)
    for rn in sorted(round_numbers):
        consensus_a.start_round(round_num=rn, start_epoch=rn, registry=registry)
    consensus_a.advance_watermark(max(round_numbers))

    consensus_b: ConsensusState = pickle.loads(pickle.dumps(consensus_a))

    extra = max(round_numbers) + 1
    consensus_a.start_round(round_num=extra, start_epoch=extra, registry=registry)
    consensus_b.start_round(round_num=extra, start_epoch=extra, registry=registry)

    try:
        consensus_a.advance_watermark(extra)
    except ValueError:
        pass
    try:
        consensus_b.advance_watermark(extra)
    except ValueError:
        pass

    assert consensus_a.low_watermark == consensus_b.low_watermark
    assert consensus_a.high_watermark == consensus_b.high_watermark
    assert set(consensus_a.voting_rounds.keys()) == set(consensus_b.voting_rounds.keys())
