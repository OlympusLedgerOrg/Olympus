from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import assume, given, settings

from protocol.partition import (
    ConsensusBlock,
    ConsensusChainState,
    PartitionDetector,
    PublishedVote,
    TransactionBroadcast,
    VotePublication,
    build_inclusion_list,
    detect_slashable_equivocations,
    find_first_divergent_round,
    missing_inclusion_entries,
    proof_of_elapsed_rounds,
    resolve_partition_fork,
    select_random_peers,
    select_rotating_leader,
    validate_proof_of_wait,
    vrf_hash_from_seed,
)


def _block(round_number: int, quorum_weight: int, seed: str) -> ConsensusBlock:
    return ConsensusBlock(
        round_number=round_number,
        quorum_weight=quorum_weight,
        vrf_hash=vrf_hash_from_seed(seed),
        timestamp=f"2026-03-10T00:00:{round_number:02d}Z",
    )


def _chain(*blocks: ConsensusBlock) -> tuple[ConsensusBlock, ...]:
    return tuple(blocks)


def test_resolve_partition_fork_prefers_longer_chain() -> None:
    shared = [_block(0, 3, "shared-0"), _block(1, 3, "shared-1")]
    longer = _chain(*shared, _block(2, 3, "a-2"))
    shorter = _chain(*shared)

    winner = resolve_partition_fork(longer, shorter)

    assert winner == longer


def test_resolve_partition_fork_prefers_higher_quorum_at_fork() -> None:
    prefix = [_block(0, 2, "p-0")]
    chain_a = _chain(*prefix, _block(1, 5, "a-1"), _block(2, 5, "a-2"))
    chain_b = _chain(*prefix, _block(1, 3, "b-1"), _block(2, 5, "b-2"))

    winner = resolve_partition_fork(chain_a, chain_b)

    assert winner == chain_a


def test_resolve_partition_fork_uses_vrf_tiebreaker() -> None:
    prefix = [_block(0, 2, "p-0")]
    diverge_a = _block(1, 4, "aaa")
    diverge_b = _block(1, 4, "bbb")
    post_a = _block(2, 4, "a-2")
    post_b = _block(2, 4, "b-2")
    chain_a = _chain(*prefix, diverge_a, post_a)
    chain_b = _chain(*prefix, diverge_b, post_b)

    winner = resolve_partition_fork(chain_a, chain_b)

    assert winner == (chain_a if post_a.vrf_hash < post_b.vrf_hash else chain_b)


def test_validate_proof_of_wait_accepts_nonmonotonic_timestamps() -> None:
    block_a = _block(0, 1, "seed-0")
    block_b = ConsensusBlock(
        round_number=1,
        quorum_weight=1,
        vrf_hash=vrf_hash_from_seed("seed-1"),
        timestamp=block_a.timestamp,  # non-monotonic
    )

    validate_proof_of_wait((block_a, block_b))


def test_validate_proof_of_wait_rejects_round_gaps() -> None:
    with pytest.raises(ValueError, match="advance by exactly one"):
        validate_proof_of_wait((_block(0, 1, "seed-0"), _block(2, 1, "seed-2")))


def test_proof_of_elapsed_rounds_uses_round_numbers() -> None:
    elapsed_rounds = proof_of_elapsed_rounds((_block(4, 2, "seed-4"), _block(5, 2, "seed-5")))

    assert elapsed_rounds == 1


def test_partition_detector_freezes_watermark_on_quorum_loss() -> None:
    frozen_state = ConsensusChainState(round_number=2, chain=_chain(_block(0, 2, "f-0")))

    class _State:
        def __init__(self) -> None:
            self.state = frozen_state

        def get(self) -> ConsensusChainState:
            return self.state

    state_source = _State()
    detector = PartitionDetector(
        ping_nodes=lambda nodes: nodes[:1],
        get_current_state=state_source.get,
    )

    result = detector.check_network_health(5, ("n1", "n2", "n3"))

    assert result is False
    assert detector.frozen_watermarks[5] == frozen_state


def test_partition_detector_recovers_with_fork_choice() -> None:
    short_chain = ConsensusChainState(
        round_number=1,
        chain=_chain(_block(0, 2, "s-0"), _block(1, 2, "s-1")),
    )
    long_chain = ConsensusChainState(
        round_number=3,
        chain=_chain(
            _block(0, 2, "l-0"),
            _block(1, 2, "l-1"),
            _block(2, 2, "l-2"),
        ),
    )

    class _State:
        def __init__(self) -> None:
            self.state = short_chain

        def get(self) -> ConsensusChainState:
            return self.state

    state_source = _State()
    detector = PartitionDetector(
        ping_nodes=lambda nodes: nodes,  # recovered paths should see full quorum
        get_current_state=state_source.get,
    )
    detector.frozen_watermarks[1] = short_chain
    state_source.state = long_chain

    winner = detector.recover_from_partition(healed_round=10)

    assert winner == long_chain
    assert 1 not in detector.frozen_watermarks
    assert 10 in detector.last_quorum_time


def test_select_random_peers_enforces_bounds() -> None:
    with pytest.raises(ValueError, match="sample_size must be positive"):
        select_random_peers(("n1", "n2"), 0)
    with pytest.raises(ValueError, match="cannot exceed"):
        select_random_peers(("n1", "n2"), 3)


def test_partition_detector_uses_peer_sampling() -> None:
    frozen_state = ConsensusChainState(round_number=1, chain=_chain(_block(0, 2, "base")))
    seen_nodes: list[tuple[str, ...]] = []

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=lambda nodes: seen_nodes.append(tuple(nodes)) or tuple(nodes),
        get_current_state=_State().get,
        sample_size=2,
        peer_selector=lambda nodes, sample_size: tuple(nodes[:sample_size]),
    )

    assert detector.check_network_health(7, ("n1", "n2", "n3", "n4")) is True
    assert seen_nodes == [("n1", "n2")]


def test_partition_detector_freezes_on_insufficient_diversity() -> None:
    frozen_state = ConsensusChainState(round_number=2, chain=_chain(_block(0, 2, "base")))

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=lambda nodes: tuple(nodes),
        get_current_state=_State().get,
        peer_groups={"n1": "asn-a", "n2": "asn-a", "n3": "asn-a"},
        min_peer_group_diversity=2,
    )

    assert detector.check_network_health(8, ("n1", "n2", "n3")) is False
    assert detector.frozen_watermarks[8] == frozen_state


def test_partition_detector_freezes_when_cross_network_verification_fails() -> None:
    frozen_state = ConsensusChainState(round_number=2, chain=_chain(_block(0, 2, "base")))

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=lambda nodes: tuple(nodes),
        get_current_state=_State().get,
        cross_network_verifier=lambda reachable: False,
    )

    assert detector.check_network_health(9, ("n1", "n2", "n3")) is False
    assert detector.frozen_watermarks[9] == frozen_state


def test_partition_detector_peer_sampling_with_sample_size_less_than_total() -> None:
    """
    Test the production code path where sample_size < len(nodes).
    Verify that:
    1. Only sampled peers are pinged (not all nodes)
    2. Peer selector is properly invoked with correct parameters
    3. Network health check uses the sampled subset for quorum calculation
    """
    frozen_state = ConsensusChainState(round_number=3, chain=_chain(_block(0, 2, "base")))
    all_nodes = ("n1", "n2", "n3", "n4", "n5", "n6")
    sample_size = 3

    # Track which nodes were actually pinged
    pinged_nodes: list[tuple[str, ...]] = []

    def mock_ping(nodes: tuple[str, ...]) -> tuple[str, ...]:
        pinged_nodes.append(nodes)
        # Return 2/3 of sampled nodes as reachable
        return nodes[: (2 * len(nodes)) // 3 + 1]

    # Track peer selector invocations
    selector_calls: list[tuple[tuple[str, ...], int]] = []

    def mock_selector(nodes: tuple[str, ...], size: int) -> tuple[str, ...]:
        selector_calls.append((nodes, size))
        # Return first 'size' nodes as the sample
        return nodes[:size]

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=mock_ping,
        get_current_state=_State().get,
        sample_size=sample_size,
        peer_selector=mock_selector,
    )

    result = detector.check_network_health(10, all_nodes)

    # Verify peer selector was called with correct parameters
    assert len(selector_calls) == 1
    assert selector_calls[0] == (all_nodes, sample_size)

    # Verify only sampled nodes were pinged (not all 6 nodes)
    assert len(pinged_nodes) == 1
    assert len(pinged_nodes[0]) == sample_size
    assert set(pinged_nodes[0]).issubset(set(all_nodes))

    # Verify network health check passed (2/3 of sampled nodes are reachable)
    assert result is True
    assert 10 in detector.last_quorum_time


def test_partition_detector_peer_sampling_respects_diversity_constraints() -> None:
    """
    Test that peer sampling interacts correctly with diversity checks.
    Even with custom peer selector, diversity requirements must be enforced.
    """
    frozen_state = ConsensusChainState(round_number=4, chain=_chain(_block(0, 2, "base")))

    # All nodes in same peer group
    peer_groups = {"n1": "asn-a", "n2": "asn-a", "n3": "asn-a", "n4": "asn-a"}
    all_nodes = tuple(peer_groups.keys())

    def custom_selector(nodes: tuple[str, ...], size: int) -> tuple[str, ...]:
        # Select first 'size' nodes
        return nodes[:size]

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=lambda nodes: tuple(nodes),  # All reachable
        get_current_state=_State().get,
        sample_size=3,
        peer_selector=custom_selector,
        peer_groups=peer_groups,
        min_peer_group_diversity=2,  # Require at least 2 different groups
    )

    # Should freeze because all sampled nodes are in the same group
    result = detector.check_network_health(11, all_nodes)

    assert result is False
    assert 11 in detector.frozen_watermarks


def test_partition_detector_peer_sampling_with_exact_quorum_threshold() -> None:
    """
    Test edge case where exactly ceil(2/3) of sampled nodes are reachable.
    """
    frozen_state = ConsensusChainState(round_number=5, chain=_chain(_block(0, 2, "base")))
    all_nodes = ("n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9")
    sample_size = 6

    def mock_selector(nodes: tuple[str, ...], size: int) -> tuple[str, ...]:
        return nodes[:size]

    def mock_ping_exactly_quorum(nodes: tuple[str, ...]) -> tuple[str, ...]:
        # Return exactly ceil(2/3) of sampled nodes
        required = (2 * len(nodes) + 2) // 3  # ceil(2*6/3) = 4
        return nodes[:required]

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=mock_ping_exactly_quorum,
        get_current_state=_State().get,
        sample_size=sample_size,
        peer_selector=mock_selector,
    )

    result = detector.check_network_health(12, all_nodes)

    # Should pass with exactly ceil(2/3) reachable
    assert result is True
    assert 12 in detector.last_quorum_time


def test_partition_detector_peer_sampling_fails_just_below_quorum() -> None:
    """
    Test edge case where one less than ceil(2/3) of sampled nodes are reachable.
    """
    frozen_state = ConsensusChainState(round_number=6, chain=_chain(_block(0, 2, "base")))
    all_nodes = ("n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9")
    sample_size = 6

    def mock_selector(nodes: tuple[str, ...], size: int) -> tuple[str, ...]:
        return nodes[:size]

    def mock_ping_below_quorum(nodes: tuple[str, ...]) -> tuple[str, ...]:
        # Return one less than required quorum
        required = (2 * len(nodes) + 2) // 3  # ceil(2*6/3) = 4
        return nodes[: required - 1]  # Return 3 nodes (below quorum)

    class _State:
        def get(self) -> ConsensusChainState:
            return frozen_state

    detector = PartitionDetector(
        ping_nodes=mock_ping_below_quorum,
        get_current_state=_State().get,
        sample_size=sample_size,
        peer_selector=mock_selector,
    )

    result = detector.check_network_health(13, all_nodes)

    # Should fail with one less than required quorum
    assert result is False
    assert 13 in detector.frozen_watermarks


def test_find_first_divergent_round_identifies_first_difference() -> None:
    chain_a = _chain(_block(0, 1, "x"), _block(1, 1, "y"), _block(2, 1, "z"))
    chain_b = _chain(_block(0, 1, "x"), _block(1, 2, "different"), _block(2, 1, "z"))

    idx = find_first_divergent_round(chain_a, chain_b)

    assert idx == 1


def test_detect_slashable_equivocations_requires_conflicting_published_votes() -> None:
    vote_a = PublishedVote(
        node_id="guardian-1",
        shard_id="records.a",
        round_number=7,
        chain_id="chain-a",
        publication=VotePublication(
            vote_hash=vrf_hash_from_seed("guardian-1-chain-a"),
            published_at="2026-03-10T00:01:00Z",
            witnesses=("w1", "w2"),
        ),
    )
    vote_b = PublishedVote(
        node_id="guardian-1",
        shard_id="records.a",
        round_number=7,
        chain_id="chain-b",
        publication=VotePublication(
            vote_hash=vrf_hash_from_seed("guardian-1-chain-b"),
            published_at="2026-03-10T00:01:01Z",
            witnesses=("w1", "w3"),
        ),
    )

    evidence = detect_slashable_equivocations((vote_a, vote_b))

    assert len(evidence) == 1
    assert evidence[0].node_id == "guardian-1"
    assert evidence[0].conflicting_chain_ids == ("chain-a", "chain-b")


def test_select_rotating_leader_rotates_every_round() -> None:
    leaders = ("n1", "n2", "n3")

    assert select_rotating_leader(0, leaders) == "n1"
    assert select_rotating_leader(1, leaders) == "n2"
    assert select_rotating_leader(2, leaders) == "n3"
    assert select_rotating_leader(3, leaders) == "n1"


def test_build_inclusion_list_filters_on_broadcast_witness_quorum() -> None:
    broadcasts = (
        TransactionBroadcast(
            tx_id="tx-1",
            round_number=1,
            broadcast_at="2026-03-10T00:01:00Z",
            witnesses=("n1", "n2"),
        ),
        TransactionBroadcast(
            tx_id="tx-2",
            round_number=1,
            broadcast_at="2026-03-10T00:01:01Z",
            witnesses=("n1",),
        ),
        TransactionBroadcast(
            tx_id="tx-3",
            round_number=1,
            broadcast_at="2026-03-10T00:01:02Z",
            witnesses=("n1", "n2", "n3"),
        ),
    )

    inclusion_list = build_inclusion_list(broadcasts, minimum_witnesses=2)

    assert inclusion_list == ("tx-1", "tx-3")


def test_missing_inclusion_entries_reports_omissions() -> None:
    inclusion_list = ("tx-1", "tx-2", "tx-3")
    proposed_transactions = ("tx-1", "tx-3")

    missing = missing_inclusion_entries(inclusion_list, proposed_transactions)

    assert missing == ("tx-2",)


# Property-based tests for fork resolution, VRF tiebreaking, and build_inclusion_list


def _block_strategy(round_number: int, max_weight: int = 10) -> st.SearchStrategy[ConsensusBlock]:
    """Strategy for generating ConsensusBlocks with given round number."""
    return st.builds(
        ConsensusBlock,
        round_number=st.just(round_number),
        quorum_weight=st.integers(min_value=1, max_value=max_weight),
        vrf_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
        timestamp=st.just(f"2026-03-10T00:00:{round_number:02d}Z"),
    )


@given(
    shared_length=st.integers(min_value=1, max_value=10),
    chain_a_extra=st.integers(min_value=0, max_value=5),
    chain_b_extra=st.integers(min_value=0, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_fork_resolution_prefers_longer_elapsed_rounds(
    shared_length: int, chain_a_extra: int, chain_b_extra: int
) -> None:
    """
    Property: resolve_partition_fork always prefers the chain with more elapsed rounds.
    """
    assume(chain_a_extra != chain_b_extra)  # Ensure chains differ in length

    # Build shared prefix
    shared = [_block(i, 3, f"shared-{i}") for i in range(shared_length)]

    # Build divergent extensions
    chain_a = shared + [
        _block(shared_length + i, 3, f"a-{shared_length + i}") for i in range(chain_a_extra)
    ]
    chain_b = shared + [
        _block(shared_length + i, 3, f"b-{shared_length + i}") for i in range(chain_b_extra)
    ]

    winner = resolve_partition_fork(tuple(chain_a), tuple(chain_b))

    # Longer elapsed rounds should win
    if chain_a_extra > chain_b_extra:
        assert winner == tuple(chain_a)
    else:
        assert winner == tuple(chain_b)


@given(
    shared_length=st.integers(min_value=1, max_value=8),
    weight_a=st.integers(min_value=1, max_value=10),
    weight_b=st.integers(min_value=1, max_value=10),
    post_fork_length=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_fork_resolution_uses_quorum_weight_at_divergence(
    shared_length: int, weight_a: int, weight_b: int, post_fork_length: int
) -> None:
    """
    Property: When chains have equal elapsed rounds, higher quorum weight at fork point wins.
    """
    assume(weight_a != weight_b)  # Ensure different weights

    # Shared prefix
    shared = [_block(i, 2, f"shared-{i}") for i in range(shared_length)]

    # Divergent blocks with different weights at fork point
    fork_round = shared_length
    chain_a = shared + [
        _block(fork_round + i, weight_a, f"a-{fork_round + i}") for i in range(post_fork_length)
    ]
    chain_b = shared + [
        _block(fork_round + i, weight_b, f"b-{fork_round + i}") for i in range(post_fork_length)
    ]

    winner = resolve_partition_fork(tuple(chain_a), tuple(chain_b))

    # Higher quorum weight at fork should win
    if weight_a > weight_b:
        assert winner == tuple(chain_a)
    else:
        assert winner == tuple(chain_b)


@given(
    shared_length=st.integers(min_value=1, max_value=8),
    seed_a=st.text(alphabet="abcdefghijklmnop", min_size=3, max_size=10),
    seed_b=st.text(alphabet="abcdefghijklmnop", min_size=3, max_size=10),
    post_fork_length=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=100, deadline=None)
def test_fork_resolution_vrf_tiebreaker_is_deterministic(
    shared_length: int, seed_a: str, seed_b: str, post_fork_length: int
) -> None:
    """
    Property: When elapsed rounds and quorum weights are equal, VRF hash tiebreaker is deterministic.
    Lower lexicographic VRF hash wins.
    """
    assume(seed_a != seed_b)  # Ensure different seeds produce different VRF hashes

    # Shared prefix
    shared = [_block(i, 3, f"shared-{i}") for i in range(shared_length)]

    # Equal weight, different VRF hashes
    fork_round = shared_length
    chain_a = shared + [
        _block(fork_round + i, 3, f"{seed_a}-{fork_round + i}") for i in range(post_fork_length)
    ]
    chain_b = shared + [
        _block(fork_round + i, 3, f"{seed_b}-{fork_round + i}") for i in range(post_fork_length)
    ]

    winner = resolve_partition_fork(tuple(chain_a), tuple(chain_b))

    # Verify VRF tiebreaker: lower hash wins
    vrf_index = fork_round + (1 if post_fork_length > 1 else 0)
    vrf_a = chain_a[vrf_index].vrf_hash
    vrf_b = chain_b[vrf_index].vrf_hash

    if vrf_a <= vrf_b:
        assert winner == tuple(chain_a)
    else:
        assert winner == tuple(chain_b)


@given(
    broadcasts=st.lists(
        st.builds(
            TransactionBroadcast,
            tx_id=st.text(alphabet="abcdefghijklmnop", min_size=4, max_size=8),
            round_number=st.just(1),
            broadcast_at=st.integers(min_value=0, max_value=59).map(
                lambda i: f"2026-03-10T00:00:{i:02d}Z"
            ),
            witnesses=st.lists(
                st.text(alphabet="nN123456789", min_size=2, max_size=4),
                min_size=1,
                max_size=5,
                unique=True,
            ).map(tuple),
        ),
        min_size=1,
        max_size=15,
    ),
    minimum_witnesses=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=100, deadline=None)
def test_build_inclusion_list_filters_by_witness_threshold(
    broadcasts: list[TransactionBroadcast], minimum_witnesses: int
) -> None:
    """
    Property: build_inclusion_list only includes tx_ids with >= minimum_witnesses unique witnesses.
    """
    # Aggregate witnesses per tx_id
    witness_counts: dict[str, set[str]] = {}
    for broadcast in broadcasts:
        witness_counts.setdefault(broadcast.tx_id, set()).update(broadcast.witnesses)

    # Build inclusion list
    inclusion_list = build_inclusion_list(tuple(broadcasts), minimum_witnesses=minimum_witnesses)

    # Verify all included tx_ids meet threshold
    for tx_id in inclusion_list:
        assert len(witness_counts[tx_id]) >= minimum_witnesses, (
            f"tx_id {tx_id} included with only {len(witness_counts[tx_id])} witnesses"
        )

    # Verify all eligible tx_ids are included
    eligible = {
        tx_id for tx_id, witnesses in witness_counts.items() if len(witnesses) >= minimum_witnesses
    }
    assert set(inclusion_list) == eligible


@given(
    broadcasts=st.lists(
        st.builds(
            TransactionBroadcast,
            tx_id=st.text(alphabet="tx", min_size=3, max_size=6),
            round_number=st.just(1),
            broadcast_at=st.integers(min_value=0, max_value=59).map(
                lambda i: f"2026-03-10T00:00:{i:02d}Z"
            ),
            witnesses=st.just(("w1", "w2", "w3")),  # All have sufficient witnesses
        ),
        min_size=2,
        max_size=10,
        unique_by=lambda b: b.tx_id,
    ),
)
@settings(max_examples=100, deadline=None)
def test_build_inclusion_list_sorts_by_timestamp_then_broadcast_order(
    broadcasts: list[TransactionBroadcast],
) -> None:
    """
    Property: build_inclusion_list sorts by (timestamp, broadcast_index, tx_id).
    """
    inclusion_list = build_inclusion_list(tuple(broadcasts), minimum_witnesses=2)

    # Extract timestamps for each included tx_id
    tx_order: dict[str, tuple[str, int]] = {}
    for index, broadcast in enumerate(broadcasts):
        if broadcast.tx_id not in tx_order:
            tx_order[broadcast.tx_id] = (broadcast.broadcast_at, index)

    # Verify sorting
    for i in range(len(inclusion_list) - 1):
        tx_current = inclusion_list[i]
        tx_next = inclusion_list[i + 1]

        timestamp_current, index_current = tx_order[tx_current]
        timestamp_next, index_next = tx_order[tx_next]

        # Current should be <= next in sort order
        assert (timestamp_current, index_current, tx_current) <= (
            timestamp_next,
            index_next,
            tx_next,
        )


@given(
    chain_length=st.integers(min_value=2, max_value=20),
    start_round=st.integers(min_value=0, max_value=50),
)
@settings(max_examples=100, deadline=None)
def test_proof_of_elapsed_rounds_matches_last_minus_first(
    chain_length: int, start_round: int
) -> None:
    """
    Property: proof_of_elapsed_rounds returns last_round - first_round.
    """
    # Generate timestamps with valid seconds (0-59)
    chain = [
        ConsensusBlock(
            round_number=start_round + i,
            quorum_weight=2,
            vrf_hash=vrf_hash_from_seed(f"block-{i}"),
            timestamp=f"2026-03-10T00:00:{min(i, 59):02d}Z",
        )
        for i in range(chain_length)
    ]

    elapsed = proof_of_elapsed_rounds(tuple(chain))

    expected = (start_round + chain_length - 1) - start_round
    assert elapsed == expected


@given(
    round_sequence=st.lists(
        st.integers(min_value=0, max_value=100), min_size=1, max_size=15, unique=True
    ),
    leader_count=st.integers(min_value=1, max_value=5),
    rotation_window=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=100, deadline=None)
def test_select_rotating_leader_cycles_through_all_leaders(
    round_sequence: list[int], leader_count: int, rotation_window: int
) -> None:
    """
    Property: select_rotating_leader cycles through all leaders in order based on rotation_window.
    """
    leaders = tuple(f"leader-{i}" for i in range(leader_count))

    selected_leaders = [
        select_rotating_leader(round_num, leaders, rotation_window=rotation_window)
        for round_num in round_sequence
    ]

    # Verify all selected leaders are valid
    for leader in selected_leaders:
        assert leader in leaders

    # Verify rotation pattern for sequential rounds
    # Generate a contiguous sequence to properly test the cycle
    if len(round_sequence) > 0:
        min_round = min(round_sequence)
        # Need enough sequential rounds to see all leaders
        full_cycle_size = leader_count * rotation_window
        sequential_rounds = list(range(min_round, min_round + full_cycle_size))

        cycle_leaders = {
            select_rotating_leader(r, leaders, rotation_window=rotation_window)
            for r in sequential_rounds
        }
        # Should see all leaders when we go through a full cycle of sequential rounds
        assert len(cycle_leaders) == leader_count
