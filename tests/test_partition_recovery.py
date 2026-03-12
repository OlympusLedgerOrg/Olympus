from __future__ import annotations

import pytest

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


def test_find_first_divergent_round_identifies_first_difference() -> None:
    chain_a = _chain(_block(0, 1, "x"), _block(1, 1, "y"), _block(2, 1, "z"))
    chain_b = _chain(_block(0, 1, "x"), _block(1, 2, "different"), _block(2, 1, "z"))

    idx = find_first_divergent_round(chain_a, chain_b)

    assert idx == 1


def test_detect_slashable_equivocations_requires_conflicting_published_votes() -> None:
    vote_a = PublishedVote(
        node_id="guardian-1",
        shard_id="records/a",
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
        shard_id="records/a",
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
