"""
Tests for protocol.partition — Partition detection and fork resolution.

Covers:
- Dataclass validation: VotePublication, PublishedVote, ConsensusBlock, etc.
- validate_proof_of_wait() — round progression enforcement
- proof_of_elapsed_rounds() — elapsed round counting
- find_first_divergent_round() — fork point detection
- resolve_partition_fork() — deterministic fork choice (elapsed, weight, VRF)
- detect_slashable_equivocations() — Nothing-at-Stake detection
- select_rotating_leader() — round-robin leader selection
- build_inclusion_list() — censorship-resistant tx ordering
- missing_inclusion_entries() — missing tx detection
- select_random_peers() — cryptographic peer sampling
- PartitionDetector — quorum detection, watermark freeze, recovery
- vrf_hash_from_seed() — deterministic VRF-style hash

Pure protocol logic — no DB, Redis, or external APIs required.
"""

from __future__ import annotations

import pytest

from protocol.hashes import hash_bytes
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


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _vrf(seed: str) -> str:
    return hash_bytes(seed.encode()).hex()


def _block(round_number: int, *, weight: int = 100, seed: str = "") -> ConsensusBlock:
    return ConsensusBlock(
        round_number=round_number,
        quorum_weight=weight,
        vrf_hash=_vrf(seed or f"block-{round_number}"),
        timestamp="2024-01-01T00:00:00Z",
    )


def _chain(start: int, length: int, *, weight: int = 100) -> tuple[ConsensusBlock, ...]:
    return tuple(_block(start + i, weight=weight) for i in range(length))


def _pub(vote_hash_seed: str = "vote") -> VotePublication:
    return VotePublication(
        vote_hash=hash_bytes(vote_hash_seed.encode()).hex(),
        published_at="2024-01-01T00:00:00Z",
        witnesses=("w1", "w2"),
    )


# ------------------------------------------------------------------ #
# VotePublication validation
# ------------------------------------------------------------------ #


class TestVotePublication:
    def test_valid(self) -> None:
        pub = _pub()
        assert len(pub.witnesses) == 2

    def test_empty_vote_hash(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            VotePublication(vote_hash="", published_at="2024-01-01T00:00:00Z", witnesses=("w1",))

    def test_invalid_hex_vote_hash(self) -> None:
        with pytest.raises(ValueError, match="hex-encoded"):
            VotePublication(
                vote_hash="not-hex", published_at="2024-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_wrong_length_vote_hash(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            VotePublication(
                vote_hash="ab" * 16, published_at="2024-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_invalid_timestamp(self) -> None:
        with pytest.raises(ValueError, match="ISO 8601"):
            VotePublication(
                vote_hash=_vrf("v"),
                published_at="not-a-timestamp",
                witnesses=("w1",),
            )

    def test_empty_witnesses(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            VotePublication(vote_hash=_vrf("v"), published_at="2024-01-01T00:00:00Z", witnesses=())

    def test_duplicate_witnesses(self) -> None:
        with pytest.raises(ValueError, match="unique"):
            VotePublication(
                vote_hash=_vrf("v"),
                published_at="2024-01-01T00:00:00Z",
                witnesses=("w1", "w1"),
            )


# ------------------------------------------------------------------ #
# PublishedVote validation
# ------------------------------------------------------------------ #


class TestPublishedVote:
    def test_valid(self) -> None:
        vote = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c1", publication=_pub()
        )
        assert vote.node_id == "n1"

    def test_empty_node_id(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            PublishedVote(
                node_id="", shard_id="s1", round_number=0, chain_id="c1", publication=_pub()
            )

    def test_negative_round(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            PublishedVote(
                node_id="n1", shard_id="s1", round_number=-1, chain_id="c1", publication=_pub()
            )


# ------------------------------------------------------------------ #
# ConsensusBlock validation
# ------------------------------------------------------------------ #


class TestConsensusBlock:
    def test_valid(self) -> None:
        b = _block(0)
        assert b.round_number == 0

    def test_negative_round(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ConsensusBlock(
                round_number=-1,
                quorum_weight=100,
                vrf_hash=_vrf("x"),
                timestamp="2024-01-01T00:00:00Z",
            )

    def test_negative_weight(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ConsensusBlock(
                round_number=0,
                quorum_weight=-1,
                vrf_hash=_vrf("x"),
                timestamp="2024-01-01T00:00:00Z",
            )

    def test_empty_vrf(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ConsensusBlock(
                round_number=0,
                quorum_weight=100,
                vrf_hash="",
                timestamp="2024-01-01T00:00:00Z",
            )

    def test_bad_timestamp(self) -> None:
        with pytest.raises(ValueError, match="ISO 8601"):
            ConsensusBlock(
                round_number=0,
                quorum_weight=100,
                vrf_hash=_vrf("x"),
                timestamp="bad-ts",
            )


# ------------------------------------------------------------------ #
# TransactionBroadcast validation
# ------------------------------------------------------------------ #


class TestTransactionBroadcast:
    def test_valid(self) -> None:
        tb = TransactionBroadcast(
            tx_id="tx1", round_number=0, broadcast_at="2024-01-01T00:00:00Z", witnesses=("w1",)
        )
        assert tb.tx_id == "tx1"

    def test_empty_tx_id(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            TransactionBroadcast(
                tx_id="", round_number=0, broadcast_at="2024-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_empty_witnesses(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            TransactionBroadcast(
                tx_id="tx1", round_number=0, broadcast_at="2024-01-01T00:00:00Z", witnesses=()
            )


# ------------------------------------------------------------------ #
# validate_proof_of_wait
# ------------------------------------------------------------------ #


class TestValidateProofOfWait:
    def test_valid_chain(self) -> None:
        validate_proof_of_wait(_chain(0, 5))

    def test_empty_chain_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_proof_of_wait([])

    def test_gap_in_rounds_raises(self) -> None:
        blocks = [_block(0), _block(2)]  # Skips round 1
        with pytest.raises(ValueError, match="advance by exactly one"):
            validate_proof_of_wait(blocks)

    def test_single_block_valid(self) -> None:
        validate_proof_of_wait([_block(0)])

    def test_non_zero_start_valid(self) -> None:
        validate_proof_of_wait(_chain(5, 3))


# ------------------------------------------------------------------ #
# proof_of_elapsed_rounds
# ------------------------------------------------------------------ #


class TestProofOfElapsedRounds:
    def test_five_blocks(self) -> None:
        assert proof_of_elapsed_rounds(_chain(0, 5)) == 4

    def test_single_block(self) -> None:
        assert proof_of_elapsed_rounds([_block(0)]) == 0

    def test_offset_start(self) -> None:
        assert proof_of_elapsed_rounds(_chain(10, 6)) == 5


# ------------------------------------------------------------------ #
# find_first_divergent_round
# ------------------------------------------------------------------ #


class TestFindFirstDivergentRound:
    def test_identical_chains(self) -> None:
        chain = _chain(0, 3)
        assert find_first_divergent_round(chain, chain) == 3

    def test_diverge_at_start(self) -> None:
        a = (_block(0, seed="a"),)
        b = (_block(0, seed="b"),)
        assert find_first_divergent_round(a, b) == 0

    def test_diverge_in_middle(self) -> None:
        shared = _block(0, seed="same")
        a = (shared, _block(1, seed="a"))
        b = (shared, _block(1, seed="b"))
        assert find_first_divergent_round(a, b) == 1

    def test_different_lengths(self) -> None:
        chain = _chain(0, 5)
        short = _chain(0, 3)
        assert find_first_divergent_round(chain, short) == 3


# ------------------------------------------------------------------ #
# resolve_partition_fork
# ------------------------------------------------------------------ #


class TestResolvePartitionFork:
    def test_longer_chain_wins(self) -> None:
        a = _chain(0, 10)
        b = _chain(0, 5)
        winner = resolve_partition_fork(a, b)
        assert len(winner) == 10

    def test_identical_chains_returns_a(self) -> None:
        chain = _chain(0, 5)
        winner = resolve_partition_fork(chain, chain)
        assert winner == chain

    def test_higher_weight_at_fork_wins(self) -> None:
        shared = _block(0, seed="shared")
        a = (shared, _block(1, weight=200, seed="a"))
        b = (shared, _block(1, weight=100, seed="b"))
        winner = resolve_partition_fork(a, b)
        assert winner == a

    def test_vrf_tiebreaker(self) -> None:
        shared = _block(0, seed="shared")
        # Same weight, different VRF — lexicographically smaller VRF wins
        block_a = _block(1, weight=100, seed="aaa")
        block_b = _block(1, weight=100, seed="bbb")
        a = (shared, block_a)
        b = (shared, block_b)
        winner = resolve_partition_fork(a, b)
        # The winner should have the lexicographically smaller VRF at fork+1
        if block_a.vrf_hash <= block_b.vrf_hash:
            assert winner == a
        else:
            assert winner == b


# ------------------------------------------------------------------ #
# detect_slashable_equivocations
# ------------------------------------------------------------------ #


class TestDetectSlashableEquivocations:
    def test_no_equivocation(self) -> None:
        vote = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c1", publication=_pub("v1")
        )
        evidence = detect_slashable_equivocations([vote])
        assert evidence == ()

    def test_double_signing_detected(self) -> None:
        vote1 = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c1", publication=_pub("v1")
        )
        vote2 = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c2", publication=_pub("v2")
        )
        evidence = detect_slashable_equivocations([vote1, vote2])
        assert len(evidence) == 1
        assert evidence[0].node_id == "n1"
        assert len(evidence[0].conflicting_chain_ids) == 2

    def test_different_rounds_not_equivocation(self) -> None:
        vote1 = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c1", publication=_pub("v1")
        )
        vote2 = PublishedVote(
            node_id="n1", shard_id="s1", round_number=1, chain_id="c2", publication=_pub("v2")
        )
        evidence = detect_slashable_equivocations([vote1, vote2])
        assert evidence == ()

    def test_different_nodes_not_equivocation(self) -> None:
        vote1 = PublishedVote(
            node_id="n1", shard_id="s1", round_number=0, chain_id="c1", publication=_pub("v1")
        )
        vote2 = PublishedVote(
            node_id="n2", shard_id="s1", round_number=0, chain_id="c2", publication=_pub("v2")
        )
        evidence = detect_slashable_equivocations([vote1, vote2])
        assert evidence == ()


# ------------------------------------------------------------------ #
# select_rotating_leader
# ------------------------------------------------------------------ #


class TestSelectRotatingLeader:
    def test_round_robin(self) -> None:
        leaders = ["alice", "bob", "carol"]
        assert select_rotating_leader(0, leaders) == "alice"
        assert select_rotating_leader(1, leaders) == "bob"
        assert select_rotating_leader(2, leaders) == "carol"
        assert select_rotating_leader(3, leaders) == "alice"

    def test_rotation_window(self) -> None:
        leaders = ["alice", "bob"]
        assert select_rotating_leader(0, leaders, rotation_window=2) == "alice"
        assert select_rotating_leader(1, leaders, rotation_window=2) == "alice"
        assert select_rotating_leader(2, leaders, rotation_window=2) == "bob"

    def test_empty_leaders_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            select_rotating_leader(0, [])

    def test_negative_round_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            select_rotating_leader(-1, ["a"])

    def test_zero_window_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            select_rotating_leader(0, ["a"], rotation_window=0)

    def test_single_leader(self) -> None:
        assert select_rotating_leader(99, ["alice"]) == "alice"


# ------------------------------------------------------------------ #
# build_inclusion_list / missing_inclusion_entries
# ------------------------------------------------------------------ #


class TestBuildInclusionList:
    def test_sufficient_witnesses(self) -> None:
        b1 = TransactionBroadcast(
            tx_id="tx1",
            round_number=0,
            broadcast_at="2024-01-01T00:00:00Z",
            witnesses=("w1", "w2"),
        )
        result = build_inclusion_list([b1], minimum_witnesses=2)
        assert "tx1" in result

    def test_insufficient_witnesses(self) -> None:
        b1 = TransactionBroadcast(
            tx_id="tx1",
            round_number=0,
            broadcast_at="2024-01-01T00:00:00Z",
            witnesses=("w1",),
        )
        result = build_inclusion_list([b1], minimum_witnesses=2)
        assert "tx1" not in result

    def test_combined_witnesses_across_broadcasts(self) -> None:
        b1 = TransactionBroadcast(
            tx_id="tx1",
            round_number=0,
            broadcast_at="2024-01-01T00:00:00Z",
            witnesses=("w1",),
        )
        b2 = TransactionBroadcast(
            tx_id="tx1",
            round_number=0,
            broadcast_at="2024-01-01T00:00:01Z",
            witnesses=("w2",),
        )
        result = build_inclusion_list([b1, b2], minimum_witnesses=2)
        assert "tx1" in result

    def test_zero_witnesses_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            build_inclusion_list([], minimum_witnesses=0)


class TestMissingInclusionEntries:
    def test_all_present(self) -> None:
        assert missing_inclusion_entries(["tx1", "tx2"], ["tx1", "tx2", "tx3"]) == ()

    def test_some_missing(self) -> None:
        result = missing_inclusion_entries(["tx1", "tx2", "tx3"], ["tx1"])
        assert set(result) == {"tx2", "tx3"}

    def test_empty_inclusion(self) -> None:
        assert missing_inclusion_entries([], ["tx1"]) == ()

    def test_empty_proposed(self) -> None:
        result = missing_inclusion_entries(["tx1", "tx2"], [])
        assert set(result) == {"tx1", "tx2"}


# ------------------------------------------------------------------ #
# select_random_peers
# ------------------------------------------------------------------ #


class TestSelectRandomPeers:
    def test_full_sample(self) -> None:
        nodes = ["n1", "n2", "n3"]
        result = select_random_peers(nodes, 3)
        assert set(result) == set(nodes)

    def test_subsample(self) -> None:
        nodes = ["n1", "n2", "n3", "n4", "n5"]
        result = select_random_peers(nodes, 2)
        assert len(result) == 2
        assert all(n in nodes for n in result)

    def test_zero_sample_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            select_random_peers(["n1"], 0)

    def test_oversized_sample_raises(self) -> None:
        with pytest.raises(ValueError, match="exceed"):
            select_random_peers(["n1"], 2)


# ------------------------------------------------------------------ #
# PartitionDetector
# ------------------------------------------------------------------ #


class TestPartitionDetector:
    def _make_state(self, start: int = 0, length: int = 3) -> ConsensusChainState:
        return ConsensusChainState(round_number=start, chain=_chain(start, length))

    def test_healthy_quorum(self) -> None:
        state = self._make_state()
        detector = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: state,
        )
        healthy = detector.check_network_health(0, ["n1", "n2", "n3"])
        assert healthy
        assert 0 in detector.last_quorum_time

    def test_quorum_loss_freezes_watermark(self) -> None:
        state = self._make_state()
        detector = PartitionDetector(
            ping_nodes=lambda nodes: [],  # No nodes reachable
            get_current_state=lambda: state,
        )
        healthy = detector.check_network_health(1, ["n1", "n2", "n3"])
        assert not healthy
        assert 1 in detector.frozen_watermarks

    def test_partial_quorum_loss(self) -> None:
        state = self._make_state()
        # Only 1 of 3 reachable (< 2/3 = 2)
        detector = PartitionDetector(
            ping_nodes=lambda nodes: ["n1"],
            get_current_state=lambda: state,
        )
        healthy = detector.check_network_health(2, ["n1", "n2", "n3"])
        assert not healthy

    def test_exactly_two_thirds_is_healthy(self) -> None:
        state = self._make_state()
        # 2 of 3 reachable = 66.7% >= ceil(2/3 * 3) = 2
        detector = PartitionDetector(
            ping_nodes=lambda nodes: ["n1", "n2"],
            get_current_state=lambda: state,
        )
        healthy = detector.check_network_health(3, ["n1", "n2", "n3"])
        assert healthy

    def test_empty_nodes_raises(self) -> None:
        state = self._make_state()
        detector = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: state,
        )
        with pytest.raises(ValueError, match="cannot be empty"):
            detector.check_network_health(0, [])

    def test_recover_from_partition(self) -> None:
        state = self._make_state(0, 5)
        detector = PartitionDetector(
            ping_nodes=lambda nodes: [],
            get_current_state=lambda: state,
        )
        # Lose quorum at round 1
        detector.check_network_health(1, ["n1", "n2", "n3"])
        assert 1 in detector.frozen_watermarks

        # Recover at round 10
        winner = detector.recover_from_partition(10)
        assert isinstance(winner, ConsensusChainState)
        # Frozen watermark for round 1 should be cleaned up
        assert 1 not in detector.frozen_watermarks
        assert 10 in detector.last_quorum_time

    def test_cross_network_verifier_rejection(self) -> None:
        state = self._make_state()
        detector = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: state,
            cross_network_verifier=lambda reachable: False,  # Always reject
        )
        healthy = detector.check_network_health(0, ["n1", "n2", "n3"])
        assert not healthy
        assert 0 in detector.frozen_watermarks

    def test_peer_group_diversity_check(self) -> None:
        state = self._make_state()
        detector = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: state,
            peer_groups={"n1": "dc1", "n2": "dc1", "n3": "dc1"},
            min_peer_group_diversity=2,  # Require 2 different groups
        )
        # All nodes in same group => insufficient diversity
        healthy = detector.check_network_health(0, ["n1", "n2", "n3"])
        assert not healthy


# ------------------------------------------------------------------ #
# vrf_hash_from_seed
# ------------------------------------------------------------------ #


class TestVrfHashFromSeed:
    def test_deterministic(self) -> None:
        assert vrf_hash_from_seed("test") == vrf_hash_from_seed("test")

    def test_different_seeds_different_hashes(self) -> None:
        assert vrf_hash_from_seed("a") != vrf_hash_from_seed("b")

    def test_returns_hex_string(self) -> None:
        result = vrf_hash_from_seed("seed")
        assert isinstance(result, str)
        assert len(result) == 64
        bytes.fromhex(result)
