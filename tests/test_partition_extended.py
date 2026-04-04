"""Extended tests for protocol/partition.py targeting uncovered lines."""

import pytest

from protocol.hashes import hash_bytes
from protocol.partition import (
    ConsensusBlock,
    ConsensusChainState,
    PartitionDetector,
    PublishedVote,
    TransactionBroadcast,
    VotePublication,
    detect_slashable_equivocations,
    resolve_partition_fork,
    select_random_peers,
    select_rotating_leader,
    vrf_hash_from_seed,
)


def _vrf(seed: str) -> str:
    return hash_bytes(seed.encode()).hex()


def _block(rnd: int, weight: int = 1, vrf_seed: str | None = None) -> ConsensusBlock:
    vrf = _vrf(vrf_seed or f"vrf-{rnd}")
    return ConsensusBlock(
        round_number=rnd, quorum_weight=weight, vrf_hash=vrf, timestamp="2025-01-01T00:00:00Z"
    )


# ── VotePublication validation (lines 46, 49-50, 52, 55-56, 58, 60, 62) ──


class TestVotePublication:
    def test_empty_vote_hash(self):
        with pytest.raises(ValueError, match="non-empty hex"):
            VotePublication(vote_hash="", published_at="2025-01-01T00:00:00Z", witnesses=("w1",))

    def test_non_hex_vote_hash(self):
        with pytest.raises(ValueError, match="hex-encoded"):
            VotePublication(
                vote_hash="zzzz", published_at="2025-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_wrong_length_vote_hash(self):
        with pytest.raises(ValueError, match="32 bytes"):
            VotePublication(
                vote_hash="aa" * 16, published_at="2025-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_bad_timestamp(self):
        with pytest.raises(ValueError, match="ISO 8601"):
            VotePublication(vote_hash="aa" * 32, published_at="not-a-date", witnesses=("w1",))

    def test_empty_witnesses(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            VotePublication(vote_hash="aa" * 32, published_at="2025-01-01T00:00:00Z", witnesses=())

    def test_empty_witness_id(self):
        with pytest.raises(ValueError, match="non-empty strings"):
            VotePublication(
                vote_hash="aa" * 32, published_at="2025-01-01T00:00:00Z", witnesses=("",)
            )

    def test_duplicate_witnesses(self):
        with pytest.raises(ValueError, match="unique"):
            VotePublication(
                vote_hash="aa" * 32, published_at="2025-01-01T00:00:00Z", witnesses=("w1", "w1")
            )

    def test_valid_publication(self):
        vp = VotePublication(
            vote_hash="aa" * 32, published_at="2025-01-01T00:00:00Z", witnesses=("w1", "w2")
        )
        assert vp.vote_hash == "aa" * 32


# ── PublishedVote validation (lines 77, 79, 81, 83) ──


class TestPublishedVote:
    def _pub(self):
        return VotePublication(
            vote_hash="aa" * 32, published_at="2025-01-01T00:00:00Z", witnesses=("w1",)
        )

    def test_empty_shard_id(self):
        with pytest.raises(ValueError, match="shard_id"):
            PublishedVote(
                node_id="n1", shard_id="", round_number=0, chain_id="c1", publication=self._pub()
            )

    def test_negative_round(self):
        with pytest.raises(ValueError, match="non-negative"):
            PublishedVote(
                node_id="n1", shard_id="s1", round_number=-1, chain_id="c1", publication=self._pub()
            )

    def test_empty_chain_id(self):
        with pytest.raises(ValueError, match="chain_id"):
            PublishedVote(
                node_id="n1", shard_id="s1", round_number=0, chain_id="", publication=self._pub()
            )


# ── ConsensusBlock validation (lines 108, 110, 112, 118, 121-122) ──


class TestConsensusBlock:
    def test_negative_quorum_weight(self):
        with pytest.raises(ValueError, match="quorum_weight"):
            ConsensusBlock(
                round_number=0,
                quorum_weight=-1,
                vrf_hash="aa" * 32,
                timestamp="2025-01-01T00:00:00Z",
            )

    def test_empty_vrf_hash(self):
        with pytest.raises(ValueError, match="non-empty"):
            ConsensusBlock(
                round_number=0, quorum_weight=0, vrf_hash="", timestamp="2025-01-01T00:00:00Z"
            )

    def test_wrong_length_vrf(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ConsensusBlock(
                round_number=0,
                quorum_weight=0,
                vrf_hash="aa" * 16,
                timestamp="2025-01-01T00:00:00Z",
            )

    def test_bad_timestamp(self):
        with pytest.raises(ValueError, match="ISO 8601"):
            ConsensusBlock(round_number=0, quorum_weight=0, vrf_hash="aa" * 32, timestamp="bad")


# ── ConsensusChainState (line 134) ──


class TestConsensusChainState:
    def test_negative_round(self):
        with pytest.raises(ValueError, match="non-negative"):
            ConsensusChainState(round_number=-1, chain=(_block(0),))


# ── TransactionBroadcast validation (lines 149, 151, 154-155, 157, 159, 161) ──


class TestTransactionBroadcast:
    def test_empty_tx_id(self):
        with pytest.raises(ValueError, match="tx_id"):
            TransactionBroadcast(
                tx_id="", round_number=0, broadcast_at="2025-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_negative_round(self):
        with pytest.raises(ValueError, match="non-negative"):
            TransactionBroadcast(
                tx_id="tx1", round_number=-1, broadcast_at="2025-01-01T00:00:00Z", witnesses=("w1",)
            )

    def test_bad_timestamp(self):
        with pytest.raises(ValueError, match="ISO 8601"):
            TransactionBroadcast(tx_id="tx1", round_number=0, broadcast_at="bad", witnesses=("w1",))

    def test_empty_witnesses(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            TransactionBroadcast(
                tx_id="tx1", round_number=0, broadcast_at="2025-01-01T00:00:00Z", witnesses=()
            )

    def test_empty_witness_string(self):
        with pytest.raises(ValueError, match="non-empty strings"):
            TransactionBroadcast(
                tx_id="tx1", round_number=0, broadcast_at="2025-01-01T00:00:00Z", witnesses=("",)
            )

    def test_duplicate_witnesses(self):
        with pytest.raises(ValueError, match="unique"):
            TransactionBroadcast(
                tx_id="tx1",
                round_number=0,
                broadcast_at="2025-01-01T00:00:00Z",
                witnesses=("w1", "w1"),
            )


# ── detect_slashable_equivocations (line 174-175, 180) ──


class TestSlashableEquivocations:
    def _pub(self, vh: str) -> VotePublication:
        return VotePublication(vote_hash=vh, published_at="2025-01-01T00:00:00Z", witnesses=("w1",))

    def test_no_equivocation_single_chain(self):
        vote = PublishedVote(
            node_id="n1",
            shard_id="s1",
            round_number=0,
            chain_id="c1",
            publication=self._pub("aa" * 32),
        )
        result = detect_slashable_equivocations([vote])
        assert result == ()

    def test_equivocation_detected(self):
        v1 = PublishedVote(
            node_id="n1",
            shard_id="s1",
            round_number=0,
            chain_id="c1",
            publication=self._pub("aa" * 32),
        )
        v2 = PublishedVote(
            node_id="n1",
            shard_id="s1",
            round_number=0,
            chain_id="c2",
            publication=self._pub("bb" * 32),
        )
        result = detect_slashable_equivocations([v1, v2])
        assert len(result) == 1
        assert result[0].node_id == "n1"

    def test_conflicting_hash_same_chain(self):
        """Same node, same chain, different vote_hash → keeps min hash."""
        v1 = PublishedVote(
            node_id="n1",
            shard_id="s1",
            round_number=0,
            chain_id="c1",
            publication=self._pub("bb" * 32),
        )
        v2 = PublishedVote(
            node_id="n1",
            shard_id="s1",
            round_number=0,
            chain_id="c1",
            publication=self._pub("aa" * 32),
        )
        # Only one chain, so no equivocation
        result = detect_slashable_equivocations([v1, v2])
        assert result == ()


# ── select_rotating_leader (lines 200, 202, 204, 206) ──


class TestSelectRotatingLeader:
    def test_negative_round(self):
        with pytest.raises(ValueError, match="non-negative"):
            select_rotating_leader(-1, ["a"])

    def test_zero_rotation_window(self):
        with pytest.raises(ValueError, match="positive"):
            select_rotating_leader(0, ["a"], rotation_window=0)

    def test_empty_leaders(self):
        with pytest.raises(ValueError, match="empty"):
            select_rotating_leader(0, [])

    def test_empty_leader_string(self):
        with pytest.raises(ValueError, match="non-empty"):
            select_rotating_leader(0, [""])


# ── resolve_partition_fork tiebreaker paths (lines 309, 311, 313, 317) ──


class TestResolvePartitionFork:
    def test_chain_b_longer(self):
        chain_a = [_block(0)]
        chain_b = [_block(0), _block(1)]
        result = resolve_partition_fork(chain_a, chain_b)
        assert result == tuple(chain_b)

    def test_identical_chains(self):
        chain = [_block(0), _block(1)]
        result = resolve_partition_fork(chain, chain)
        assert result == tuple(chain)

    def test_vrf_tiebreaker(self):
        """Equal elapsed rounds, equal weight → VRF tiebreaker."""
        chain_a = [_block(0, 1, "seed-a"), _block(1, 1, "seed-a2")]
        chain_b = [_block(0, 1, "seed-a"), _block(1, 1, "seed-b2")]
        result = resolve_partition_fork(chain_a, chain_b)
        assert result in (tuple(chain_a), tuple(chain_b))

    def test_quorum_weight_tiebreaker(self):
        """Equal elapsed rounds, different weight at fork."""
        chain_a = [_block(0, 1, "seed"), _block(1, 5, "seed-a")]
        chain_b = [_block(0, 1, "seed"), _block(1, 10, "seed-b")]
        result = resolve_partition_fork(chain_a, chain_b)
        assert result == tuple(chain_b)


# ── select_random_peers (line 345) ──


class TestSelectRandomPeers:
    def test_sample_equals_nodes(self):
        result = select_random_peers(["a", "b"], 2)
        assert set(result) == {"a", "b"}

    def test_sample_subset(self):
        result = select_random_peers(["a", "b", "c"], 2)
        assert len(result) == 2


# ── PartitionDetector (lines 387, 395, 397, 408, 447, 455) ──


class TestPartitionDetector:
    def _make_state(self, rnd=0):
        return ConsensusChainState(round_number=rnd, chain=(_block(rnd),))

    def test_empty_nodes_raises(self):
        det = PartitionDetector(
            ping_nodes=lambda _: [], get_current_state=lambda: self._make_state()
        )
        with pytest.raises(ValueError, match="empty"):
            det.check_network_health(0, [])

    def test_sample_size_clamped(self):
        """sample_size > len(nodes) is clamped down."""
        det = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: self._make_state(),
            sample_size=100,
        )
        assert det.check_network_health(0, ["n1", "n2"]) is True

    def test_insufficient_peer_group_diversity(self):
        det = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: self._make_state(),
            peer_groups={"n1": "group-a", "n2": "group-a"},
            min_peer_group_diversity=2,
        )
        result = det.check_network_health(0, ["n1", "n2"])
        assert result is False
        assert 0 in det.frozen_watermarks

    def test_cross_network_verifier_rejection(self):
        det = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: self._make_state(),
            cross_network_verifier=lambda _: False,
        )
        result = det.check_network_health(0, ["n1", "n2", "n3"])
        assert result is False

    def test_recover_skips_future_rounds(self):
        """Frozen watermarks at or beyond healed_round are not processed."""
        det = PartitionDetector(
            ping_nodes=lambda nodes: list(nodes),
            get_current_state=lambda: self._make_state(5),
        )
        det.frozen_watermarks[3] = self._make_state(3)
        det.frozen_watermarks[10] = self._make_state(10)
        winner = det.recover_from_partition(5)
        # Round 10 should remain in frozen_watermarks
        assert 10 in det.frozen_watermarks
        assert 3 not in det.frozen_watermarks
        assert winner is not None


# ── vrf_hash_from_seed ──


class TestVrfHashFromSeed:
    def test_deterministic(self):
        assert vrf_hash_from_seed("test") == vrf_hash_from_seed("test")

    def test_different_seeds(self):
        assert vrf_hash_from_seed("a") != vrf_hash_from_seed("b")
