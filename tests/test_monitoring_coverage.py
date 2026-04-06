"""
Tests for protocol.monitoring — LogMonitor and split-view detection.

Covers:
- LogMonitor.record_observation() with valid STHs
- Append-only growth enforcement
- Split-view detection (same size, different root)
- Consistency proof requirement
- poll_node() with fetchers
- split_view_evidence() detection
- observed() iteration
"""

from __future__ import annotations

import nacl.signing
import pytest

from protocol.consistency import ConsistencyProof, generate_consistency_proof
from protocol.epochs import SignedTreeHead
from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree
from protocol.monitoring import LogMonitor, Observation


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_tree(n: int) -> MerkleTree:
    return MerkleTree([hash_bytes(f"leaf-{i}".encode()) for i in range(n)])


def _make_sth(
    key: nacl.signing.SigningKey,
    epoch_id: int,
    tree: MerkleTree,
) -> SignedTreeHead:
    return SignedTreeHead.create(
        epoch_id=epoch_id,
        tree_size=len(tree.leaves),
        merkle_root=tree.get_root(),
        signing_key=key,
    )


# ------------------------------------------------------------------ #
# Observation dataclass
# ------------------------------------------------------------------ #


class TestObservation:
    """Tests for the Observation dataclass."""

    def test_frozen(self) -> None:
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(5))
        obs = Observation(node_id="n1", shard_id="s1", sth=sth)
        with pytest.raises(AttributeError):
            obs.node_id = "n2"  # type: ignore[misc]


# ------------------------------------------------------------------ #
# record_observation
# ------------------------------------------------------------------ #


class TestRecordObservation:
    """Tests for LogMonitor.record_observation()."""

    def test_first_observation_accepted(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(5))
        obs = monitor.record_observation(node_id="n1", shard_id="s1", sth=sth)
        assert obs.node_id == "n1"
        assert obs.shard_id == "s1"

    def test_invalid_signature_rejected(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(5))
        tampered = SignedTreeHead(
            epoch_id=sth.epoch_id,
            tree_size=sth.tree_size,
            merkle_root=sth.merkle_root,
            timestamp=sth.timestamp,
            signature="00" * 64,
            signer_pubkey=sth.signer_pubkey,
        )
        with pytest.raises(ValueError, match="Invalid STH signature"):
            monitor.record_observation(node_id="n1", shard_id="s1", sth=tampered)

    def test_tree_size_regression_rejected(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth1 = _make_sth(key, 1, _make_tree(10))
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        sth2 = _make_sth(key, 2, _make_tree(5))
        with pytest.raises(ValueError, match="regressed"):
            monitor.record_observation(node_id="n1", shard_id="s1", sth=sth2)

    def test_same_size_different_root_is_split_view(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        tree1 = _make_tree(5)
        sth1 = _make_sth(key, 1, tree1)
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        # Create a different tree with same number of leaves but different content
        different_leaves = [hash_bytes(f"other-{i}".encode()) for i in range(5)]
        tree2 = MerkleTree(different_leaves)
        sth2 = SignedTreeHead.create(
            epoch_id=2,
            tree_size=5,
            merkle_root=tree2.get_root(),
            signing_key=key,
        )
        with pytest.raises(ValueError, match="Split view"):
            monitor.record_observation(node_id="n1", shard_id="s1", sth=sth2)

    def test_same_size_same_root_accepted(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth1 = _make_sth(key, 1, tree)
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        # Same size, same root — should be accepted
        sth2 = SignedTreeHead.create(
            epoch_id=2,
            tree_size=5,
            merkle_root=tree.get_root(),
            signing_key=key,
        )
        obs = monitor.record_observation(node_id="n1", shard_id="s1", sth=sth2)
        assert obs.sth == sth2

    def test_growth_requires_proof(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth1 = _make_sth(key, 1, _make_tree(5))
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        sth2 = _make_sth(key, 2, _make_tree(10))
        with pytest.raises(ValueError, match="Consistency proof required"):
            monitor.record_observation(node_id="n1", shard_id="s1", sth=sth2)

    def test_growth_with_valid_proof(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        old_tree = MerkleTree(leaves[:5])
        new_tree = MerkleTree(leaves[:10])

        sth1 = _make_sth(key, 1, old_tree)
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)

        sth2 = _make_sth(key, 2, new_tree)
        proof = generate_consistency_proof(5, 10, new_tree)
        obs = monitor.record_observation(node_id="n1", shard_id="s1", sth=sth2, proof=proof)
        assert obs.sth == sth2


# ------------------------------------------------------------------ #
# split_view_evidence
# ------------------------------------------------------------------ #


class TestSplitViewEvidence:
    """Tests for LogMonitor.split_view_evidence()."""

    def test_no_evidence_single_node(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(5))
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth)
        assert monitor.split_view_evidence("s1") == ()

    def test_no_evidence_consistent_nodes(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth = _make_sth(key, 1, tree)
        # Same STH from two different nodes
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth)
        monitor.record_observation(node_id="n2", shard_id="s1", sth=sth)
        assert monitor.split_view_evidence("s1") == ()

    def test_evidence_detected(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()

        # Two nodes report same tree_size but different roots
        tree1 = _make_tree(5)
        tree2 = MerkleTree([hash_bytes(f"alt-{i}".encode()) for i in range(5)])

        sth1 = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=tree1.get_root(), signing_key=key
        )
        sth2 = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=tree2.get_root(), signing_key=key
        )

        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth1)
        monitor.record_observation(node_id="n2", shard_id="s1", sth=sth2)

        evidence = monitor.split_view_evidence("s1")
        assert len(evidence) == 1
        assert evidence[0].shard_id == "s1"
        assert evidence[0].tree_size == 5
        assert "n1" in evidence[0].observations
        assert "n2" in evidence[0].observations

    def test_no_evidence_for_other_shard(self) -> None:
        monitor = LogMonitor()
        assert monitor.split_view_evidence("nonexistent") == ()


# ------------------------------------------------------------------ #
# poll_node
# ------------------------------------------------------------------ #


class TestPollNode:
    """Tests for LogMonitor.poll_node()."""

    def test_no_fetcher_raises(self) -> None:
        monitor = LogMonitor()
        with pytest.raises(ValueError, match="sth_fetcher not configured"):
            monitor.poll_node(node_id="n1", shard_id="s1")

    def test_poll_with_fetcher(self) -> None:
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(5))

        def fetcher(node_id: str, shard_id: str) -> SignedTreeHead:
            return sth

        monitor = LogMonitor(sth_fetcher=fetcher)
        obs = monitor.poll_node(node_id="n1", shard_id="s1")
        assert obs.sth == sth

    def test_poll_growth_fetches_consistency_proof(self) -> None:
        key = nacl.signing.SigningKey.generate()
        leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        old_tree = MerkleTree(leaves[:5])
        new_tree = MerkleTree(leaves[:10])

        sth1 = _make_sth(key, 1, old_tree)
        sth2 = _make_sth(key, 2, new_tree)
        proof = generate_consistency_proof(5, 10, new_tree)

        call_count = {"sth": 0}

        def sth_fetcher(node_id: str, shard_id: str) -> SignedTreeHead:
            call_count["sth"] += 1
            if call_count["sth"] == 1:
                return sth1
            return sth2

        def consistency_fetcher(
            node_id: str, shard_id: str, old_size: int, new_size: int
        ) -> ConsistencyProof:
            return proof

        monitor = LogMonitor(sth_fetcher=sth_fetcher, consistency_fetcher=consistency_fetcher)
        # First poll — no prior state
        monitor.poll_node(node_id="n1", shard_id="s1")
        # Second poll — growth, should fetch consistency proof
        obs = monitor.poll_node(node_id="n1", shard_id="s1")
        assert obs.sth == sth2


# ------------------------------------------------------------------ #
# observed()
# ------------------------------------------------------------------ #


class TestObserved:
    """Tests for LogMonitor.observed()."""

    def test_empty(self) -> None:
        monitor = LogMonitor()
        assert list(monitor.observed()) == []

    def test_yields_observations(self) -> None:
        monitor = LogMonitor()
        key = nacl.signing.SigningKey.generate()
        sth = _make_sth(key, 1, _make_tree(3))
        monitor.record_observation(node_id="n1", shard_id="s1", sth=sth)
        monitor.record_observation(node_id="n2", shard_id="s2", sth=sth)
        observations = list(monitor.observed())
        assert len(observations) == 2
        node_ids = {o.node_id for o in observations}
        assert node_ids == {"n1", "n2"}
