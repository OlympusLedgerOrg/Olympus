import nacl.signing
import pytest

from protocol.consistency import generate_consistency_proof
from protocol.epochs import SignedTreeHead
from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree
from protocol.monitoring import LogMonitor, SplitViewEvidence


def _build_sth(
    signing_key: nacl.signing.SigningKey, leaves: list[bytes], epoch: int
) -> SignedTreeHead:
    tree = MerkleTree(leaves)
    return SignedTreeHead.create(
        epoch_id=epoch,
        tree_size=len(leaves),
        merkle_root=tree.get_root(),
        signing_key=signing_key,
    )


def test_log_monitor_verifies_append_only_growth():
    signing_key = nacl.signing.SigningKey.generate()
    monitor = LogMonitor()

    leaves_5 = [hash_bytes(f"leaf-{i}".encode()) for i in range(5)]
    leaves_10 = leaves_5 + [hash_bytes(f"leaf-{i}".encode()) for i in range(5, 10)]

    sth_5 = _build_sth(signing_key, leaves_5, epoch=1)
    sth_10 = _build_sth(signing_key, leaves_10, epoch=2)
    tree = MerkleTree(leaves_10)
    proof = generate_consistency_proof(5, 10, tree)

    monitor.record_observation(node_id="node-a", shard_id="shard-1", sth=sth_5)
    monitor.record_observation(node_id="node-a", shard_id="shard-1", sth=sth_10, proof=proof)

    observations = list(monitor.observed())
    assert len(observations) == 1
    assert observations[0].sth.tree_size == 10


def test_log_monitor_rejects_regression_without_proof():
    signing_key = nacl.signing.SigningKey.generate()
    monitor = LogMonitor()

    leaves_10 = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
    leaves_5 = leaves_10[:5]

    sth_10 = _build_sth(signing_key, leaves_10, epoch=2)
    sth_5 = _build_sth(signing_key, leaves_5, epoch=1)

    monitor.record_observation(node_id="node-a", shard_id="shard-1", sth=sth_10)
    with pytest.raises(ValueError):
        monitor.record_observation(node_id="node-a", shard_id="shard-1", sth=sth_5)


def test_log_monitor_detects_split_view_conflict():
    signing_key = nacl.signing.SigningKey.generate()
    monitor = LogMonitor()

    base_leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(5)]
    fork_leaves = [hash_bytes(f"fork-{i}".encode()) for i in range(5)]

    sth_a = _build_sth(signing_key, base_leaves, epoch=1)
    sth_b = _build_sth(signing_key, fork_leaves, epoch=1)

    monitor.record_observation(node_id="node-a", shard_id="shard-1", sth=sth_a)
    monitor.record_observation(node_id="node-b", shard_id="shard-1", sth=sth_b)

    evidence = monitor.split_view_evidence("shard-1")
    assert len(evidence) == 1
    assert isinstance(evidence[0], SplitViewEvidence)
    assert set(evidence[0].observations.keys()) == {"node-a", "node-b"}
