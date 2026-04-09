"""Multi-node federation integration tests.

These tests simulate a three-node federation (matching the static
``examples/federation_registry.json`` fixture) and exercise the full
lifecycle: quorum signing, gossip-based fork detection, data-availability
challenges, and key rotation — verifying that the federation primitives
compose correctly across multiple independent nodes.

No real network I/O is involved; the tests exercise the protocol layer
in-process with deterministic keys.
"""

from __future__ import annotations

from pathlib import Path

import nacl.signing
import pytest

from protocol.federation import (
    DataAvailabilityChallenge,
    EpochKeyRotationRecord,
    FederationRegistry,
    GossipedShardHeader,
    NodeSignature,
    build_quorum_certificate,
    create_replication_proof,
    detect_shard_header_forks,
    has_federation_quorum,
    sign_federated_header,
    verify_data_availability,
    verify_epoch_key_rotation,
    verify_federated_header_signatures,
    verify_quorum_certificate,
)
from protocol.hashes import HASH_SEPARATOR, hash_bytes
from protocol.shards import (
    create_shard_header,
    get_signing_key_from_seed,
)
from protocol.timestamps import current_timestamp


REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "examples" / "federation_registry.json"


# ---------------------------------------------------------------------------
# Deterministic test keys — one per simulated node.
# ---------------------------------------------------------------------------


def _node_key(seed: int) -> nacl.signing.SigningKey:
    return get_signing_key_from_seed(bytes([seed]) * 32)


NODE_KEYS = {
    "olympus-node-1": _node_key(1),
    "olympus-node-2": _node_key(2),
    "olympus-node-3": _node_key(3),
}


# ---------------------------------------------------------------------------
# Multi-node quorum lifecycle
# ---------------------------------------------------------------------------


class TestMultiNodeQuorumLifecycle:
    """Simulate quorum certificate creation across three independent nodes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.registry = FederationRegistry.from_file(REGISTRY_PATH)
        self.header = create_shard_header(
            shard_id="records.city-a",
            root_hash=bytes.fromhex("aa" * 32),
            timestamp="2026-03-10T12:00:00Z",
        )

    def test_two_of_three_nodes_reach_quorum(self) -> None:
        sigs = [
            sign_federated_header(self.header, nid, NODE_KEYS[nid], self.registry)
            for nid in ["olympus-node-1", "olympus-node-2"]
        ]
        assert has_federation_quorum(self.header, sigs, self.registry)

    def test_single_node_does_not_reach_quorum(self) -> None:
        sigs = [
            sign_federated_header(
                self.header, "olympus-node-1", NODE_KEYS["olympus-node-1"], self.registry
            )
        ]
        assert not has_federation_quorum(self.header, sigs, self.registry)

    def test_all_three_nodes_sign_and_build_certificate(self) -> None:
        sigs = [
            sign_federated_header(self.header, nid, NODE_KEYS[nid], self.registry)
            for nid in NODE_KEYS
        ]
        assert has_federation_quorum(self.header, sigs, self.registry)

        cert = build_quorum_certificate(self.header, sigs, self.registry)
        assert verify_quorum_certificate(cert, self.header, self.registry)

    def test_certificate_with_two_of_three_verifies(self) -> None:
        sigs = [
            sign_federated_header(self.header, nid, NODE_KEYS[nid], self.registry)
            for nid in ["olympus-node-1", "olympus-node-3"]
        ]
        cert = build_quorum_certificate(self.header, sigs, self.registry)
        assert verify_quorum_certificate(cert, self.header, self.registry)

    def test_federated_header_signature_verification(self) -> None:
        sigs = [
            sign_federated_header(self.header, nid, NODE_KEYS[nid], self.registry)
            for nid in NODE_KEYS
        ]
        valid = verify_federated_header_signatures(self.header, sigs, self.registry)
        assert len(valid) == 3


# ---------------------------------------------------------------------------
# Multi-node gossip & fork detection
# ---------------------------------------------------------------------------


class TestMultiNodeForkDetection:
    """Simulate nodes gossiping shard headers and detecting forks."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.registry = FederationRegistry.from_file(REGISTRY_PATH)

    def test_consistent_gossip_produces_no_forks(self) -> None:
        """All three nodes gossip the same header — no fork detected."""
        header_hash = "bb" * 32
        obs = {
            nid: GossipedShardHeader(
                peer_id=nid,
                shard_id="records.city-a",
                seq=0,
                header_hash=header_hash,
                root_hash="cc" * 32,
                timestamp="2026-03-10T12:00:00Z",
                signatures=(),
            )
            for nid in NODE_KEYS
        }
        forks = detect_shard_header_forks(obs, registry=self.registry)
        assert len(forks) == 0

    def test_divergent_gossip_detects_fork(self) -> None:
        """Node-3 reports a different header hash → fork evidence emitted."""
        obs = {
            "olympus-node-1": GossipedShardHeader(
                peer_id="olympus-node-1",
                shard_id="records.city-a",
                seq=0,
                header_hash="aa" * 32,
                root_hash="cc" * 32,
                timestamp="2026-03-10T12:00:00Z",
                signatures=(),
            ),
            "olympus-node-2": GossipedShardHeader(
                peer_id="olympus-node-2",
                shard_id="records.city-a",
                seq=0,
                header_hash="aa" * 32,
                root_hash="cc" * 32,
                timestamp="2026-03-10T12:00:00Z",
                signatures=(),
            ),
            "olympus-node-3": GossipedShardHeader(
                peer_id="olympus-node-3",
                shard_id="records.city-a",
                seq=0,
                header_hash="ff" * 32,
                root_hash="dd" * 32,
                timestamp="2026-03-10T12:00:05Z",
                signatures=(),
            ),
        }
        forks = detect_shard_header_forks(obs, registry=self.registry)
        assert len(forks) >= 1
        evidence = forks[0]
        assert evidence.shard_id == "records.city-a"
        assert len(evidence.conflicting_header_hashes) >= 2


# ---------------------------------------------------------------------------
# Multi-node data-availability challenge / response
# ---------------------------------------------------------------------------


class TestMultiNodeDataAvailability:
    """Simulate data-availability challenges answered by multiple Guardians."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.registry = FederationRegistry.from_file(REGISTRY_PATH)

    def _make_challenge(self) -> DataAvailabilityChallenge:
        return DataAvailabilityChallenge(
            shard_id="records.city-a",
            header_hash="dd" * 32,
            challenger_id="olympus-node-1",
            challenge_nonce="deadbeef" * 8,
            issued_at="2026-03-10T13:00:00Z",
            response_deadline="2026-03-10T14:00:00Z",
        )

    def test_two_guardians_independently_answer_challenge(self) -> None:
        """Two different Guardian nodes each produce a valid replication proof."""
        challenge = self._make_challenge()

        for guardian_id in ["olympus-node-2", "olympus-node-3"]:
            proof = create_replication_proof(
                challenge=challenge,
                guardian_id=guardian_id,
                signing_key=NODE_KEYS[guardian_id],
                ledger_tail_hash="ee" * 32,
                proof_sample_indices=(0, 5, 10),
                proof_sample_hashes=("f0" * 32, "f1" * 32, "f2" * 32),
                replicated_at="2026-03-10T13:01:00Z",
            )
            assert verify_data_availability(challenge, proof, self.registry)


# ---------------------------------------------------------------------------
# Multi-node key rotation witness
# ---------------------------------------------------------------------------


class TestMultiNodeKeyRotation:
    """Simulate key rotation witnessed by multiple federation nodes."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.registry = FederationRegistry.from_file(REGISTRY_PATH)

    def test_key_rotation_with_two_witnesses(self) -> None:
        old_key = NODE_KEYS["olympus-node-1"]
        new_key = nacl.signing.SigningKey.generate()

        old_pubkey_hash = hash_bytes(bytes(old_key.verify_key)).hex()
        new_pubkey_hash = hash_bytes(bytes(new_key.verify_key)).hex()
        ts = current_timestamp()

        # Build rotation payload matching verify_epoch_key_rotation
        rotation_payload = HASH_SEPARATOR.join(
            [
                "olympus-node-1",
                "1",
                old_pubkey_hash,
                new_pubkey_hash,
                ts,
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(rotation_payload)

        # Sign rotation with old key
        rotation_sig = old_key.sign(rotation_hash).signature.hex()

        # Witnesses sign the rotation hash
        witness_sigs = tuple(
            NodeSignature(
                node_id=nid,
                signature=NODE_KEYS[nid].sign(rotation_hash).signature.hex(),
            )
            for nid in ["olympus-node-2", "olympus-node-3"]
        )

        record = EpochKeyRotationRecord(
            node_id="olympus-node-1",
            epoch=1,
            old_pubkey_hash=old_pubkey_hash,
            new_pubkey_hash=new_pubkey_hash,
            rotated_at=ts,
            rotation_signature=rotation_sig,
            witness_signatures=witness_sigs,
        )

        assert verify_epoch_key_rotation(
            record,
            old_key.verify_key,
            self.registry,
            min_witnesses=2,
        )

    def test_key_rotation_insufficient_witnesses_fails(self) -> None:
        old_key = NODE_KEYS["olympus-node-1"]
        new_key = nacl.signing.SigningKey.generate()

        old_pubkey_hash = hash_bytes(bytes(old_key.verify_key)).hex()
        new_pubkey_hash = hash_bytes(bytes(new_key.verify_key)).hex()
        ts = current_timestamp()

        rotation_payload = HASH_SEPARATOR.join(
            [
                "olympus-node-1",
                "1",
                old_pubkey_hash,
                new_pubkey_hash,
                ts,
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(rotation_payload)

        rotation_sig = old_key.sign(rotation_hash).signature.hex()

        # Only one witness — but we require two
        witness_sigs = (
            NodeSignature(
                node_id="olympus-node-2",
                signature=NODE_KEYS["olympus-node-2"].sign(rotation_hash).signature.hex(),
            ),
        )

        record = EpochKeyRotationRecord(
            node_id="olympus-node-1",
            epoch=1,
            old_pubkey_hash=old_pubkey_hash,
            new_pubkey_hash=new_pubkey_hash,
            rotated_at=ts,
            rotation_signature=rotation_sig,
            witness_signatures=witness_sigs,
        )

        assert not verify_epoch_key_rotation(
            record,
            old_key.verify_key,
            self.registry,
            min_witnesses=2,
        )
