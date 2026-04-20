"""Extended tests for protocol/federation/replication.py targeting uncovered lines."""

import nacl.signing
import pytest

from protocol.federation.identity import FederationNode, FederationRegistry
from protocol.federation.quorum import NodeSignature
from protocol.federation.replication import (
    DataAvailabilityChallenge,
    FederationFinalityStatus,
    GossipedShardHeader,
    ReplicationProof,
    ShardHeaderForkEvidence,
    create_replication_proof,
    detect_shard_header_forks,
    registry_forest_commitment,
    verify_data_availability,
)


def _ts():
    return "2025-01-01T00:00:00Z"


def _ts2():
    return "2025-06-01T00:00:00Z"


# ── ShardHeaderForkEvidence validation (lines 54, 58, 60, 63-64, 68) ──


class TestShardHeaderForkEvidence:
    def _valid_kwargs(self):
        return dict(
            shard_id="s1",
            seq=0,
            conflicting_header_hashes=("h1", "h2"),
            observer_ids=("o1",),
            signatures_a=(),
            signatures_b=(),
            detected_at=_ts(),
        )

    def test_empty_shard_id(self):
        kw = self._valid_kwargs()
        kw["shard_id"] = ""
        with pytest.raises(ValueError, match="shard_id"):
            ShardHeaderForkEvidence(**kw)

    def test_negative_seq(self):
        kw = self._valid_kwargs()
        kw["seq"] = -1
        with pytest.raises(ValueError, match="seq"):
            ShardHeaderForkEvidence(**kw)

    def test_single_hash(self):
        kw = self._valid_kwargs()
        kw["conflicting_header_hashes"] = ("h1",)
        with pytest.raises(ValueError, match="at least two"):
            ShardHeaderForkEvidence(**kw)

    def test_duplicate_hashes(self):
        kw = self._valid_kwargs()
        kw["conflicting_header_hashes"] = ("h1", "h1")
        with pytest.raises(ValueError, match="unique"):
            ShardHeaderForkEvidence(**kw)

    def test_no_observers(self):
        kw = self._valid_kwargs()
        kw["observer_ids"] = ()
        with pytest.raises(ValueError, match="observer"):
            ShardHeaderForkEvidence(**kw)

    def test_bad_timestamp(self):
        kw = self._valid_kwargs()
        kw["detected_at"] = "bad"
        with pytest.raises(ValueError, match="ISO 8601"):
            ShardHeaderForkEvidence(**kw)

    def test_to_dict(self):
        e = ShardHeaderForkEvidence(**self._valid_kwargs())
        d = e.to_dict()
        assert d["shard_id"] == "s1"

    def test_colluding_guardians(self):
        sig_a = NodeSignature(node_id="g1", signature="aa")
        sig_b = NodeSignature(node_id="g1", signature="bb")
        e = ShardHeaderForkEvidence(
            shard_id="s1",
            seq=0,
            conflicting_header_hashes=("h1", "h2"),
            observer_ids=("o1",),
            signatures_a=(sig_a,),
            signatures_b=(sig_b,),
            detected_at=_ts(),
        )
        assert e.colluding_guardians() == ("g1",)


# ── GossipedShardHeader (lines 99, 101, 103, 105) ──


class TestGossipedShardHeader:
    def test_empty_peer_id(self):
        with pytest.raises(ValueError, match="peer_id"):
            GossipedShardHeader(
                peer_id="",
                shard_id="s1",
                seq=0,
                header_hash="h",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            )

    def test_empty_shard_id(self):
        with pytest.raises(ValueError, match="shard_id"):
            GossipedShardHeader(
                peer_id="p1",
                shard_id="",
                seq=0,
                header_hash="h",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            )

    def test_negative_seq(self):
        with pytest.raises(ValueError, match="seq"):
            GossipedShardHeader(
                peer_id="p1",
                shard_id="s1",
                seq=-1,
                header_hash="h",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            )

    def test_empty_header_hash(self):
        with pytest.raises(ValueError, match="header_hash"):
            GossipedShardHeader(
                peer_id="p1",
                shard_id="s1",
                seq=0,
                header_hash="",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            )


# ── detect_shard_header_forks (lines 132, 250, 252, 254, 258-259, 263) ──


class TestDetectShardHeaderForks:
    def test_empty_observations(self):
        assert detect_shard_header_forks({}) == ()

    def test_no_conflict(self):
        obs = {
            "p1": GossipedShardHeader(
                peer_id="p1",
                shard_id="s1",
                seq=0,
                header_hash="h1",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            ),
            "p2": GossipedShardHeader(
                peer_id="p2",
                shard_id="s1",
                seq=0,
                header_hash="h1",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            ),
        }
        assert detect_shard_header_forks(obs) == ()

    def test_fork_detected(self):
        obs = {
            "p1": GossipedShardHeader(
                peer_id="p1",
                shard_id="s1",
                seq=0,
                header_hash="h1",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            ),
            "p2": GossipedShardHeader(
                peer_id="p2",
                shard_id="s1",
                seq=0,
                header_hash="h2",
                root_hash="r",
                timestamp=_ts(),
                signatures=(),
            ),
        }
        result = detect_shard_header_forks(obs)
        assert len(result) == 1
        assert "h1" in result[0].conflicting_header_hashes
        assert "h2" in result[0].conflicting_header_hashes


# ── registry_forest_commitment (lines 195-213) ──


class TestRegistryForestCommitment:
    def test_basic_commitment(self):
        sk = nacl.signing.SigningKey.generate()
        node = FederationNode(
            node_id="n1",
            pubkey=sk.verify_key.encode(),
            endpoint="https://n1.example.com",
            operator="op1",
            jurisdiction="US",
        )
        registry = FederationRegistry(nodes=(node,), epoch=1)
        result = registry_forest_commitment(registry)
        assert len(result) == 64  # hex encoded 32 bytes

    def test_pipe_in_node_id_does_not_collide_with_field_separator(self):
        """Length-prefixed encoding prevents pipe injection in node fields.

        With naive HASH_SEPARATOR.join(), node_id="a|b" + endpoint="c" would
        produce the same joined string as node_id="a" + endpoint="|b|c" (if
        surrounding separators allowed that boundary shift). Length-prefix
        encoding commits field boundaries, so these registries must produce
        different commitments.
        """
        sk = nacl.signing.SigningKey.generate()

        node_pipe = FederationNode(
            node_id="a|b",
            pubkey=sk.verify_key.encode(),
            endpoint="c",
            operator="op",
            jurisdiction="US",
        )
        node_plain = FederationNode(
            node_id="a",
            pubkey=sk.verify_key.encode(),
            endpoint="|b|c",
            operator="op",
            jurisdiction="US",
        )

        registry_pipe = FederationRegistry(nodes=(node_pipe,), epoch=1)
        registry_plain = FederationRegistry(nodes=(node_plain,), epoch=1)

        commitment_pipe = registry_forest_commitment(registry_pipe)
        commitment_plain = registry_forest_commitment(registry_plain)

        assert commitment_pipe != commitment_plain


# ── DataAvailabilityChallenge (lines 248-259) ──


class TestDataAvailabilityChallenge:
    def _valid_kwargs(self):
        return dict(
            shard_id="s1",
            header_hash="hh",
            challenger_id="c1",
            challenge_nonce="nonce1",
            issued_at=_ts(),
            response_deadline=_ts2(),
        )

    def test_empty_shard_id(self):
        kw = self._valid_kwargs()
        kw["shard_id"] = ""
        with pytest.raises(ValueError, match="shard_id"):
            DataAvailabilityChallenge(**kw)

    def test_empty_header_hash(self):
        kw = self._valid_kwargs()
        kw["header_hash"] = ""
        with pytest.raises(ValueError, match="header_hash"):
            DataAvailabilityChallenge(**kw)

    def test_empty_challenger_id(self):
        kw = self._valid_kwargs()
        kw["challenger_id"] = ""
        with pytest.raises(ValueError, match="challenger_id"):
            DataAvailabilityChallenge(**kw)

    def test_empty_nonce(self):
        kw = self._valid_kwargs()
        kw["challenge_nonce"] = ""
        with pytest.raises(ValueError, match="challenge_nonce"):
            DataAvailabilityChallenge(**kw)

    def test_bad_timestamp(self):
        kw = self._valid_kwargs()
        kw["issued_at"] = "bad"
        with pytest.raises(ValueError, match="ISO 8601"):
            DataAvailabilityChallenge(**kw)

    def test_to_dict(self):
        c = DataAvailabilityChallenge(**self._valid_kwargs())
        assert c.to_dict()["shard_id"] == "s1"

    def test_challenge_hash_deterministic(self):
        c = DataAvailabilityChallenge(**self._valid_kwargs())
        assert c.challenge_hash() == c.challenge_hash()


# ── ReplicationProof (lines 317, 319, 321, 323, 326-327) ──


class TestReplicationProof:
    def _valid_kwargs(self):
        return dict(
            challenge_hash="ch",
            guardian_id="g1",
            ledger_tail_hash="lth",
            merkle_root_verified=True,
            proof_sample_indices=(0, 1),
            proof_sample_hashes=("h0", "h1"),
            replicated_at=_ts(),
            guardian_signature="sig",
        )

    def test_empty_challenge_hash(self):
        kw = self._valid_kwargs()
        kw["challenge_hash"] = ""
        with pytest.raises(ValueError, match="challenge_hash"):
            ReplicationProof(**kw)

    def test_empty_guardian_id(self):
        kw = self._valid_kwargs()
        kw["guardian_id"] = ""
        with pytest.raises(ValueError, match="guardian_id"):
            ReplicationProof(**kw)

    def test_empty_ledger_tail_hash(self):
        kw = self._valid_kwargs()
        kw["ledger_tail_hash"] = ""
        with pytest.raises(ValueError, match="ledger_tail_hash"):
            ReplicationProof(**kw)

    def test_mismatched_sample_lengths(self):
        kw = self._valid_kwargs()
        kw["proof_sample_hashes"] = ("h0",)
        with pytest.raises(ValueError, match="same length"):
            ReplicationProof(**kw)

    def test_bad_timestamp(self):
        kw = self._valid_kwargs()
        kw["replicated_at"] = "bad"
        with pytest.raises(ValueError, match="ISO 8601"):
            ReplicationProof(**kw)


# ── FederationFinalityStatus (lines 404, 406, 410-411, 425) ──


class TestFederationFinalityStatus:
    def _valid_kwargs(self):
        return dict(
            shard_id="s1",
            seq=0,
            header_hash="hh",
            status="PROPOSED",
            availability_proofs=(),
            quorum_signatures=(),
            finalized_at=None,
        )

    def test_invalid_status(self):
        kw = self._valid_kwargs()
        kw["status"] = "INVALID"
        with pytest.raises(ValueError, match="status"):
            FederationFinalityStatus(**kw)

    def test_negative_seq(self):
        kw = self._valid_kwargs()
        kw["seq"] = -1
        with pytest.raises(ValueError, match="seq"):
            FederationFinalityStatus(**kw)

    def test_bad_finalized_at(self):
        kw = self._valid_kwargs()
        kw["finalized_at"] = "bad"
        with pytest.raises(ValueError, match="ISO 8601"):
            FederationFinalityStatus(**kw)

    def test_is_final_true(self):
        kw = self._valid_kwargs()
        kw["status"] = "FEDERATION_FINAL"
        kw["finalized_at"] = _ts()
        s = FederationFinalityStatus(**kw)
        assert s.is_final() is True

    def test_is_final_false(self):
        s = FederationFinalityStatus(**self._valid_kwargs())
        assert s.is_final() is False

    def test_availability_threshold(self):
        nodes = tuple(
            FederationNode(
                node_id=f"n{i}",
                pubkey=nacl.signing.SigningKey.generate().verify_key.encode(),
                endpoint=f"https://n{i}.example.com",
                operator=f"op{i}",
                jurisdiction="US",
            )
            for i in range(1, 4)
        )
        registry = FederationRegistry(nodes=nodes, epoch=1)
        s = FederationFinalityStatus(**self._valid_kwargs())
        # No proofs → threshold not met
        assert s.availability_threshold_met(registry) is False

    def test_to_dict(self):
        s = FederationFinalityStatus(**self._valid_kwargs())
        d = s.to_dict()
        assert d["shard_id"] == "s1"


# ── verify_data_availability (lines 465-466, 468, 472, 480-481) ──


class TestVerifyDataAvailability:
    def _make_setup(self):
        sk = nacl.signing.SigningKey.generate()
        node = FederationNode(
            node_id="guardian1",
            pubkey=sk.verify_key.encode(),
            endpoint="https://g1.example.com",
            operator="op1",
            jurisdiction="US",
        )
        registry = FederationRegistry(nodes=(node,), epoch=1)
        challenge = DataAvailabilityChallenge(
            shard_id="s1",
            header_hash="hh",
            challenger_id="c1",
            challenge_nonce="nonce",
            issued_at=_ts(),
            response_deadline=_ts2(),
        )
        return sk, node, registry, challenge

    def test_wrong_challenge_hash(self):
        sk, node, registry, challenge = self._make_setup()
        proof = ReplicationProof(
            challenge_hash="wrong",
            guardian_id="guardian1",
            ledger_tail_hash="lth",
            merkle_root_verified=True,
            proof_sample_indices=(),
            proof_sample_hashes=(),
            replicated_at=_ts(),
            guardian_signature="sig",
        )
        assert verify_data_availability(challenge, proof, registry) is False

    def test_unregistered_guardian(self):
        sk, node, registry, challenge = self._make_setup()
        proof = create_replication_proof(
            challenge,
            "unknown-guardian",
            sk,
            "lth",
            (),
            (),
            _ts(),
        )
        assert verify_data_availability(challenge, proof, registry) is False

    def test_inactive_guardian(self):
        sk, node, registry, challenge = self._make_setup()
        inactive_node = FederationNode(
            node_id="guardian1",
            pubkey=sk.verify_key.encode(),
            endpoint="https://g1.example.com",
            operator="op1",
            jurisdiction="US",
            status="inactive",
        )
        registry2 = FederationRegistry(nodes=(inactive_node,), epoch=1)
        proof = create_replication_proof(
            challenge,
            "guardian1",
            sk,
            "lth",
            (),
            (),
            _ts(),
        )
        assert verify_data_availability(challenge, proof, registry2) is False

    def test_bad_signature(self):
        sk, node, registry, challenge = self._make_setup()
        proof = ReplicationProof(
            challenge_hash=challenge.challenge_hash(),
            guardian_id="guardian1",
            ledger_tail_hash="lth",
            merkle_root_verified=True,
            proof_sample_indices=(),
            proof_sample_hashes=(),
            replicated_at=_ts(),
            guardian_signature="00" * 64,  # invalid signature
        )
        assert verify_data_availability(challenge, proof, registry) is False

    def test_merkle_not_verified(self):
        sk, node, registry, challenge = self._make_setup()
        # Create proper proof but with merkle_root_verified=False
        unsigned = ReplicationProof(
            challenge_hash=challenge.challenge_hash(),
            guardian_id="guardian1",
            ledger_tail_hash="lth",
            merkle_root_verified=False,
            proof_sample_indices=(),
            proof_sample_hashes=(),
            replicated_at=_ts(),
            guardian_signature="placeholder",
        )
        payload_hash = bytes.fromhex(unsigned.proof_payload_hash())
        sig = sk.sign(payload_hash).signature.hex()
        proof = ReplicationProof(
            challenge_hash=challenge.challenge_hash(),
            guardian_id="guardian1",
            ledger_tail_hash="lth",
            merkle_root_verified=False,
            proof_sample_indices=(),
            proof_sample_hashes=(),
            replicated_at=_ts(),
            guardian_signature=sig,
        )
        assert verify_data_availability(challenge, proof, registry) is False

    def test_valid_proof(self):
        sk, node, registry, challenge = self._make_setup()
        proof = create_replication_proof(
            challenge,
            "guardian1",
            sk,
            "lth",
            (0,),
            ("sample_hash",),
            _ts(),
        )
        assert verify_data_availability(challenge, proof, registry) is True
