"""Extended tests for protocol/federation/rotation.py targeting uncovered lines."""

import nacl.signing
import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.federation.identity import FederationNode, FederationRegistry
from protocol.federation.quorum import NodeSignature
from protocol.federation.rotation import (
    EpochKeyRotationRecord,
    RecursiveChainProof,
    verify_epoch_key_rotation,
    verify_recursive_chain_proof,
)
from protocol.hashes import HASH_SEPARATOR, hash_bytes


def _ts():
    return "2025-01-01T00:00:00Z"


# ── RecursiveChainProof validation (lines 71, 73, 75, 79, 81, 83, 86-87) ──


class TestRecursiveChainProof:
    def _valid_kwargs(self):
        return dict(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("aabb", "ccdd", "0", "1"),
            verification_key_hash="vkhash",
            created_at=_ts(),
        )

    def test_invalid_proof_type(self):
        kw = self._valid_kwargs()
        kw["proof_type"] = "invalid"
        with pytest.raises(ValueError, match="proof_type"):
            RecursiveChainProof(**kw)

    def test_empty_previous_root(self):
        kw = self._valid_kwargs()
        kw["previous_root"] = ""
        with pytest.raises(ValueError, match="previous_root"):
            RecursiveChainProof(**kw)

    def test_empty_current_root(self):
        kw = self._valid_kwargs()
        kw["current_root"] = ""
        with pytest.raises(ValueError, match="current_root"):
            RecursiveChainProof(**kw)

    def test_negative_epoch_start(self):
        kw = self._valid_kwargs()
        kw["epoch_start"] = -1
        with pytest.raises(ValueError, match="epoch_start"):
            RecursiveChainProof(**kw)

    def test_epoch_end_before_start(self):
        kw = self._valid_kwargs()
        kw["epoch_end"] = -1
        with pytest.raises(ValueError):
            RecursiveChainProof(**kw)

    def test_negative_transition_count(self):
        kw = self._valid_kwargs()
        kw["transition_count"] = -1
        with pytest.raises(ValueError, match="transition_count"):
            RecursiveChainProof(**kw)

    def test_empty_proof_data(self):
        kw = self._valid_kwargs()
        kw["proof_data"] = ""
        with pytest.raises(ValueError, match="proof_data"):
            RecursiveChainProof(**kw)

    def test_empty_vk_hash(self):
        kw = self._valid_kwargs()
        kw["verification_key_hash"] = ""
        with pytest.raises(ValueError, match="verification_key_hash"):
            RecursiveChainProof(**kw)

    def test_bad_timestamp(self):
        kw = self._valid_kwargs()
        kw["created_at"] = "not-a-date"
        with pytest.raises(ValueError, match="ISO 8601"):
            RecursiveChainProof(**kw)

    def test_to_dict(self):
        proof = RecursiveChainProof(**self._valid_kwargs())
        d = proof.to_dict()
        assert d["proof_type"] == "groth16"

    def test_proof_commitment_hash(self):
        proof = RecursiveChainProof(**self._valid_kwargs())
        h = proof.proof_commitment_hash()
        assert len(h) == 64  # hex-encoded 32 bytes


# ── EpochKeyRotationRecord validation (lines 148, 150, 152, 154, 159-160, 164) ──


class TestEpochKeyRotationRecord:
    def _valid_kwargs(self):
        return dict(
            node_id="node1",
            epoch=1,
            old_pubkey_hash="oldhash",
            new_pubkey_hash="newhash",
            rotated_at=_ts(),
            rotation_signature="sig",
            witness_signatures=(),
        )

    def test_empty_node_id(self):
        kw = self._valid_kwargs()
        kw["node_id"] = ""
        with pytest.raises(ValueError, match="node_id"):
            EpochKeyRotationRecord(**kw)

    def test_negative_epoch(self):
        kw = self._valid_kwargs()
        kw["epoch"] = -1
        with pytest.raises(ValueError, match="epoch"):
            EpochKeyRotationRecord(**kw)

    def test_empty_old_pubkey(self):
        kw = self._valid_kwargs()
        kw["old_pubkey_hash"] = ""
        with pytest.raises(ValueError, match="old_pubkey_hash"):
            EpochKeyRotationRecord(**kw)

    def test_empty_new_pubkey(self):
        kw = self._valid_kwargs()
        kw["new_pubkey_hash"] = ""
        with pytest.raises(ValueError, match="new_pubkey_hash"):
            EpochKeyRotationRecord(**kw)

    def test_same_pubkey(self):
        kw = self._valid_kwargs()
        kw["new_pubkey_hash"] = kw["old_pubkey_hash"]
        with pytest.raises(ValueError, match="differ"):
            EpochKeyRotationRecord(**kw)

    def test_bad_timestamp(self):
        kw = self._valid_kwargs()
        kw["rotated_at"] = "bad"
        with pytest.raises(ValueError, match="ISO 8601"):
            EpochKeyRotationRecord(**kw)

    def test_to_dict(self):
        record = EpochKeyRotationRecord(**self._valid_kwargs())
        d = record.to_dict()
        assert d["node_id"] == "node1"


# ── verify_recursive_chain_proof (lines 198-202, 212) ──


class TestVerifyRecursiveChainProof:
    def test_vk_hash_mismatch(self):
        """VK hash computed from vk doesn't match expected."""
        vk = {"key": "value"}
        actual_hash = hash_bytes(canonical_json_bytes(vk)).hex()
        proof = RecursiveChainProof(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("aabb", "ccdd", "0", "1"),
            verification_key_hash=actual_hash,
            created_at=_ts(),
        )
        assert verify_recursive_chain_proof(proof, vk, "wrong_hash") is False

    def test_proof_vk_hash_mismatch(self):
        """Proof's vk_hash doesn't match expected."""
        vk = {"key": "value"}
        actual_hash = hash_bytes(canonical_json_bytes(vk)).hex()
        proof = RecursiveChainProof(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("aabb", "ccdd", "0", "1"),
            verification_key_hash="mismatched",
            created_at=_ts(),
        )
        assert verify_recursive_chain_proof(proof, vk, actual_hash) is False

    def test_wrong_public_inputs(self):
        vk = {"key": "value"}
        actual_hash = hash_bytes(canonical_json_bytes(vk)).hex()
        proof = RecursiveChainProof(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("wrong", "inputs", "0", "1"),
            verification_key_hash=actual_hash,
            created_at=_ts(),
        )
        assert verify_recursive_chain_proof(proof, vk, actual_hash) is False

    def test_valid_proof(self):
        vk = {"key": "value"}
        actual_hash = hash_bytes(canonical_json_bytes(vk)).hex()
        proof = RecursiveChainProof(
            proof_type="groth16",
            previous_root="aabb",
            current_root="ccdd",
            epoch_start=0,
            epoch_end=1,
            transition_count=1,
            proof_data="deadbeef",
            public_inputs=("aabb", "ccdd", "0", "1"),
            verification_key_hash=actual_hash,
            created_at=_ts(),
        )
        assert verify_recursive_chain_proof(proof, vk, actual_hash) is True


# ── verify_epoch_key_rotation (lines 259-260, 264, 270-271, 273, 278-279) ──


class TestVerifyEpochKeyRotation:
    def _make_registry_and_keys(self, witness_count=1):
        """Create a registry with a node and witness nodes."""
        old_sk = nacl.signing.SigningKey.generate()
        node_id = "node-main"
        witnesses = []
        nodes = [
            FederationNode(
                node_id=node_id,
                pubkey=old_sk.verify_key.encode(),
                endpoint="https://main.example.com",
                operator="op-main",
                jurisdiction="US",
            )
        ]
        for i in range(witness_count):
            wsk = nacl.signing.SigningKey.generate()
            wnode = FederationNode(
                node_id=f"witness-{i}",
                pubkey=wsk.verify_key.encode(),
                endpoint=f"https://w{i}.example.com",
                operator=f"op-w{i}",
                jurisdiction="US",
            )
            nodes.append(wnode)
            witnesses.append((wsk, wnode))

        registry = FederationRegistry(nodes=tuple(nodes), epoch=1)
        return old_sk, registry, witnesses

    def _sign_rotation(self, old_sk, record):
        payload = HASH_SEPARATOR.join(
            [
                record.node_id,
                str(record.epoch),
                record.old_pubkey_hash,
                record.new_pubkey_hash,
                record.rotated_at,
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(payload)
        return old_sk.sign(rotation_hash).signature.hex()

    def test_bad_rotation_signature(self):
        old_sk, registry, witnesses = self._make_registry_and_keys(1)
        record = EpochKeyRotationRecord(
            node_id="node-main",
            epoch=1,
            old_pubkey_hash="old",
            new_pubkey_hash="new",
            rotated_at=_ts(),
            rotation_signature="00" * 64,  # invalid sig
            witness_signatures=(),
        )
        assert verify_epoch_key_rotation(record, old_sk.verify_key, registry) is False

    def test_insufficient_witnesses(self):
        old_sk, registry, witnesses = self._make_registry_and_keys(1)
        sig = self._sign_rotation(
            old_sk,
            EpochKeyRotationRecord(
                node_id="node-main",
                epoch=1,
                old_pubkey_hash="old",
                new_pubkey_hash="new",
                rotated_at=_ts(),
                rotation_signature="placeholder",
                witness_signatures=(),
            ),
        )
        record = EpochKeyRotationRecord(
            node_id="node-main",
            epoch=1,
            old_pubkey_hash="old",
            new_pubkey_hash="new",
            rotated_at=_ts(),
            rotation_signature=sig,
            witness_signatures=(),
        )
        assert (
            verify_epoch_key_rotation(record, old_sk.verify_key, registry, min_witnesses=1) is False
        )

    def test_valid_rotation_with_witness(self):
        old_sk, registry, witnesses = self._make_registry_and_keys(1)
        wsk, wnode = witnesses[0]
        # Build rotation payload hash for witness signing
        record_kwargs = dict(
            node_id="node-main",
            epoch=1,
            old_pubkey_hash="old",
            new_pubkey_hash="new",
            rotated_at=_ts(),
        )
        payload = HASH_SEPARATOR.join(
            [
                record_kwargs["node_id"],
                str(record_kwargs["epoch"]),
                record_kwargs["old_pubkey_hash"],
                record_kwargs["new_pubkey_hash"],
                record_kwargs["rotated_at"],
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(payload)
        rotation_sig = old_sk.sign(rotation_hash).signature.hex()
        witness_sig = wsk.sign(rotation_hash).signature.hex()

        record = EpochKeyRotationRecord(
            **record_kwargs,
            rotation_signature=rotation_sig,
            witness_signatures=(NodeSignature(node_id=wnode.node_id, signature=witness_sig),),
        )
        assert (
            verify_epoch_key_rotation(record, old_sk.verify_key, registry, min_witnesses=1) is True
        )

    def test_inactive_witness_ignored(self):
        old_sk, registry, witnesses = self._make_registry_and_keys(1)
        wsk, wnode = witnesses[0]
        # Deactivate the witness
        deactivated = FederationNode(
            node_id=wnode.node_id,
            pubkey=wnode.pubkey,
            endpoint=wnode.endpoint,
            operator=wnode.operator,
            jurisdiction=wnode.jurisdiction,
            status="inactive",
        )
        nodes_list = list(registry.nodes)
        for i, n in enumerate(nodes_list):
            if n.node_id == wnode.node_id:
                nodes_list[i] = deactivated
        registry2 = FederationRegistry(nodes=tuple(nodes_list), epoch=1)

        payload = HASH_SEPARATOR.join(
            [
                "node-main",
                "1",
                "old",
                "new",
                _ts(),
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(payload)
        rotation_sig = old_sk.sign(rotation_hash).signature.hex()
        witness_sig = wsk.sign(rotation_hash).signature.hex()

        record = EpochKeyRotationRecord(
            node_id="node-main",
            epoch=1,
            old_pubkey_hash="old",
            new_pubkey_hash="new",
            rotated_at=_ts(),
            rotation_signature=rotation_sig,
            witness_signatures=(NodeSignature(node_id=wnode.node_id, signature=witness_sig),),
        )
        # Inactive witness should not count
        assert (
            verify_epoch_key_rotation(record, old_sk.verify_key, registry2, min_witnesses=1)
            is False
        )

    def test_unknown_witness_ignored(self):
        old_sk, registry, witnesses = self._make_registry_and_keys(0)
        payload = HASH_SEPARATOR.join(
            [
                "node-main",
                "1",
                "old",
                "new",
                _ts(),
            ]
        ).encode("utf-8")
        rotation_hash = hash_bytes(payload)
        rotation_sig = old_sk.sign(rotation_hash).signature.hex()

        record = EpochKeyRotationRecord(
            node_id="node-main",
            epoch=1,
            old_pubkey_hash="old",
            new_pubkey_hash="new",
            rotated_at=_ts(),
            rotation_signature=rotation_sig,
            witness_signatures=(NodeSignature(node_id="unknown-node", signature="aa" * 64),),
        )
        assert (
            verify_epoch_key_rotation(record, old_sk.verify_key, registry, min_witnesses=1) is False
        )
