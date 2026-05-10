from __future__ import annotations

from typing import List

from fastapi.testclient import TestClient
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from api.app import app
from api.transparency import monitor
from api.transparency.gossip import SignedRootEnvelope
from api.transparency.witness import WitnessCosignature
from protocol.hashes import hash_string
from protocol.ssmf import ExistenceProof, NonExistenceProof, SparseMerkleTree


class _Backend:
    def __init__(self) -> None:
        self.tree = SparseMerkleTree()
        self.key = bytes.fromhex("11" * 32)
        self.absent_key = bytes.fromhex("22" * 32)
        self.value = hash_string("monitor-api-test")
        self.tree.update(self.key, self.value, parser_id="docling@2.3.1", canonical_parser_version="v1")
        self.root_hex = self.tree.get_root().hex()

        payload = b"OLY:WITNESS:V1|" + bytes.fromhex(self.root_hex)
        w1 = SigningKey(bytes([1]) * 32)
        w2 = SigningKey(bytes([2]) * 32)
        self._envelope = SignedRootEnvelope(
            height=9,
            root_hash=self.root_hex,
            sequencer_signature="ff" * 64,
            sequencer_key_id="sequencer-main",
            witness_cosignatures=[
                WitnessCosignature(
                    witness_id="w1",
                    signature_hex=w1.sign(payload).signature.hex(),
                    public_key_hex=w1.verify_key.encode(encoder=HexEncoder).decode(),
                ),
                WitnessCosignature(
                    witness_id="w2",
                    signature_hex=w2.sign(payload).signature.hex(),
                    public_key_hex=w2.verify_key.encode(encoder=HexEncoder).decode(),
                ),
            ],
            timestamp="2026-05-10T21:40:09Z",
        )

    def latest_signed_root(self) -> SignedRootEnvelope:
        return self._envelope

    def signed_root_by_height(self, height: int) -> SignedRootEnvelope | None:
        return self._envelope if height == self._envelope.height else None

    def witness_keys(self) -> list[monitor.WitnessKeyInfo]:
        return [
            monitor.WitnessKeyInfo(witness_id="w1", public_key_hex=self._envelope.witness_cosignatures[0].public_key_hex),
            monitor.WitnessKeyInfo(witness_id="w2", public_key_hex=self._envelope.witness_cosignatures[1].public_key_hex),
        ]

    def inclusion_proof(self, key: bytes) -> ExistenceProof:
        return self.tree.prove_existence(key)

    def non_inclusion_proof(self, key: bytes) -> NonExistenceProof:
        return self.tree.prove_nonexistence(key)


def test_monitor_endpoints_shapes_and_proofs() -> None:
    previous = monitor._backend
    backend = _Backend()
    monitor.set_transparency_backend(backend)
    client = TestClient(app)
    try:
        latest = client.get("/transparency/v1/signed-root")
        assert latest.status_code == 200
        assert latest.json()["root_hash"] == backend.root_hex
        assert latest.json()["witness_threshold_met"] is True

        by_height = client.get(f"/transparency/v1/signed-root/{backend._envelope.height}")
        assert by_height.status_code == 200

        witnesses = client.get("/transparency/v1/witnesses")
        assert witnesses.status_code == 200
        assert len(witnesses.json()) == 2

        inclusion = client.get(f"/transparency/v1/inclusion/{backend.key.hex()}")
        assert inclusion.status_code == 200
        assert inclusion.json()["proof_valid"] is True

        non_inclusion = client.get(f"/transparency/v1/non-inclusion/{backend.absent_key.hex()}")
        assert non_inclusion.status_code == 200
        assert non_inclusion.json()["proof_valid"] is True

        equivocation = client.post(
            "/transparency/v1/gossip/equivocation",
            json={
                "height": backend._envelope.height,
                "sequencer_key_id": "sequencer-main",
                "root_a": "aa" * 32,
                "root_b": "bb" * 32,
                "signature_a": "11" * 64,
                "signature_b": "22" * 64,
                "source_peer_a": "peer-a",
                "source_peer_b": "peer-b",
            },
        )
        assert equivocation.status_code == 200
        assert equivocation.json()["accepted"] is True
    finally:
        monitor.set_transparency_backend(previous)
