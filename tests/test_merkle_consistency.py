"""
Tests for Merkle consistency proofs.
"""

from protocol.hashes import hash_bytes
from protocol.merkle import (
    ct_merkle_root,
    generate_consistency_proof,
    verify_consistency_proof,
)


def test_merkle_consistency_proof_round_trip():
    """Generated consistency proofs should verify."""
    leaves = [hash_bytes(f"leaf-{i}".encode("utf-8")) for i in range(6)]
    old_size = 3
    new_size = 6

    old_root = ct_merkle_root(leaves[:old_size])
    new_root = ct_merkle_root(leaves[:new_size])
    proof = generate_consistency_proof(leaves, old_size, new_size)

    assert verify_consistency_proof(old_root, new_root, proof, old_size, new_size)


def test_merkle_consistency_proof_detects_tampering():
    """Tampering with the proof should invalidate verification."""
    leaves = [hash_bytes(f"leaf-{i}".encode("utf-8")) for i in range(5)]
    old_size = 2
    new_size = 5

    old_root = ct_merkle_root(leaves[:old_size])
    new_root = ct_merkle_root(leaves[:new_size])
    proof = generate_consistency_proof(leaves, old_size, new_size)

    bad_proof = proof.copy()
    bad_proof[0] = hash_bytes(b"tamper")

    assert not verify_consistency_proof(old_root, new_root, bad_proof, old_size, new_size)
