"""Federation key rotation and recursive SNARK chain proofs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import nacl.exceptions
import nacl.signing

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import HASH_SEPARATOR, hash_bytes

from .identity import FederationRegistry, _parse_timestamp
from .quorum import NodeSignature


# =============================================================================
# T3: Long-Range Key Compromise Mitigation (Recursive SNARK Chain Proofs)
# =============================================================================


@dataclass(frozen=True)
class RecursiveChainProof:
    """
    Recursive SNARK proof of correct hash chain transition.

    Using the existing Circom/snarkjs stack, this wraps the hash chain in a
    ZK-proof of correct transition. Even with leaked keys, an adversary cannot
    easily forge the computational history of the ledger without breaking the
    underlying circuit logic.

    The proof attests that:
    1. The chain from previous_root to current_root follows valid transitions
    2. All intermediate hashes are correctly computed
    3. The epoch transitions respect key rotation schedules

    Attributes:
        proof_type: The ZK proof system used (e.g., "groth16", "plonk")
        previous_root: The starting state root being proved from
        current_root: The ending state root being proved to
        epoch_start: Starting epoch of the proven transition
        epoch_end: Ending epoch of the proven transition
        transition_count: Number of state transitions covered by the proof
        proof_data: The serialized SNARK proof (hex-encoded)
        public_inputs: Public inputs to the circuit verification
        verification_key_hash: Hash of the verification key for this proof type
        created_at: ISO 8601 timestamp when the proof was generated
    """

    proof_type: str
    previous_root: str
    current_root: str
    epoch_start: int
    epoch_end: int
    transition_count: int
    proof_data: str
    public_inputs: tuple[str, ...]
    verification_key_hash: str
    created_at: str

    # Supported proof types
    PROOF_TYPE_GROTH16 = "groth16"
    PROOF_TYPE_PLONK = "plonk"

    def __post_init__(self) -> None:
        valid_proof_types = {self.PROOF_TYPE_GROTH16, self.PROOF_TYPE_PLONK}
        if self.proof_type not in valid_proof_types:
            raise ValueError(f"proof_type must be one of {valid_proof_types}")
        if not self.previous_root:
            raise ValueError("previous_root must be non-empty")
        if not self.current_root:
            raise ValueError("current_root must be non-empty")
        if self.epoch_start < 0:
            raise ValueError("epoch_start must be non-negative")
        if self.epoch_end < self.epoch_start:
            raise ValueError("epoch_end must be >= epoch_start")
        if self.transition_count < 0:
            raise ValueError("transition_count must be non-negative")
        if not self.proof_data:
            raise ValueError("proof_data must be non-empty")
        if not self.verification_key_hash:
            raise ValueError("verification_key_hash must be non-empty")
        try:
            _parse_timestamp(self.created_at)
        except ValueError as exc:
            raise ValueError("created_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "proof_type": self.proof_type,
            "previous_root": self.previous_root,
            "current_root": self.current_root,
            "epoch_start": self.epoch_start,
            "epoch_end": self.epoch_end,
            "transition_count": self.transition_count,
            "proof_data": self.proof_data,
            "public_inputs": list(self.public_inputs),
            "verification_key_hash": self.verification_key_hash,
            "created_at": self.created_at,
        }

    def proof_commitment_hash(self) -> str:
        """Return a deterministic hash commitment for this proof."""
        payload = HASH_SEPARATOR.join(
            [
                self.proof_type,
                self.previous_root,
                self.current_root,
                str(self.epoch_start),
                str(self.epoch_end),
                str(self.transition_count),
                self.verification_key_hash,
            ]
        ).encode("utf-8")
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class EpochKeyRotationRecord:
    """
    Record of a key rotation event for epoch-based key compromise mitigation.

    Guardian keys are rotated based on time-bound epochs. This record captures
    the rotation event for audit and verification purposes.

    Attributes:
        node_id: The Guardian node whose key was rotated
        epoch: The epoch in which the rotation occurred
        old_pubkey_hash: Hash of the previous public key
        new_pubkey_hash: Hash of the new public key
        rotated_at: ISO 8601 timestamp of the rotation
        rotation_signature: Signature over the rotation by the old key
        witness_signatures: Signatures from witnesses who observed the rotation
    """

    node_id: str
    epoch: int
    old_pubkey_hash: str
    new_pubkey_hash: str
    rotated_at: str
    rotation_signature: str
    witness_signatures: tuple[NodeSignature, ...]

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must be non-empty")
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")
        if not self.old_pubkey_hash:
            raise ValueError("old_pubkey_hash must be non-empty")
        if not self.new_pubkey_hash:
            raise ValueError("new_pubkey_hash must be non-empty")
        if self.old_pubkey_hash == self.new_pubkey_hash:
            raise ValueError("new_pubkey_hash must differ from old_pubkey_hash")
        try:
            _parse_timestamp(self.rotated_at)
        except ValueError as exc:
            raise ValueError("rotated_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "node_id": self.node_id,
            "epoch": self.epoch,
            "old_pubkey_hash": self.old_pubkey_hash,
            "new_pubkey_hash": self.new_pubkey_hash,
            "rotated_at": self.rotated_at,
            "rotation_signature": self.rotation_signature,
            "witness_signatures": [s.to_dict() for s in self.witness_signatures],
        }


def verify_recursive_chain_proof(
    proof: RecursiveChainProof,
    verification_key: dict[str, Any],
    expected_vk_hash: str,
) -> bool:
    """
    Verify a recursive SNARK chain proof.

    This is a placeholder for integration with the existing Circom/snarkjs
    verification infrastructure. Full implementation requires binding to the
    proof_interface module.

    Args:
        proof: The recursive chain proof to verify
        verification_key: The SNARK verification key
        expected_vk_hash: Expected hash of the verification key

    Returns:
        True if the proof is valid, False otherwise
    """
    # Verify the verification key hash matches
    vk_bytes = canonical_json_bytes(verification_key)
    actual_vk_hash = hash_bytes(vk_bytes).hex()
    if actual_vk_hash != expected_vk_hash:
        return False

    if proof.verification_key_hash != expected_vk_hash:
        return False

    # Verify public inputs match the proof claims
    expected_inputs = [
        proof.previous_root,
        proof.current_root,
        str(proof.epoch_start),
        str(proof.epoch_end),
    ]
    if list(proof.public_inputs[:4]) != expected_inputs:
        return False

    # NOTE: Actual SNARK verification would be performed here via
    # protocol.proof_interface or protocol.groth16_backend
    # For now, this validates structural integrity only
    return True


def verify_epoch_key_rotation(
    record: EpochKeyRotationRecord,
    old_verify_key: nacl.signing.VerifyKey,
    registry: FederationRegistry,
    *,
    min_witnesses: int = 1,
) -> bool:
    """
    Verify an epoch key rotation record.

    This verifies that:
    1. The rotation was signed by the old key
    2. Sufficient witnesses observed the rotation
    3. The new key hash is different from the old

    Args:
        record: The key rotation record to verify
        old_verify_key: The previous verification key
        registry: Federation registry for witness verification
        min_witnesses: Minimum number of witness signatures required

    Returns:
        True if the rotation is valid, False otherwise
    """
    # Verify the rotation signature by the old key
    rotation_payload = HASH_SEPARATOR.join(
        [
            record.node_id,
            str(record.epoch),
            record.old_pubkey_hash,
            record.new_pubkey_hash,
            record.rotated_at,
        ]
    ).encode("utf-8")
    rotation_hash = hash_bytes(rotation_payload)

    try:
        signature_bytes = bytes.fromhex(record.rotation_signature)
        old_verify_key.verify(rotation_hash, signature_bytes)
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False

    # Verify witness signatures meet threshold
    if len(record.witness_signatures) < min_witnesses:
        return False

    verified_witnesses: set[str] = set()
    for witness_sig in record.witness_signatures:
        try:
            witness_node = registry.get_node(witness_sig.node_id)
        except ValueError:
            continue
        if not witness_node.active:
            continue
        try:
            witness_sig_bytes = bytes.fromhex(witness_sig.signature)
            witness_node.verify_key().verify(rotation_hash, witness_sig_bytes)
            verified_witnesses.add(witness_sig.node_id)
        except (ValueError, nacl.exceptions.BadSignatureError):
            continue

    return len(verified_witnesses) >= min_witnesses
