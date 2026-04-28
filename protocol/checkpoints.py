"""
Signed Root Checkpoints for Olympus

This module implements signed checkpoint protocol to prevent split-view attacks
in transparency logs. Checkpoints provide public commitments to the global
ledger state, allowing witnesses to verify that everyone sees the same history.

Based on Certificate Transparency's Signed Tree Head (STH) design.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import nacl.signing

from .canonical_json import canonical_json_bytes
from .checkpoint_forks import (
    CheckpointRegistry,
    GossipForkEvidence,
    _ForkAccumulator,
    detect_checkpoint_fork,
    detect_gossip_checkpoint_forks,
)
from .checkpoint_types import SignedCheckpoint
from .checkpoint_verify import (
    CHECKPOINT_DOMAIN_TAG,
    CheckpointVoteMessage,
    _build_checkpoint_vote_message,
    _checkpoint_vote_event_id,
    serialize_checkpoint_vote_message,
    verify_checkpoint,
    verify_checkpoint_chain,
    verify_checkpoint_quorum_certificate,
    verify_federated_checkpoint_signatures,
)
from .federation import FederationRegistry, NodeSignature
from .hashes import CHECKPOINT_PREFIX, hash_bytes
from .timestamps import current_timestamp


# Public API for this module — re-exports symbols from ``protocol.checkpoint_types``,
# ``protocol.checkpoint_verify``, and ``protocol.checkpoint_forks`` so callers can
# import everything checkpoint-related from a single location.
__all__ = [
    # Re-exported from protocol.checkpoint_types
    "SignedCheckpoint",
    # Re-exported from protocol.checkpoint_verify
    "CheckpointVoteMessage",
    "CHECKPOINT_DOMAIN_TAG",
    "serialize_checkpoint_vote_message",
    "verify_federated_checkpoint_signatures",
    "verify_checkpoint_quorum_certificate",
    "verify_checkpoint",
    "verify_checkpoint_chain",
    # Locally defined
    "sign_federated_checkpoint",
    "build_checkpoint_quorum_certificate",
    "create_checkpoint",
    # Re-exported from protocol.checkpoint_forks
    "detect_checkpoint_fork",
    "detect_gossip_checkpoint_forks",
    "GossipForkEvidence",
    "_ForkAccumulator",
    "CheckpointRegistry",
]


def sign_federated_checkpoint(
    *,
    checkpoint_hash: str,
    sequence: int,
    ledger_height: int,
    timestamp: str,
    node_id: str,
    signing_key: nacl.signing.SigningKey,
    registry: FederationRegistry,
) -> NodeSignature:
    """Sign a checkpoint on behalf of a federation node."""
    msg = _build_checkpoint_vote_message(
        checkpoint_hash=checkpoint_hash,
        sequence=sequence,
        ledger_height=ledger_height,
        timestamp=timestamp,
        node_id=node_id,
        registry=registry,
    )
    vote_hash = hash_bytes(serialize_checkpoint_vote_message(msg))
    signature = signing_key.sign(vote_hash).signature.hex()
    return NodeSignature(node_id=node_id, signature=signature)


def build_checkpoint_quorum_certificate(
    *,
    checkpoint_hash: str,
    sequence: int,
    ledger_height: int,
    timestamp: str,
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> dict[str, Any]:
    """Build a quorum certificate for a federation-signed checkpoint.

    The certificate includes both membership_hash and validator_set_hash to
    mirror federation header certificates. membership_hash matches the
    registry commitment used by federation verifiers, while validator_set_hash
    preserves parity with header certificate schemas consumed by ledger tooling.
    """
    valid_signatures = verify_federated_checkpoint_signatures(
        checkpoint_hash=checkpoint_hash,
        sequence=sequence,
        ledger_height=ledger_height,
        timestamp=timestamp,
        signatures=signatures,
        registry=registry,
    )
    if len(valid_signatures) < registry.quorum_threshold():
        signer_ids = [signature.node_id for signature in valid_signatures]
        raise ValueError(
            "Insufficient valid federation signatures for checkpoint quorum "
            f"(got {len(valid_signatures)} from {signer_ids}, "
            f"need {registry.quorum_threshold()})"
        )
    signature_by_node = {signature.node_id: signature for signature in valid_signatures}
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap_bits: list[str] = []
    ordered_signatures: list[NodeSignature] = []
    validator_count = len(active_node_ids)
    for node_id in active_node_ids:
        signature = signature_by_node.get(node_id)
        if signature is not None:
            ordered_signatures.append(signature)
            signer_bitmap_bits.append("1")
        else:
            signer_bitmap_bits.append("0")
    validator_set_hash = registry.membership_hash()
    return {
        "checkpoint_hash": checkpoint_hash,
        "sequence": sequence,
        "ledger_height": ledger_height,
        "timestamp": timestamp,
        "event_id": _checkpoint_vote_event_id(checkpoint_hash, sequence, ledger_height, registry),
        "federation_epoch": registry.epoch,
        "membership_hash": validator_set_hash,
        "validator_set_hash": validator_set_hash,
        "validator_count": validator_count,
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": "ed25519",
        "signer_bitmap": "".join(signer_bitmap_bits),
        "signatures": [signature.to_dict() for signature in ordered_signatures],
    }


def create_checkpoint(
    *,
    sequence: int,
    ledger_head_hash: str,
    ledger_height: int,
    previous_checkpoint_hash: str = "",
    shard_roots: dict[str, str] | None = None,
    consistency_proof: list[str] | None = None,
    registry: FederationRegistry,
    signing_keys: Mapping[str, nacl.signing.SigningKey] | None = None,
    signatures: list[NodeSignature] | None = None,
) -> SignedCheckpoint:
    """
    Create a signed checkpoint for the current ledger state.

    Args:
        sequence: Monotonically increasing checkpoint sequence number
        ledger_head_hash: Hex-encoded hash of the latest ledger entry
        ledger_height: Total number of ledger entries
        previous_checkpoint_hash: Hex-encoded hash of previous checkpoint
        shard_roots: Optional mapping of shard_id to root_hash
        consistency_proof: Merkle consistency proof (hex strings) showing this
            ledger root extends the previous checkpoint's ledger root. Required
            for non-genesis checkpoints.
        registry: Federation registry used to verify quorum signatures
        signing_keys: Optional mapping of node_id -> signing key. If provided,
            signatures are generated locally for each entry. Either signing_keys
            or signatures must be supplied.
        signatures: Optional list of federation node signatures over the
            checkpoint vote message. Either signing_keys or signatures must be supplied.

    Returns:
        Signed checkpoint

    Raises:
        ValueError: If sequence is negative or ledger_height is negative
    """
    if sequence < 0:
        raise ValueError(f"Checkpoint sequence must be non-negative, got {sequence}")
    if ledger_height < 0:
        raise ValueError(f"Ledger height must be non-negative, got {ledger_height}")
    if sequence == 0:
        if previous_checkpoint_hash:
            raise ValueError(
                "Genesis checkpoints (sequence=0) cannot have previous_checkpoint_hash"
            )
        if consistency_proof:
            raise ValueError("Genesis checkpoints (sequence=0) cannot have consistency_proof")
    else:
        if not previous_checkpoint_hash:
            raise ValueError("Non-genesis checkpoints must include previous_checkpoint_hash")
        if not consistency_proof:
            raise ValueError("Non-genesis checkpoints must include a consistency proof")
    if signatures and signing_keys:
        raise ValueError(
            "Cannot provide both signing_keys and signatures: choose one signing method"
        )
    if signatures is None and signing_keys is None:
        raise ValueError(
            "Checkpoint creation requires federation signatures via signing_keys or signatures"
        )

    timestamp = current_timestamp()
    consistency_proof = consistency_proof or []

    # Validate proof encodings
    for proof_element in consistency_proof:
        try:
            bytes.fromhex(proof_element)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError("Consistency proof elements must be hex strings") from exc

    # Build canonical checkpoint payload (excludes signature and checkpoint_hash)
    payload = {
        "sequence": sequence,
        "timestamp": timestamp,
        "ledger_head_hash": ledger_head_hash,
        "previous_checkpoint_hash": previous_checkpoint_hash,
        "ledger_height": ledger_height,
        "shard_roots": shard_roots or {},
        "consistency_proof": consistency_proof,
    }

    # Compute checkpoint hash with domain separation
    checkpoint_hash_bytes = hash_bytes(CHECKPOINT_PREFIX + canonical_json_bytes(payload))
    checkpoint_hash = checkpoint_hash_bytes.hex()

    if signatures is None:
        # signing_keys is guaranteed non-None here by the check at line 487.
        # The assert is purely for mypy type narrowing and can never fail at
        # runtime; nosec suppresses the Bandit B101 false-positive.
        assert signing_keys is not None  # nosec B101
        _keys = signing_keys  # local binding for mypy type narrowing
        signatures = [
            sign_federated_checkpoint(
                checkpoint_hash=checkpoint_hash,
                sequence=sequence,
                ledger_height=ledger_height,
                timestamp=timestamp,
                node_id=node_id,
                signing_key=key,
                registry=registry,
            )
            for node_id, key in _keys.items()
        ]

    certificate = build_checkpoint_quorum_certificate(
        checkpoint_hash=checkpoint_hash,
        sequence=sequence,
        ledger_height=ledger_height,
        timestamp=timestamp,
        signatures=signatures,
        registry=registry,
    )

    return SignedCheckpoint(
        sequence=sequence,
        timestamp=timestamp,
        ledger_head_hash=ledger_head_hash,
        previous_checkpoint_hash=previous_checkpoint_hash,
        ledger_height=ledger_height,
        shard_roots=shard_roots or {},
        consistency_proof=consistency_proof,
        checkpoint_hash=checkpoint_hash,
        federation_quorum_certificate=certificate,
    )
