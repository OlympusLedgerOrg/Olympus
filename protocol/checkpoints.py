"""
Signed Root Checkpoints for Olympus

This module implements signed checkpoint protocol to prevent split-view attacks
in transparency logs. Checkpoints provide public commitments to the global
ledger state, allowing witnesses to verify that everyone sees the same history.

Based on Certificate Transparency's Signed Tree Head (STH) design.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import nacl.exceptions
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
from .federation import FederationRegistry, NodeSignature
from .hashes import CHECKPOINT_PREFIX, HASH_SEPARATOR, hash_bytes
from .timestamps import current_timestamp


# Public API for this module — includes both locally-defined symbols and symbols
# re-exported from ``protocol.checkpoint_forks`` / ``protocol.checkpoint_types``
# so that callers can import everything checkpoint-related from a single location.
__all__ = [
    # Re-exported from protocol.checkpoint_types
    "SignedCheckpoint",
    # Locally defined
    "CheckpointVoteMessage",
    "CHECKPOINT_DOMAIN_TAG",
    "serialize_checkpoint_vote_message",
    "sign_federated_checkpoint",
    "verify_federated_checkpoint_signatures",
    "build_checkpoint_quorum_certificate",
    "verify_checkpoint_quorum_certificate",
    "create_checkpoint",
    "verify_checkpoint",
    "verify_checkpoint_chain",
    # Re-exported from protocol.checkpoint_forks
    "detect_checkpoint_fork",
    "detect_gossip_checkpoint_forks",
    "GossipForkEvidence",
    "_ForkAccumulator",
    "CheckpointRegistry",
]

# Domain tag for federation vote messages (distinct from CHECKPOINT_PREFIX hashes).
CHECKPOINT_DOMAIN_TAG = "OLY:CHECKPOINT-VOTE:V1"


@dataclass(frozen=True)
class CheckpointVoteMessage:
    """Canonical federation vote message for checkpoint signatures."""

    domain: str
    node_id: str
    event_id: str
    checkpoint_hash: str
    sequence: int
    ledger_height: int
    timestamp: str
    federation_epoch: int
    validator_set_hash: str


def serialize_checkpoint_vote_message(msg: CheckpointVoteMessage) -> bytes:
    """Return canonical JSON bytes for a checkpoint vote message."""
    payload: dict[str, Any] = {
        "checkpoint_hash": msg.checkpoint_hash,
        "domain": msg.domain,
        "event_id": msg.event_id,
        "federation_epoch": msg.federation_epoch,
        "ledger_height": msg.ledger_height,
        "node_id": msg.node_id,
        "sequence": msg.sequence,
        "timestamp": msg.timestamp,
        "validator_set_hash": msg.validator_set_hash,
    }
    return canonical_json_bytes(payload)


def _checkpoint_vote_event_id(
    checkpoint_hash: str, sequence: int, ledger_height: int, registry: FederationRegistry
) -> str:
    """Return deterministic event identifier for checkpoint votes."""
    payload = HASH_SEPARATOR.join(
        [
            checkpoint_hash,
            str(sequence),
            str(ledger_height),
            str(registry.epoch),
            registry.membership_hash(),
        ]
    ).encode("utf-8")
    return hash_bytes(payload).hex()


def _build_checkpoint_vote_message(
    *,
    checkpoint_hash: str,
    sequence: int,
    ledger_height: int,
    timestamp: str,
    node_id: str,
    registry: FederationRegistry,
) -> CheckpointVoteMessage:
    """Construct the canonical checkpoint vote message for signing or verification."""
    event_id = _checkpoint_vote_event_id(checkpoint_hash, sequence, ledger_height, registry)
    validator_set_hash = registry.membership_hash()
    return CheckpointVoteMessage(
        domain=CHECKPOINT_DOMAIN_TAG,
        node_id=node_id,
        event_id=event_id,
        checkpoint_hash=checkpoint_hash,
        sequence=sequence,
        ledger_height=ledger_height,
        timestamp=timestamp,
        federation_epoch=registry.epoch,
        validator_set_hash=validator_set_hash,
    )


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


def verify_federated_checkpoint_signatures(
    *,
    checkpoint_hash: str,
    sequence: int,
    ledger_height: int,
    timestamp: str,
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> list[NodeSignature]:
    """Return the subset of federation signatures that verify for this checkpoint."""
    valid_signatures: list[NodeSignature] = []
    seen_nodes: set[str] = set()
    for signature in signatures:
        if signature.node_id in seen_nodes:
            continue
        try:
            node = registry.get_node(signature.node_id)
        except ValueError:
            continue
        if not node.active:
            continue
        msg = _build_checkpoint_vote_message(
            checkpoint_hash=checkpoint_hash,
            sequence=sequence,
            ledger_height=ledger_height,
            timestamp=timestamp,
            node_id=signature.node_id,
            registry=registry,
        )
        if msg.domain != CHECKPOINT_DOMAIN_TAG:
            continue
        vote_hash = hash_bytes(serialize_checkpoint_vote_message(msg))
        try:
            sig_bytes = bytes.fromhex(signature.signature)
        except ValueError:
            continue
        verified = False
        for verify_key in node.verify_keys_for_timestamp(timestamp):
            try:
                verify_key.verify(vote_hash, sig_bytes)
                verified = True
                break
            except nacl.exceptions.BadSignatureError:
                continue
        if not verified:
            continue
        valid_signatures.append(signature)
        seen_nodes.add(signature.node_id)
    return valid_signatures


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


def verify_checkpoint_quorum_certificate(
    *,
    checkpoint: SignedCheckpoint,
    registry: FederationRegistry,
) -> bool:
    """Verify the federation quorum certificate for a checkpoint."""
    certificate = checkpoint.federation_quorum_certificate
    required_fields = {
        "checkpoint_hash",
        "sequence",
        "ledger_height",
        "timestamp",
        "event_id",
        "federation_epoch",
        "membership_hash",
        "validator_set_hash",
        "validator_count",
        "quorum_threshold",
        "scheme",
        "signer_bitmap",
        "signatures",
    }
    if not required_fields.issubset(certificate):
        return False
    try:
        certificate_epoch = int(certificate["federation_epoch"])
    except (TypeError, ValueError):
        return False
    try:
        registry_snapshot = registry.get_snapshot(certificate_epoch)
    except ValueError:
        return False
    if certificate["checkpoint_hash"] != checkpoint.checkpoint_hash:
        return False
    if int(certificate["sequence"]) != checkpoint.sequence:
        return False
    if int(certificate["ledger_height"]) != checkpoint.ledger_height:
        return False
    if certificate["timestamp"] != checkpoint.timestamp:
        return False
    expected_event_id = _checkpoint_vote_event_id(
        checkpoint.checkpoint_hash,
        checkpoint.sequence,
        checkpoint.ledger_height,
        registry_snapshot,
    )
    if certificate["event_id"] != expected_event_id:
        return False
    if int(certificate["federation_epoch"]) != registry_snapshot.epoch:
        return False
    validator_set_hash = registry_snapshot.membership_hash()
    if str(certificate["membership_hash"]) != validator_set_hash:
        return False
    if str(certificate["validator_set_hash"]) != validator_set_hash:
        return False
    try:
        validator_count = int(certificate["validator_count"])
        quorum_threshold = int(certificate["quorum_threshold"])
    except (TypeError, ValueError):
        return False
    if validator_count != len(registry_snapshot.active_nodes()):
        return False
    if quorum_threshold != registry_snapshot.quorum_threshold():
        return False
    if certificate.get("scheme") != "ed25519":
        return False

    serialized_signatures = certificate.get("signatures")
    if not isinstance(serialized_signatures, list):
        return False
    signer_bitmap = certificate.get("signer_bitmap")
    if not isinstance(signer_bitmap, str):
        return False
    active_node_ids = sorted(node.node_id for node in registry_snapshot.active_nodes())
    if len(signer_bitmap) != len(active_node_ids):
        return False
    if not all(bit in {"0", "1"} for bit in signer_bitmap):
        return False
    expected_signer_ids = [
        node_id
        for node_id, bitmap_bit in zip(active_node_ids, signer_bitmap, strict=True)
        if bitmap_bit == "1"
    ]
    if len(serialized_signatures) != len(expected_signer_ids):
        return False

    unique_verified_nodes: set[str] = set()
    for expected_node_id, serialized_signature in zip(
        expected_signer_ids, serialized_signatures, strict=True
    ):
        if not (
            isinstance(serialized_signature, dict)
            and "node_id" in serialized_signature
            and "signature" in serialized_signature
        ):
            return False
        node_id = str(serialized_signature["node_id"])
        if node_id != expected_node_id:
            return False
        if node_id in unique_verified_nodes:
            return False
        try:
            node = registry_snapshot.get_node(node_id)
        except ValueError:
            return False
        if not node.active:
            return False
        msg = _build_checkpoint_vote_message(
            checkpoint_hash=checkpoint.checkpoint_hash,
            sequence=checkpoint.sequence,
            ledger_height=checkpoint.ledger_height,
            timestamp=checkpoint.timestamp,
            node_id=node_id,
            registry=registry_snapshot,
        )
        if msg.domain != CHECKPOINT_DOMAIN_TAG:
            return False
        vote_hash = hash_bytes(serialize_checkpoint_vote_message(msg))
        try:
            sig_bytes = bytes.fromhex(str(serialized_signature["signature"]))
        except ValueError:
            return False
        verified = False
        for verify_key in node.verify_keys_for_timestamp(checkpoint.timestamp):
            try:
                verify_key.verify(vote_hash, sig_bytes)
                verified = True
                break
            except nacl.exceptions.BadSignatureError:
                continue
        if not verified:
            return False
        unique_verified_nodes.add(node_id)
    return len(unique_verified_nodes) >= registry_snapshot.quorum_threshold()


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


def verify_checkpoint(
    checkpoint: SignedCheckpoint,
    registry: FederationRegistry,
) -> bool:
    """
    Verify a signed checkpoint's integrity and signature.

    Args:
        checkpoint: Checkpoint to verify
        registry: Federation registry used to verify quorum certificates
    Returns:
        True if checkpoint is valid, False otherwise
    """
    try:
        # Recompute checkpoint hash
        payload = {
            "sequence": checkpoint.sequence,
            "timestamp": checkpoint.timestamp,
            "ledger_head_hash": checkpoint.ledger_head_hash,
            "previous_checkpoint_hash": checkpoint.previous_checkpoint_hash,
            "ledger_height": checkpoint.ledger_height,
            "shard_roots": checkpoint.shard_roots,
            "consistency_proof": checkpoint.consistency_proof,
        }
        expected_hash = hash_bytes(CHECKPOINT_PREFIX + canonical_json_bytes(payload)).hex()

        if checkpoint.checkpoint_hash != expected_hash:
            return False

        return verify_checkpoint_quorum_certificate(
            checkpoint=checkpoint,
            registry=registry,
        )
    except (TypeError, ValueError):
        return False


def verify_checkpoint_chain(
    checkpoints: list[SignedCheckpoint],
    registry: FederationRegistry,
    finality_anchors: Mapping[int, str] | None = None,
) -> bool:
    """
    Verify the integrity of a chain of checkpoints.

    This verifies:
    1. Each checkpoint is individually valid
    2. Sequences are monotonically increasing
    3. Each checkpoint correctly references the previous checkpoint hash
    4. Ledger heights are monotonically increasing

    Args:
        checkpoints: List of checkpoints in chronological order
        registry: Federation registry used to verify quorum certificates
        finality_anchors: Optional out-of-band finality anchors mapping
            checkpoint sequence -> checkpoint_hash. When provided, every anchor
            must be present in the local chain and match exactly.

    Returns:
        True if the entire chain is valid, False otherwise
    """
    if not checkpoints:
        return not finality_anchors

    # Verify genesis checkpoint
    if checkpoints[0].previous_checkpoint_hash != "":
        return False
    if checkpoints[0].consistency_proof:
        return False

    for i, checkpoint in enumerate(checkpoints):
        # Verify individual checkpoint
        if not verify_checkpoint(checkpoint, registry):
            return False

        # Verify sequence numbers are monotonically increasing
        if i > 0:
            if checkpoint.sequence <= checkpoints[i - 1].sequence:
                return False

            # Verify checkpoint linkage
            if checkpoint.previous_checkpoint_hash != checkpoints[i - 1].checkpoint_hash:
                return False

            # Verify ledger heights are monotonically increasing
            if checkpoint.ledger_height < checkpoints[i - 1].ledger_height:
                return False

            # Verify Merkle consistency proof links previous and current roots
            try:
                from .merkle import verify_consistency_proof

                previous_root = bytes.fromhex(checkpoints[i - 1].ledger_head_hash)
                current_root = bytes.fromhex(checkpoint.ledger_head_hash)
                proof_bytes = [bytes.fromhex(p) for p in checkpoint.consistency_proof]
            except (TypeError, ValueError):  # pragma: no cover — hex validated at creation
                return False

            trust_new_root_on_empty = checkpoints[i - 1].ledger_height == 0
            # current_root comes from a signed checkpoint validated by verify_checkpoint above.
            if not verify_consistency_proof(
                previous_root,
                current_root,
                proof_bytes,
                checkpoints[i - 1].ledger_height,
                checkpoint.ledger_height,
                trust_new_root_on_empty=trust_new_root_on_empty,
            ):
                return False
        elif checkpoint.consistency_proof:
            # A genesis checkpoint must not carry a consistency proof
            return False  # pragma: no cover — create_checkpoint rejects this

    if finality_anchors:
        checkpoints_by_sequence = {checkpoint.sequence: checkpoint for checkpoint in checkpoints}
        for sequence, checkpoint_hash in finality_anchors.items():
            anchored = checkpoints_by_sequence.get(sequence)
            if anchored is None:
                return False
            if anchored.checkpoint_hash != checkpoint_hash:
                return False

    return True

