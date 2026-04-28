"""Checkpoint verification primitives.

Contains the pure-verification helpers that don't depend on signing or fork
detection. Extracted from ``protocol.checkpoints`` so that ``protocol.checkpoint_forks``
can call ``verify_checkpoint`` / ``verify_checkpoint_chain`` without creating an
import cycle with ``protocol.checkpoints``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import nacl.exceptions

from .canonical_json import canonical_json_bytes
from .checkpoint_types import SignedCheckpoint
from .federation import FederationRegistry, NodeSignature
from .hashes import CHECKPOINT_PREFIX, HASH_SEPARATOR, hash_bytes


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
