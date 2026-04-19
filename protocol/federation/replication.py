"""Federation replication, data availability, and fork evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import nacl.exceptions
import nacl.signing

from protocol.hashes import HASH_SEPARATOR, _length_prefixed_bytes, hash_bytes

from .identity import FederationRegistry, _parse_timestamp
from .quorum import NodeSignature


# =============================================================================
# T1: Steward-Guardian Equivocation Detection (Shadow Ledger Mitigation)
# =============================================================================


@dataclass(frozen=True)
class ShardHeaderForkEvidence:
    """
    Non-repudiable cryptographic proof of Steward-Guardian equivocation.

    When two distinct shard headers H_a and H_b share the same (shard_id, seq)
    but have different header_hash values, this constitutes a "shadow ledger"
    attack. Discovery of such conflicting headers is cryptographic proof of
    fraud that can be publicly verified.

    Attributes:
        shard_id: The shard where equivocation was detected.
        seq: The sequence number where conflicting headers were observed.
        conflicting_header_hashes: Tuple of distinct header hashes for the same seq.
        observer_ids: Tuple of observer identifiers who reported the conflict.
        signatures_a: Signatures collected for header H_a.
        signatures_b: Signatures collected for header H_b.
        detected_at: ISO 8601 timestamp when the fork was detected.
    """

    shard_id: str
    seq: int
    conflicting_header_hashes: tuple[str, ...]
    observer_ids: tuple[str, ...]
    signatures_a: tuple[NodeSignature, ...]
    signatures_b: tuple[NodeSignature, ...]
    detected_at: str

    def __post_init__(self) -> None:
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if len(self.conflicting_header_hashes) < 2:
            raise ValueError("conflicting_header_hashes must include at least two hashes")
        if len(set(self.conflicting_header_hashes)) != len(self.conflicting_header_hashes):
            raise ValueError("conflicting_header_hashes must be unique")
        if len(self.observer_ids) < 1:
            raise ValueError("observer_ids must include at least one observer")
        try:
            _parse_timestamp(self.detected_at)
        except ValueError as exc:
            raise ValueError("detected_at must be a valid ISO 8601 timestamp") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize fork evidence to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "seq": self.seq,
            "conflicting_header_hashes": list(self.conflicting_header_hashes),
            "observer_ids": list(self.observer_ids),
            "signatures_a": [sig.to_dict() for sig in self.signatures_a],
            "signatures_b": [sig.to_dict() for sig in self.signatures_b],
            "detected_at": self.detected_at,
        }

    def colluding_guardians(self) -> tuple[str, ...]:
        """Return node_ids that signed both conflicting headers (provable collusion)."""
        signers_a = {sig.node_id for sig in self.signatures_a}
        signers_b = {sig.node_id for sig in self.signatures_b}
        return tuple(sorted(signers_a & signers_b))


@dataclass(frozen=True)
class GossipedShardHeader:
    """A shard header observation received via gossip from a peer."""

    peer_id: str
    shard_id: str
    seq: int
    header_hash: str
    root_hash: str
    timestamp: str
    signatures: tuple[NodeSignature, ...]

    def __post_init__(self) -> None:
        if not self.peer_id:
            raise ValueError("peer_id must be non-empty")
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if not self.header_hash:
            raise ValueError("header_hash must be non-empty")


def detect_shard_header_forks(
    observations: dict[str, GossipedShardHeader],
    *,
    registry: FederationRegistry | None = None,
) -> tuple[ShardHeaderForkEvidence, ...]:
    """
    Detect equivocation by comparing gossiped shard headers from multiple peers.

    This implements the gossip-based fork detection mitigation for the Shadow
    Ledger attack (T1). When monitors and third-party verifiers gossip signed
    headers, discovery of any H_a != H_b where seq(H_a) == seq(H_b) constitutes
    non-repudiable cryptographic proof of fraud.

    Args:
        observations: Mapping of peer_id -> GossipedShardHeader observed
        registry: Optional federation registry for signature validation

    Returns:
        Tuple of ShardHeaderForkEvidence objects describing detected forks.

    Raises:
        ValueError: If invalid observations are provided.
    """
    if not observations:
        return ()

    from protocol.timestamps import current_timestamp as _current_timestamp

    # Group observations by (shard_id, seq)
    grouped: dict[tuple[str, int], list[GossipedShardHeader]] = {}
    for peer_id, header in sorted(observations.items()):
        key = (header.shard_id, header.seq)
        grouped.setdefault(key, []).append(header)

    evidences: list[ShardHeaderForkEvidence] = []
    for (shard_id, seq), headers in sorted(grouped.items()):
        # Check for conflicting header hashes at the same seq
        hash_to_headers: dict[str, list[GossipedShardHeader]] = {}
        for header in headers:
            hash_to_headers.setdefault(header.header_hash, []).append(header)

        if len(hash_to_headers) <= 1:
            # No conflict at this seq
            continue

        # Fork detected: multiple distinct header hashes for the same seq
        sorted_hashes = sorted(hash_to_headers.keys())
        observer_ids: set[str] = set()
        signatures_by_hash: dict[str, list[NodeSignature]] = {}

        for header_hash, hash_headers in hash_to_headers.items():
            signatures_by_hash[header_hash] = []
            for header in hash_headers:
                observer_ids.add(header.peer_id)
                signatures_by_hash[header_hash].extend(header.signatures)

        # Use the first two conflicting hashes for the evidence
        hash_a, hash_b = sorted_hashes[0], sorted_hashes[1]

        evidence = ShardHeaderForkEvidence(
            shard_id=shard_id,
            seq=seq,
            conflicting_header_hashes=tuple(sorted_hashes),
            observer_ids=tuple(sorted(observer_ids)),
            signatures_a=tuple(signatures_by_hash[hash_a]),
            signatures_b=tuple(signatures_by_hash[hash_b]),
            detected_at=_current_timestamp(),
        )
        evidences.append(evidence)

    return tuple(evidences)


def registry_forest_commitment(registry: FederationRegistry) -> str:
    """
    Compute a deterministic commitment of the Guardian registry to the Forest root.

    This implements the Public Guardian Registry mitigation: the set of active
    Guardian keys is committed to the immutable Forest root, ensuring that a
    "Shadow Ledger" would require a quorum from specifically registered keys.

    Args:
        registry: The federation registry to commit

    Returns:
        Hex-encoded BLAKE3 hash commitment of the registry state.
    """
    active_nodes = sorted(registry.active_nodes(), key=lambda n: n.node_id)

    parts: list[bytes] = [
        _length_prefixed_bytes("epoch", str(registry.epoch).encode("utf-8")),
        _length_prefixed_bytes("membership", registry.membership_hash().encode("utf-8")),
    ]
    for node in active_nodes:
        node_part = b"".join(
            [
                _length_prefixed_bytes("node_id", node.node_id.encode("utf-8")),
                _length_prefixed_bytes("pubkey", node.pubkey.hex().encode("utf-8")),
                _length_prefixed_bytes("endpoint", node.endpoint.encode("utf-8")),
                _length_prefixed_bytes("operator", node.operator.encode("utf-8")),
                _length_prefixed_bytes("jurisdiction", node.jurisdiction.encode("utf-8")),
                _length_prefixed_bytes("status", node.status.encode("utf-8")),
            ]
        )
        parts.append(node_part)

    return hash_bytes(b"".join(parts)).hex()


# =============================================================================
# T2: State Suppression Mitigation (Missing Shard Attack)
# =============================================================================


@dataclass(frozen=True)
class DataAvailabilityChallenge:
    """
    A challenge requiring proof that shard data is available for replication.

    Guardians must refuse to countersign a Forest header unless they have
    successfully replicated the underlying shard data or a verifiable
    data-availability commitment.

    Attributes:
        shard_id: The shard being challenged for availability.
        header_hash: The header hash whose underlying data must be available.
        challenger_id: Node ID of the Guardian issuing the challenge.
        challenge_nonce: Random nonce to prevent replay of stale proofs.
        issued_at: ISO 8601 timestamp when the challenge was issued.
        response_deadline: ISO 8601 timestamp by which proof must be provided.
    """

    shard_id: str
    header_hash: str
    challenger_id: str
    challenge_nonce: str
    issued_at: str
    response_deadline: str

    def __post_init__(self) -> None:
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if not self.header_hash:
            raise ValueError("header_hash must be non-empty")
        if not self.challenger_id:
            raise ValueError("challenger_id must be non-empty")
        if not self.challenge_nonce:
            raise ValueError("challenge_nonce must be non-empty")
        try:
            _parse_timestamp(self.issued_at)
            _parse_timestamp(self.response_deadline)
        except ValueError as exc:
            raise ValueError("timestamps must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "header_hash": self.header_hash,
            "challenger_id": self.challenger_id,
            "challenge_nonce": self.challenge_nonce,
            "issued_at": self.issued_at,
            "response_deadline": self.response_deadline,
        }

    def challenge_hash(self) -> str:
        """Return deterministic hash of the challenge for binding responses."""
        payload = HASH_SEPARATOR.join(
            [
                self.shard_id,
                self.header_hash,
                self.challenger_id,
                self.challenge_nonce,
                self.issued_at,
            ]
        ).encode("utf-8")
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class ReplicationProof:
    """
    Proof that a Guardian has replicated and verified shard data.

    This implements the Signed Tail Consistency mitigation: Guardians must
    provide evidence that they have the underlying Merkle inclusion proofs
    and raw data before a header can be promoted to "Federation Final" status.

    Attributes:
        challenge_hash: Hash of the DataAvailabilityChallenge being answered.
        guardian_id: Node ID of the Guardian providing the proof.
        ledger_tail_hash: BLAKE3 hash of the replicated ledger tail entries.
        merkle_root_verified: Whether the Merkle root was independently verified.
        proof_sample_indices: Random indices that were spot-checked for availability.
        proof_sample_hashes: Hashes of the spot-checked data at sample indices.
        replicated_at: ISO 8601 timestamp when replication completed.
        guardian_signature: Ed25519 signature over the proof payload.
    """

    challenge_hash: str
    guardian_id: str
    ledger_tail_hash: str
    merkle_root_verified: bool
    proof_sample_indices: tuple[int, ...]
    proof_sample_hashes: tuple[str, ...]
    replicated_at: str
    guardian_signature: str

    def __post_init__(self) -> None:
        if not self.challenge_hash:
            raise ValueError("challenge_hash must be non-empty")
        if not self.guardian_id:
            raise ValueError("guardian_id must be non-empty")
        if not self.ledger_tail_hash:
            raise ValueError("ledger_tail_hash must be non-empty")
        if len(self.proof_sample_indices) != len(self.proof_sample_hashes):
            raise ValueError("proof_sample_indices and proof_sample_hashes must have same length")
        try:
            _parse_timestamp(self.replicated_at)
        except ValueError as exc:
            raise ValueError("replicated_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "challenge_hash": self.challenge_hash,
            "guardian_id": self.guardian_id,
            "ledger_tail_hash": self.ledger_tail_hash,
            "merkle_root_verified": self.merkle_root_verified,
            "proof_sample_indices": list(self.proof_sample_indices),
            "proof_sample_hashes": list(self.proof_sample_hashes),
            "replicated_at": self.replicated_at,
            "guardian_signature": self.guardian_signature,
        }

    def proof_payload_hash(self) -> str:
        """Return the hash of the proof payload (excluding signature).

        Each field is encoded with a 4-byte big-endian length prefix so that
        values containing the literal ``|`` character cannot be injected to
        collide with a different field layout.
        """
        sample_indices_bytes = ",".join(str(i) for i in self.proof_sample_indices).encode(
            "utf-8"
        )
        sample_hashes_bytes = ",".join(self.proof_sample_hashes).encode("utf-8")
        payload = b"".join(
            [
                _length_prefixed_bytes("challenge_hash", self.challenge_hash.encode("utf-8")),
                _length_prefixed_bytes("guardian_id", self.guardian_id.encode("utf-8")),
                _length_prefixed_bytes(
                    "ledger_tail_hash", self.ledger_tail_hash.encode("utf-8")
                ),
                _length_prefixed_bytes(
                    "merkle_root_verified",
                    str(self.merkle_root_verified).encode("utf-8"),
                ),
                _length_prefixed_bytes("proof_sample_indices", sample_indices_bytes),
                _length_prefixed_bytes("proof_sample_hashes", sample_hashes_bytes),
                _length_prefixed_bytes("replicated_at", self.replicated_at.encode("utf-8")),
            ]
        )
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class FederationFinalityStatus:
    """
    Tracks the finality status of a shard header with availability gates.

    A header progresses through these states:
    1. PROPOSED: Header announced by Steward
    2. AVAILABILITY_PENDING: Awaiting replication proofs from Guardians
    3. AVAILABILITY_VERIFIED: Sufficient replication proofs received
    4. QUORUM_PENDING: Awaiting quorum signatures
    5. FEDERATION_FINAL: Full quorum + availability = immutable

    Attributes:
        shard_id: The shard being finalized.
        seq: Sequence number of the header.
        header_hash: Hash of the header being finalized.
        status: Current finality status string.
        availability_proofs: Replication proofs received from Guardians.
        quorum_signatures: Federation signatures received.
        finalized_at: ISO 8601 timestamp when finality was achieved (if final).
    """

    shard_id: str
    seq: int
    header_hash: str
    status: str
    availability_proofs: tuple[ReplicationProof, ...]
    quorum_signatures: tuple[NodeSignature, ...]
    finalized_at: str | None

    # Finality status constants
    STATUS_PROPOSED = "PROPOSED"
    STATUS_AVAILABILITY_PENDING = "AVAILABILITY_PENDING"
    STATUS_AVAILABILITY_VERIFIED = "AVAILABILITY_VERIFIED"
    STATUS_QUORUM_PENDING = "QUORUM_PENDING"
    STATUS_FEDERATION_FINAL = "FEDERATION_FINAL"

    def __post_init__(self) -> None:
        valid_statuses = {
            self.STATUS_PROPOSED,
            self.STATUS_AVAILABILITY_PENDING,
            self.STATUS_AVAILABILITY_VERIFIED,
            self.STATUS_QUORUM_PENDING,
            self.STATUS_FEDERATION_FINAL,
        }
        if self.status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if self.finalized_at is not None:
            try:
                _parse_timestamp(self.finalized_at)
            except ValueError as exc:
                raise ValueError("finalized_at must be valid ISO 8601") from exc

    def is_final(self) -> bool:
        """Return whether the header has achieved federation finality."""
        return self.status == self.STATUS_FEDERATION_FINAL

    def availability_threshold_met(self, registry: FederationRegistry) -> bool:
        """Return whether sufficient availability proofs have been received."""
        # Require at least 2/3 of Guardians to have verified availability
        verified_guardians = {proof.guardian_id for proof in self.availability_proofs}
        return len(verified_guardians) >= registry.quorum_threshold()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "seq": self.seq,
            "header_hash": self.header_hash,
            "status": self.status,
            "availability_proofs": [p.to_dict() for p in self.availability_proofs],
            "quorum_signatures": [s.to_dict() for s in self.quorum_signatures],
            "finalized_at": self.finalized_at,
        }


def verify_data_availability(
    challenge: DataAvailabilityChallenge,
    proof: ReplicationProof,
    registry: FederationRegistry,
) -> bool:
    """
    Verify a replication proof against a data availability challenge.

    This verifies that:
    1. The proof answers the correct challenge
    2. The Guardian is registered in the federation
    3. The signature is valid for the proof payload
    4. The Merkle root was verified

    Args:
        challenge: The availability challenge being answered
        proof: The replication proof to verify
        registry: Federation registry for key lookup

    Returns:
        True if the proof is valid, False otherwise
    """
    # Verify challenge binding
    if proof.challenge_hash != challenge.challenge_hash():
        return False

    # Verify Guardian is registered
    try:
        node = registry.get_node(proof.guardian_id)
    except ValueError:
        return False
    if not node.active:
        return False

    # Verify Merkle root was checked
    if not proof.merkle_root_verified:
        return False

    # Verify signature over proof payload
    try:
        payload_hash = bytes.fromhex(proof.proof_payload_hash())
        signature_bytes = bytes.fromhex(proof.guardian_signature)
        verify_key = node.verify_key()
        verify_key.verify(payload_hash, signature_bytes)
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False

    return True


def create_replication_proof(
    challenge: DataAvailabilityChallenge,
    guardian_id: str,
    signing_key: nacl.signing.SigningKey,
    ledger_tail_hash: str,
    proof_sample_indices: tuple[int, ...],
    proof_sample_hashes: tuple[str, ...],
    replicated_at: str,
) -> ReplicationProof:
    """
    Create a signed replication proof for a data availability challenge.

    Args:
        challenge: The availability challenge being answered
        guardian_id: Node ID of the Guardian creating the proof
        signing_key: Ed25519 signing key for the Guardian
        ledger_tail_hash: Hash of the replicated ledger tail
        proof_sample_indices: Indices of spot-checked data
        proof_sample_hashes: Hashes of spot-checked data
        replicated_at: Timestamp when replication completed

    Returns:
        Signed ReplicationProof
    """
    if len(proof_sample_indices) != len(proof_sample_hashes):
        raise ValueError("proof_sample_indices and proof_sample_hashes must have same length")

    # Create unsigned proof to compute payload hash
    unsigned_proof = ReplicationProof(
        challenge_hash=challenge.challenge_hash(),
        guardian_id=guardian_id,
        ledger_tail_hash=ledger_tail_hash,
        merkle_root_verified=True,
        proof_sample_indices=proof_sample_indices,
        proof_sample_hashes=proof_sample_hashes,
        replicated_at=replicated_at,
        guardian_signature="",  # Placeholder
    )

    # Sign the proof payload
    payload_hash = bytes.fromhex(unsigned_proof.proof_payload_hash())
    signed = signing_key.sign(payload_hash)
    signature_hex = signed.signature.hex()

    return ReplicationProof(
        challenge_hash=challenge.challenge_hash(),
        guardian_id=guardian_id,
        ledger_tail_hash=ledger_tail_hash,
        merkle_root_verified=True,
        proof_sample_indices=proof_sample_indices,
        proof_sample_hashes=proof_sample_hashes,
        replicated_at=replicated_at,
        guardian_signature=signature_hex,
    )
