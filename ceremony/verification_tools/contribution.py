"""
Contribution Hashing Protocol

This module implements the contribution hashing scheme for the trusted setup
ceremony. Each contribution is cryptographically bound to:

1. The previous contribution (chain integrity)
2. The participant identity (attribution)
3. The beacon randomness (anti-grinding)
4. The contribution content (artifact binding)

The hash is computed using BLAKE3 with domain separation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import blake3

from .beacon import BeaconRound


# Domain separation prefix for contribution hashing
CONTRIBUTION_PREFIX = b"OLYMPUS:CEREMONY:CONTRIBUTION:V1"


class ContributionPhase(Enum):
    """Ceremony phase for a contribution."""

    PHASE1_PTAU = "phase1_ptau"  # Powers of Tau
    PHASE2_CIRCUIT = "phase2_circuit"  # Circuit-specific


@dataclass
class Contribution:
    """
    A single contribution to the trusted setup ceremony.

    Attributes:
        contribution_id: Unique identifier for this contribution
        phase: Which ceremony phase this contribution belongs to
        sequence_number: Sequential index within the phase (1-indexed)
        participant_id: Identifier for the contributing participant
        participant_pubkey: Ed25519 public key of the participant (hex)
        timestamp: ISO 8601 timestamp of contribution
        previous_hash: Hash of the previous contribution (hex)
        artifact_hash: Hash of the contribution artifact (PTAU or zkey)
        beacon_round: Beacon round used for randomness binding
        signature: Ed25519 signature over the contribution hash (hex)
        metadata: Optional additional metadata
    """

    contribution_id: str
    phase: ContributionPhase
    sequence_number: int
    participant_id: str
    participant_pubkey: str
    timestamp: str
    previous_hash: str
    artifact_hash: str
    beacon_round: BeaconRound | None
    signature: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            "contribution_id": self.contribution_id,
            "phase": self.phase.value,
            "sequence_number": self.sequence_number,
            "participant_id": self.participant_id,
            "participant_pubkey": self.participant_pubkey,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "artifact_hash": self.artifact_hash,
            "beacon_round": self.beacon_round.to_dict() if self.beacon_round else None,
            "signature": self.signature,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Contribution:
        """Deserialize from dictionary."""
        beacon_data = data.get("beacon_round")
        beacon = BeaconRound.from_dict(beacon_data) if beacon_data else None

        return cls(
            contribution_id=data["contribution_id"],
            phase=ContributionPhase(data["phase"]),
            sequence_number=data["sequence_number"],
            participant_id=data["participant_id"],
            participant_pubkey=data["participant_pubkey"],
            timestamp=data["timestamp"],
            previous_hash=data["previous_hash"],
            artifact_hash=data["artifact_hash"],
            beacon_round=beacon,
            signature=data.get("signature", ""),
            metadata=data.get("metadata", {}),
        )

    def hash_preimage(self) -> bytes:
        """
        Compute the canonical preimage for hashing.

        The preimage is a deterministic serialization of all contribution
        fields that are bound into the contribution hash.

        Returns:
            Bytes to be hashed with BLAKE3
        """
        # Fields are joined with | separator in canonical order
        fields = [
            self.contribution_id,
            self.phase.value,
            str(self.sequence_number),
            self.participant_id,
            self.participant_pubkey,
            self.timestamp,
            self.previous_hash,
            self.artifact_hash,
        ]

        # Include beacon randomness if present
        if self.beacon_round:
            fields.append(str(self.beacon_round.round_number))
            fields.append(self.beacon_round.randomness)

        return "|".join(fields).encode("utf-8")


def compute_contribution_hash(contribution: Contribution) -> bytes:
    """
    Compute the BLAKE3 hash of a contribution.

    The hash binds together all critical fields of the contribution using
    domain separation to prevent cross-protocol attacks.

    Args:
        contribution: The contribution to hash

    Returns:
        32-byte BLAKE3 hash
    """
    preimage = contribution.hash_preimage()
    return blake3.blake3(CONTRIBUTION_PREFIX + b"|" + preimage).digest()


def compute_artifact_hash(artifact_path: Path) -> str:
    """
    Compute the BLAKE3 hash of a contribution artifact file.

    This is used to bind the contribution to the actual PTAU or zkey file.

    Args:
        artifact_path: Path to the artifact file

    Returns:
        Hex-encoded BLAKE3 hash
    """
    hasher = blake3.blake3()
    with open(artifact_path, "rb") as f:
        while chunk := f.read(65536):  # 64 KiB chunks
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_artifact_sha256(artifact_path: Path) -> str:
    """
    Compute the SHA-256 hash of a contribution artifact file.

    This provides compatibility with snarkjs tooling which uses SHA-256.

    Args:
        artifact_path: Path to the artifact file

    Returns:
        Hex-encoded SHA-256 hash
    """
    hasher = hashlib.sha256()
    with open(artifact_path, "rb") as f:
        while chunk := f.read(65536):  # 64 KiB chunks
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_contribution(
    contribution: Contribution,
    expected_previous_hash: str | None = None,
    verify_signature: bool = True,
) -> tuple[bool, list[str]]:
    """
    Verify a contribution against integrity constraints.

    Checks:
    1. Contribution hash is well-formed
    2. Previous hash matches expected value (if provided)
    3. Signature is valid (if verify_signature is True)
    4. Beacon randomness is correctly derived (if present)
    5. Timestamp is valid ISO 8601

    Args:
        contribution: The contribution to verify
        expected_previous_hash: Expected hash of previous contribution
        verify_signature: Whether to verify the Ed25519 signature

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors: list[str] = []

    # Check sequence number
    if contribution.sequence_number < 1:
        errors.append(f"Invalid sequence number: {contribution.sequence_number}")

    # Check previous hash
    if expected_previous_hash is not None:
        if contribution.previous_hash != expected_previous_hash:
            errors.append(
                f"Previous hash mismatch: expected {expected_previous_hash}, "
                f"got {contribution.previous_hash}"
            )

    # Check timestamp format
    try:
        datetime.fromisoformat(contribution.timestamp.replace("Z", "+00:00"))
    except ValueError as e:
        errors.append(f"Invalid timestamp format: {e}")

    # Check participant pubkey format (should be hex-encoded Ed25519 public key)
    try:
        pubkey_bytes = bytes.fromhex(contribution.participant_pubkey)
        if len(pubkey_bytes) != 32:
            errors.append(f"Invalid public key length: expected 32 bytes, got {len(pubkey_bytes)}")
    except ValueError as e:
        errors.append(f"Invalid public key hex: {e}")

    # Check artifact hash format
    try:
        artifact_bytes = bytes.fromhex(contribution.artifact_hash)
        if len(artifact_bytes) != 32:
            errors.append(
                f"Invalid artifact hash length: expected 32 bytes, got {len(artifact_bytes)}"
            )
    except ValueError as e:
        errors.append(f"Invalid artifact hash hex: {e}")

    # Verify beacon randomness
    if contribution.beacon_round:
        from .beacon import verify_beacon_randomness

        if not verify_beacon_randomness(contribution.beacon_round):
            errors.append("Beacon randomness verification failed")

    # Verify signature
    if verify_signature and contribution.signature:
        try:
            import nacl.signing

            contribution_hash = compute_contribution_hash(contribution)
            verify_key = nacl.signing.VerifyKey(bytes.fromhex(contribution.participant_pubkey))
            signature_bytes = bytes.fromhex(contribution.signature)
            verify_key.verify(contribution_hash, signature_bytes)
        except Exception as e:
            errors.append(f"Signature verification failed: {e}")
    elif verify_signature and not contribution.signature:
        errors.append("Missing signature")

    return len(errors) == 0, errors


def sign_contribution(contribution: Contribution, signing_key_hex: str) -> str:
    """
    Sign a contribution with an Ed25519 private key.

    Args:
        contribution: The contribution to sign
        signing_key_hex: Hex-encoded Ed25519 private key (32 bytes)

    Returns:
        Hex-encoded signature
    """
    import nacl.signing

    signing_key = nacl.signing.SigningKey(bytes.fromhex(signing_key_hex))
    contribution_hash = compute_contribution_hash(contribution)
    signed = signing_key.sign(contribution_hash)
    return signed.signature.hex()


def create_contribution(
    *,
    phase: ContributionPhase,
    sequence_number: int,
    participant_id: str,
    participant_pubkey: str,
    previous_hash: str,
    artifact_hash: str,
    beacon_round: BeaconRound | None = None,
    signing_key_hex: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Contribution:
    """
    Create a new contribution with automatic ID generation and optional signing.

    Args:
        phase: Ceremony phase
        sequence_number: Sequential index within the phase
        participant_id: Identifier for the contributing participant
        participant_pubkey: Ed25519 public key of the participant (hex)
        previous_hash: Hash of the previous contribution (hex)
        artifact_hash: Hash of the contribution artifact
        beacon_round: Optional beacon round for randomness binding
        signing_key_hex: Optional Ed25519 private key for signing
        metadata: Optional additional metadata

    Returns:
        A new Contribution object
    """
    from protocol.timestamps import current_timestamp

    # Generate contribution ID from hash of inputs
    id_preimage = f"{phase.value}|{sequence_number}|{participant_id}|{artifact_hash}"
    contribution_id = blake3.blake3(id_preimage.encode("utf-8")).hexdigest()[:16]

    contribution = Contribution(
        contribution_id=contribution_id,
        phase=phase,
        sequence_number=sequence_number,
        participant_id=participant_id,
        participant_pubkey=participant_pubkey,
        timestamp=current_timestamp(),
        previous_hash=previous_hash,
        artifact_hash=artifact_hash,
        beacon_round=beacon_round,
        signature="",
        metadata=metadata or {},
    )

    # Sign if key provided
    if signing_key_hex:
        contribution.signature = sign_contribution(contribution, signing_key_hex)

    return contribution


def load_contribution(path: Path) -> Contribution:
    """
    Load a contribution from a JSON file.

    Args:
        path: Path to the contribution JSON file

    Returns:
        The deserialized Contribution object

    Raises:
        ValueError: If the file cannot be parsed
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return Contribution.from_dict(data)


def save_contribution(contribution: Contribution, path: Path) -> None:
    """
    Save a contribution to a JSON file.

    Args:
        contribution: The contribution to save
        path: Path to write the JSON file
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(contribution.to_dict(), f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    # CLI for contribution operations
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Contribution hashing operations")
    parser.add_argument("--verify", type=Path, help="Verify a contribution file")
    parser.add_argument("--hash-artifact", type=Path, help="Hash an artifact file")
    parser.add_argument("--show", type=Path, help="Show contribution details")

    args = parser.parse_args()

    if args.verify:
        contribution = load_contribution(args.verify)
        is_valid, errors = verify_contribution(
            contribution, verify_signature=bool(contribution.signature)
        )
        if is_valid:
            print(f"✓ Contribution {contribution.contribution_id} verified successfully")
            sys.exit(0)
        else:
            print(f"✗ Contribution {contribution.contribution_id} verification FAILED:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)

    elif args.hash_artifact:
        blake3_hash = compute_artifact_hash(args.hash_artifact)
        sha256_hash = compute_artifact_sha256(args.hash_artifact)
        print(f"BLAKE3: {blake3_hash}")
        print(f"SHA256: {sha256_hash}")

    elif args.show:
        contribution = load_contribution(args.show)
        print(json.dumps(contribution.to_dict(), indent=2))

    else:
        parser.print_help()
