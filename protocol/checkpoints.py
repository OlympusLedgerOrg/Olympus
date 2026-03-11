"""
Signed Root Checkpoints for Olympus

This module implements signed checkpoint protocol to prevent split-view attacks
in transparency logs. Checkpoints provide public commitments to the global
ledger state, allowing witnesses to verify that everyone sees the same history.

Based on Certificate Transparency's Signed Tree Head (STH) design.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import nacl.encoding
import nacl.signing

from .canonical_json import canonical_json_bytes
from .hashes import CHECKPOINT_PREFIX, hash_bytes
from .timestamps import current_timestamp


@dataclass
class SignedCheckpoint:
    """
    A signed commitment to the global ledger state at a specific point in time.

    Checkpoints serve as public witnesses to prevent split-view attacks where
    a malicious operator presents different histories to different auditors.
    """

    # Checkpoint sequence number (monotonically increasing)
    sequence: int

    # ISO 8601 timestamp when this checkpoint was created
    timestamp: str

    # Hex-encoded hash of the latest ledger entry at this checkpoint
    ledger_head_hash: str

    # Hex-encoded hash of the previous checkpoint (empty for genesis)
    previous_checkpoint_hash: str

    # Total number of ledger entries up to and including this checkpoint
    ledger_height: int

    # Optional shard-specific state commitments
    shard_roots: dict[str, str]  # shard_id -> root_hash

    # Merkle consistency proof linking to the previous checkpoint's ledger root
    consistency_proof: list[str]

    # Hex-encoded hash of the checkpoint payload (computed from above fields)
    checkpoint_hash: str

    # Hex-encoded Ed25519 signature over checkpoint_hash
    signature: str

    # Hex-encoded Ed25519 public key used to sign this checkpoint
    public_key: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedCheckpoint:
        """Create from dictionary."""
        return cls(
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            ledger_head_hash=data["ledger_head_hash"],
            previous_checkpoint_hash=data["previous_checkpoint_hash"],
            ledger_height=data["ledger_height"],
            shard_roots=data.get("shard_roots", {}),
            consistency_proof=data.get("consistency_proof", []),
            checkpoint_hash=data["checkpoint_hash"],
            signature=data["signature"],
            public_key=data["public_key"],
        )


def create_checkpoint(
    *,
    sequence: int,
    ledger_head_hash: str,
    ledger_height: int,
    previous_checkpoint_hash: str = "",
    shard_roots: dict[str, str] | None = None,
    consistency_proof: list[str] | None = None,
    signing_key: nacl.signing.SigningKey,
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
        signing_key: Ed25519 signing key for this checkpoint

    Returns:
        Signed checkpoint

    Raises:
        ValueError: If sequence is negative or ledger_height is negative
    """
    if sequence < 0:
        raise ValueError(f"Checkpoint sequence must be non-negative, got {sequence}")
    if ledger_height < 0:
        raise ValueError(f"Ledger height must be non-negative, got {ledger_height}")
    if previous_checkpoint_hash and not consistency_proof:
        raise ValueError("Non-genesis checkpoints must include a consistency proof")

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

    # Sign the checkpoint hash
    signature_bytes = signing_key.sign(checkpoint_hash_bytes).signature
    signature = signature_bytes.hex()

    # Extract public key
    public_key = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("ascii")

    return SignedCheckpoint(
        sequence=sequence,
        timestamp=timestamp,
        ledger_head_hash=ledger_head_hash,
        previous_checkpoint_hash=previous_checkpoint_hash,
        ledger_height=ledger_height,
        shard_roots=shard_roots or {},
        consistency_proof=consistency_proof,
        checkpoint_hash=checkpoint_hash,
        signature=signature,
        public_key=public_key,
    )


def verify_checkpoint(
    checkpoint: SignedCheckpoint,
    verify_key: nacl.signing.VerifyKey | None = None,
) -> bool:
    """
    Verify a signed checkpoint's integrity and signature.

    Args:
        checkpoint: Checkpoint to verify
        verify_key: Optional Ed25519 verification key. If not provided,
                   the public key embedded in the checkpoint is used.

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

        # Verify signature
        if verify_key is None:
            verify_key = nacl.signing.VerifyKey(bytes.fromhex(checkpoint.public_key))

        checkpoint_hash_bytes = bytes.fromhex(checkpoint.checkpoint_hash)
        signature_bytes = bytes.fromhex(checkpoint.signature)
        verify_key.verify(checkpoint_hash_bytes, signature_bytes)

        return True
    except Exception:
        return False


def verify_checkpoint_chain(checkpoints: list[SignedCheckpoint]) -> bool:
    """
    Verify the integrity of a chain of checkpoints.

    This verifies:
    1. Each checkpoint is individually valid
    2. Sequences are monotonically increasing
    3. Each checkpoint correctly references the previous checkpoint hash
    4. Ledger heights are monotonically increasing

    Args:
        checkpoints: List of checkpoints in chronological order

    Returns:
        True if the entire chain is valid, False otherwise
    """
    if not checkpoints:
        return True

    # Verify genesis checkpoint
    if checkpoints[0].previous_checkpoint_hash != "":
        return False
    if checkpoints[0].consistency_proof:
        return False

    for i, checkpoint in enumerate(checkpoints):
        # Verify individual checkpoint
        if not verify_checkpoint(checkpoint):
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
            except Exception:
                return False

            if not verify_consistency_proof(
                previous_root,
                current_root,
                proof_bytes,
                checkpoints[i - 1].ledger_height,
                checkpoint.ledger_height,
            ):
                return False
        elif checkpoint.consistency_proof:
            # A genesis checkpoint must not carry a consistency proof
            return False

    return True


def detect_checkpoint_fork(
    checkpoint_a: SignedCheckpoint,
    checkpoint_b: SignedCheckpoint,
) -> bool:
    """
    Detect if two checkpoints represent a fork in the ledger.

    A fork is detected when two checkpoints have:
    1. The same sequence number, OR
    2. The same previous_checkpoint_hash but different checkpoint_hash

    Args:
        checkpoint_a: First checkpoint
        checkpoint_b: Second checkpoint

    Returns:
        True if a fork is detected, False otherwise
    """
    # Same sequence but different content = fork
    if checkpoint_a.sequence == checkpoint_b.sequence:
        return checkpoint_a.checkpoint_hash != checkpoint_b.checkpoint_hash

    # Same parent but different checkpoints = fork
    if (
        checkpoint_a.previous_checkpoint_hash
        and checkpoint_a.previous_checkpoint_hash == checkpoint_b.previous_checkpoint_hash
    ):
        return checkpoint_a.checkpoint_hash != checkpoint_b.checkpoint_hash

    return False


class CheckpointRegistry:
    """
    Registry for storing and verifying checkpoint chains.

    This class provides an in-memory store for checkpoints with methods
    to verify chain integrity and detect forks.
    """

    def __init__(self) -> None:
        """Initialize an empty checkpoint registry."""
        self.checkpoints: list[SignedCheckpoint] = []

    def add_checkpoint(self, checkpoint: SignedCheckpoint) -> bool:
        """
        Add a checkpoint to the registry.

        Args:
            checkpoint: Checkpoint to add

        Returns:
            True if checkpoint was added successfully, False if invalid

        Raises:
            ValueError: If checkpoint would create a fork
        """
        # Verify checkpoint is valid
        if not verify_checkpoint(checkpoint):
            return False

        # Check for forks
        for existing in self.checkpoints:
            if detect_checkpoint_fork(checkpoint, existing):
                raise ValueError(
                    f"Fork detected: checkpoint {checkpoint.sequence} conflicts "
                    f"with existing checkpoint {existing.sequence}"
                )

        # Verify it links to the previous checkpoint
        if self.checkpoints:
            latest = self.checkpoints[-1]
            if checkpoint.sequence <= latest.sequence:
                # Allow out-of-order if it's filling a gap
                pass
            elif checkpoint.previous_checkpoint_hash != latest.checkpoint_hash:
                return False

        self.checkpoints.append(checkpoint)
        self.checkpoints.sort(key=lambda c: c.sequence)
        return True

    def verify_registry(self) -> bool:
        """
        Verify the entire checkpoint registry.

        Returns:
            True if all checkpoints form a valid chain
        """
        return verify_checkpoint_chain(self.checkpoints)

    def get_checkpoint(self, sequence: int) -> SignedCheckpoint | None:
        """
        Retrieve a checkpoint by sequence number.

        Args:
            sequence: Checkpoint sequence number

        Returns:
            Checkpoint if found, None otherwise
        """
        for checkpoint in self.checkpoints:
            if checkpoint.sequence == sequence:
                return checkpoint
        return None

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        """
        Get the most recent checkpoint.

        Returns:
            Latest checkpoint if registry is non-empty, None otherwise
        """
        return self.checkpoints[-1] if self.checkpoints else None

    def get_all_checkpoints(self) -> list[SignedCheckpoint]:
        """Get all checkpoints in chronological order."""
        return self.checkpoints.copy()
