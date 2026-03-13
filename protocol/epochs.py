"""
Epoch chaining and Signed Tree Head utilities for Olympus.

Epoch heads provide optional linkage across Merkle roots by hashing the
previous epoch head, the current Merkle root, and associated metadata hash
with a fixed separator for structural disambiguation.

Signed Tree Heads (STHs) add cryptographic accountability for a specific
epoch root by signing the epoch identifier, tree size, Merkle root, and
timestamp.
"""

from dataclasses import dataclass
from typing import Any

import nacl.exceptions
import nacl.signing

from .canonical_json import canonical_json_bytes
from .consistency import ConsistencyProof, verify_consistency_proof
from .hashes import HASH_SEPARATOR, TREE_HEAD_PREFIX, blake3_hash
from .timestamps import current_timestamp


_SEP = HASH_SEPARATOR.encode("utf-8")


def _normalize_hash(value: bytes | str, allow_empty: bool = False) -> bytes:
    """Normalize a hash input to raw bytes and validate length."""
    if isinstance(value, str):
        if value == "" and allow_empty:
            return b""
        try:
            hex_input = value
            value = bytes.fromhex(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid hex value: {hex_input}") from exc
    if not isinstance(value, bytes | bytearray):
        raise ValueError("Hash values must be bytes or hex strings")
    if len(value) == 0 and allow_empty:
        return bytes(value)
    if len(value) != 32:
        raise ValueError(f"Hash value must be 32 bytes, got {len(value)}")
    return bytes(value)


def compute_epoch_head(
    previous_head: bytes | str | None, merkle_root: bytes | str, metadata_hash: bytes | str
) -> bytes:
    """
    Compute the epoch head commitment.

    Args:
        previous_head: Previous epoch head (bytes or hex string). Use ``None`` or
            empty string for genesis.
        merkle_root: Current epoch Merkle root (bytes or hex string).
        metadata_hash: Hash of epoch metadata (bytes or hex string).

    Returns:
        32-byte BLAKE3 epoch head.
    """
    if previous_head is None or previous_head == "":
        prev = b""
    else:
        prev = _normalize_hash(previous_head, allow_empty=True)
    root_bytes = _normalize_hash(merkle_root)
    meta_bytes = _normalize_hash(metadata_hash)
    return blake3_hash([prev, _SEP, root_bytes, _SEP, meta_bytes])


@dataclass(frozen=True)
class EpochRecord:
    """
    Append-only epoch linkage record.

    Attributes:
        epoch_index: Monotonic epoch counter.
        merkle_root: Hex-encoded Merkle root for the epoch.
        metadata_hash: Hex-encoded hash of epoch metadata.
        previous_epoch_head: Hex-encoded previous epoch head (empty for genesis).
        epoch_head: Hex-encoded current epoch head.
    """

    epoch_index: int
    merkle_root: str
    metadata_hash: str
    previous_epoch_head: str
    epoch_head: str

    @classmethod
    def create(
        cls,
        *,
        epoch_index: int,
        merkle_root: bytes | str,
        metadata_hash: bytes | str,
        previous_epoch_head: bytes | str | None = None,
    ) -> "EpochRecord":
        """
        Build an :class:`EpochRecord` with validated inputs.

        Args:
            epoch_index: Monotonic epoch number (zero-based recommended).
            merkle_root: Merkle root for this epoch (bytes or hex string).
            metadata_hash: Hash of epoch metadata (bytes or hex string).
            previous_epoch_head: Previous epoch head (bytes, hex, or None for genesis).

        Returns:
            EpochRecord with computed epoch_head.

        Raises:
            ValueError: If inputs are invalid.
        """
        if epoch_index < 0:
            raise ValueError("epoch_index must be non-negative")

        root_bytes = _normalize_hash(merkle_root)
        metadata_bytes = _normalize_hash(metadata_hash)
        if previous_epoch_head is None or previous_epoch_head == "":
            prev_head_bytes = b""
        else:
            prev_head_bytes = _normalize_hash(previous_epoch_head, allow_empty=True)

        epoch_head = compute_epoch_head(prev_head_bytes, root_bytes, metadata_bytes)
        return cls(
            epoch_index=epoch_index,
            merkle_root=root_bytes.hex(),
            metadata_hash=metadata_bytes.hex(),
            previous_epoch_head=prev_head_bytes.hex(),
            epoch_head=epoch_head.hex(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a dictionary."""
        return {
            "epoch_index": self.epoch_index,
            "merkle_root": self.merkle_root,
            "metadata_hash": self.metadata_hash,
            "previous_epoch_head": self.previous_epoch_head,
            "epoch_head": self.epoch_head,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EpochRecord":
        """Deserialize an EpochRecord from a dictionary."""
        return cls(
            epoch_index=int(data["epoch_index"]),
            merkle_root=data["merkle_root"],
            metadata_hash=data["metadata_hash"],
            previous_epoch_head=data.get("previous_epoch_head", ""),
            epoch_head=data["epoch_head"],
        )


def _build_tree_head_payload(
    *,
    epoch_id: int,
    tree_size: int,
    merkle_root: bytes | str,
    timestamp: str,
) -> dict[str, Any]:
    """Build the canonical Signed Tree Head payload."""
    if epoch_id < 0:
        raise ValueError("epoch_id must be non-negative")
    if tree_size < 0:
        raise ValueError("tree_size must be non-negative")
    root_bytes = _normalize_hash(merkle_root)
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("timestamp must be a non-empty string")
    return {
        "epoch_id": epoch_id,
        "tree_size": tree_size,
        "merkle_root": root_bytes.hex(),
        "timestamp": timestamp,
    }


def signed_tree_head_hash(
    *,
    epoch_id: int,
    tree_size: int,
    merkle_root: bytes | str,
    timestamp: str,
) -> bytes:
    """Return the domain-separated BLAKE3 hash of a Signed Tree Head payload."""
    payload = _build_tree_head_payload(
        epoch_id=epoch_id,
        tree_size=tree_size,
        merkle_root=merkle_root,
        timestamp=timestamp,
    )
    return blake3_hash([TREE_HEAD_PREFIX, canonical_json_bytes(payload)])


@dataclass(frozen=True)
class SignedTreeHead:
    """Signed commitment to an epoch root and tree size.

    Attributes:
        epoch_id: Monotonic epoch identifier.
        tree_size: Number of leaves committed by ``merkle_root``.
        merkle_root: Hex-encoded Merkle root for the epoch.
        timestamp: ISO 8601 creation timestamp.
        signature: Hex-encoded Ed25519 signature over the STH payload hash.
        signer_pubkey: Hex-encoded Ed25519 public key used to verify ``signature``.
    """

    epoch_id: int
    tree_size: int
    merkle_root: str
    timestamp: str
    signature: str
    signer_pubkey: str

    @classmethod
    def create(
        cls,
        *,
        epoch_id: int,
        tree_size: int,
        merkle_root: bytes | str,
        signing_key: nacl.signing.SigningKey,
        timestamp: str | None = None,
    ) -> "SignedTreeHead":
        """Build and sign a Signed Tree Head."""
        normalized_timestamp = timestamp or current_timestamp()
        payload = _build_tree_head_payload(
            epoch_id=epoch_id,
            tree_size=tree_size,
            merkle_root=merkle_root,
            timestamp=normalized_timestamp,
        )
        payload_hash = blake3_hash([TREE_HEAD_PREFIX, canonical_json_bytes(payload)])
        return cls(
            epoch_id=payload["epoch_id"],
            tree_size=payload["tree_size"],
            merkle_root=payload["merkle_root"],
            timestamp=normalized_timestamp,
            signature=signing_key.sign(payload_hash).signature.hex(),
            signer_pubkey=signing_key.verify_key.encode().hex(),
        )

    def payload_hash(self) -> bytes:
        """Return the BLAKE3 hash of this Signed Tree Head payload."""
        return signed_tree_head_hash(
            epoch_id=self.epoch_id,
            tree_size=self.tree_size,
            merkle_root=self.merkle_root,
            timestamp=self.timestamp,
        )

    def verify(self) -> bool:
        """Verify the Signed Tree Head signature and payload encoding."""
        try:
            verify_key = nacl.signing.VerifyKey(bytes.fromhex(self.signer_pubkey))
            verify_key.verify(self.payload_hash(), bytes.fromhex(self.signature))
        except (ValueError, nacl.exceptions.BadSignatureError):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize the Signed Tree Head to a dictionary."""
        return {
            "epoch_id": self.epoch_id,
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "signer_pubkey": self.signer_pubkey,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedTreeHead":
        """Deserialize a Signed Tree Head from a dictionary."""
        return cls(
            epoch_id=int(data["epoch_id"]),
            tree_size=int(data["tree_size"]),
            merkle_root=data["merkle_root"],
            timestamp=data["timestamp"],
            signature=data["signature"],
            signer_pubkey=data["signer_pubkey"],
        )


def verify_sth_consistency(
    old_sth: SignedTreeHead,
    new_sth: SignedTreeHead,
    proof: ConsistencyProof,
) -> bool:
    """
    Verify consistency between two Signed Tree Heads.

    This function ensures that:
    1. The new STH has a tree size >= old STH tree size (append-only)
    2. Both STH signatures are cryptographically valid
    3. The Merkle consistency proof between their roots is valid

    This allows observers to detect split-view logs by comparing STHs across
    different nodes or epochs. If two nodes serve different STHs for the same
    epoch, or if an STH is rolled back, this verification will fail.

    Args:
        old_sth: Earlier Signed Tree Head.
        new_sth: Later Signed Tree Head (must have tree_size >= old_sth.tree_size).
        proof: Merkle consistency proof linking the two roots.

    Returns:
        True if all checks pass and the STHs are consistent.

    Example:
        >>> import nacl.signing
        >>> from protocol.merkle import MerkleTree
        >>> from protocol.hashes import hash_bytes
        >>> from protocol.consistency import generate_consistency_proof
        >>>
        >>> # Create a signing key
        >>> signing_key = nacl.signing.SigningKey.generate()
        >>>
        >>> # Build two trees with append-only growth
        >>> leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        >>> old_tree = MerkleTree(leaves[:5])
        >>> new_tree = MerkleTree(leaves[:10])
        >>>
        >>> # Create STHs
        >>> old_sth = SignedTreeHead.create(
        ...     epoch_id=1, tree_size=5, merkle_root=old_tree.get_root(),
        ...     signing_key=signing_key
        ... )
        >>> new_sth = SignedTreeHead.create(
        ...     epoch_id=2, tree_size=10, merkle_root=new_tree.get_root(),
        ...     signing_key=signing_key
        ... )
        >>>
        >>> # Generate and verify consistency proof
        >>> proof = generate_consistency_proof(5, 10, new_tree)
        >>> verify_sth_consistency(old_sth, new_sth, proof)
        True
    """
    # Rule 1: new_sth.tree_size >= old_sth.tree_size
    if new_sth.tree_size < old_sth.tree_size:
        return False

    # Rule 2: Verify both STH signatures
    if not old_sth.verify():
        return False
    if not new_sth.verify():
        return False

    # Rule 3: Verify Merkle consistency between their roots
    old_root = bytes.fromhex(old_sth.merkle_root)
    new_root = bytes.fromhex(new_sth.merkle_root)

    # Validate that the proof sizes match the STH tree sizes
    if proof.old_tree_size != old_sth.tree_size:
        return False
    if proof.new_tree_size != new_sth.tree_size:
        return False

    return verify_consistency_proof(old_root, new_root, proof)
