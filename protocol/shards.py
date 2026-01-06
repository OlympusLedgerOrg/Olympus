"""
Shard header protocol for Olympus

This module implements shard header hashing and signature verification.

Forest headers are NOT implemented in v1.0. The forest_root() function
in protocol.hashes provides the global root computation over shard headers,
but forest-level headers with signatures are deferred to Phase 1+.
"""

from dataclasses import asdict, dataclass
from typing import Any

import nacl.encoding
import nacl.signing

from .hashes import shard_header_hash


@dataclass
class ShardHeader:
    """
    Shard header structure for v1.0.
    
    A shard header represents a committed state of a single shard's
    Sparse Merkle Tree at a specific sequence number.
    """
    shard_id: str
    seq: int
    root_hash: str  # Hex-encoded 32-byte root
    header_hash: str  # Hex-encoded 32-byte header hash
    previous_header_hash: str  # Hex-encoded previous header hash (empty for genesis)
    timestamp: str  # ISO 8601 with Z suffix
    signature: str  # Hex-encoded Ed25519 signature
    pubkey: str  # Hex-encoded Ed25519 public key

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ShardHeader':
        """Create from dictionary."""
        return cls(**data)


def create_shard_header(
    shard_id: str,
    root_hash: bytes,
    timestamp: str,
    previous_header_hash: str = ""
) -> dict[str, Any]:
    """
    Create a shard header dictionary.

    Args:
        shard_id: Identifier for the shard
        root_hash: 32-byte root hash of the shard's sparse Merkle tree
        timestamp: ISO 8601 timestamp
        previous_header_hash: Hex-encoded hash of previous header (empty for genesis)

    Returns:
        Dictionary containing shard header fields
    """
    if len(root_hash) != 32:
        raise ValueError(f"Root hash must be 32 bytes, got {len(root_hash)}")

    header = {
        "shard_id": shard_id,
        "root_hash": root_hash.hex(),
        "timestamp": timestamp,
        "previous_header_hash": previous_header_hash
    }

    # Compute header hash
    header["header_hash"] = shard_header_hash(
        {k: v for k, v in header.items() if k != "header_hash"}
    ).hex()

    return header


def sign_header(header: dict[str, Any], signing_key: nacl.signing.SigningKey) -> str:
    """
    Sign a shard header with Ed25519.

    Args:
        header: Shard header dictionary
        signing_key: Ed25519 signing key

    Returns:
        Hex-encoded signature
    """
    # Sign the header hash
    header_hash_bytes = bytes.fromhex(header["header_hash"])
    signed = signing_key.sign(header_hash_bytes)
    return signed.signature.hex()


def verify_header(
    header: dict[str, Any],
    signature: str,
    verify_key: nacl.signing.VerifyKey
) -> bool:
    """
    Verify a shard header's hash and Ed25519 signature.

    Args:
        header: Shard header dictionary
        signature: Hex-encoded Ed25519 signature
        verify_key: Ed25519 verification key

    Returns:
        True if header hash is correct and signature is valid
    """
    # Verify header hash
    header_without_hash = {k: v for k, v in header.items() if k not in ["header_hash", "signature"]}
    expected_hash = shard_header_hash(header_without_hash).hex()

    if header.get("header_hash") != expected_hash:
        return False

    # Verify signature
    try:
        header_hash_bytes = bytes.fromhex(header["header_hash"])
        signature_bytes = bytes.fromhex(signature)
        verify_key.verify(header_hash_bytes, signature_bytes)
        return True
    except Exception:
        return False


def get_signing_key_from_seed(seed: bytes) -> nacl.signing.SigningKey:
    """
    Get Ed25519 signing key from a 32-byte seed.

    Args:
        seed: 32-byte seed for deterministic key generation

    Returns:
        Ed25519 signing key
    """
    if len(seed) != 32:
        raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
    return nacl.signing.SigningKey(seed)


def get_verify_key_from_signing_key(signing_key: nacl.signing.SigningKey) -> nacl.signing.VerifyKey:
    """
    Get Ed25519 verification key from signing key.

    Args:
        signing_key: Ed25519 signing key

    Returns:
        Ed25519 verification key
    """
    return signing_key.verify_key
