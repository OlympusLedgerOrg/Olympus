"""
Shard header protocol for Olympus

This module implements shard header hashing and signature verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import nacl.encoding
import nacl.signing

from .hashes import shard_header_hash


if TYPE_CHECKING:
    from .rfc3161 import TimestampToken


def create_shard_header(
    shard_id: str,
    root_hash: bytes,
    timestamp: str,
    previous_header_hash: str = "",
    timestamp_token: TimestampToken | dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Create a shard header dictionary.

    Args:
        shard_id: Identifier for the shard
        root_hash: 32-byte root hash of the shard's sparse Merkle tree
        timestamp: ISO 8601 timestamp
        previous_header_hash: Hex-encoded hash of previous header (empty for genesis)
        timestamp_token: Optional RFC 3161 timestamp token for the header hash.
            If provided, the token's serialized form is included in the returned
            header under the ``"timestamp_token"`` key (not part of the hash
            commitment, since the token is obtained after hashing).

    Returns:
        Dictionary containing shard header fields
    """
    if len(root_hash) != 32:
        raise ValueError(f"Root hash must be 32 bytes, got {len(root_hash)}")

    header: dict[str, Any] = {
        "shard_id": shard_id,
        "root_hash": root_hash.hex(),
        "timestamp": timestamp,
        "previous_header_hash": previous_header_hash,
    }

    # Compute header hash
    header["header_hash"] = shard_header_hash(
        {k: v for k, v in header.items() if k != "header_hash"}
    ).hex()

    # Attach RFC 3161 timestamp token after hash commitment (not part of the hash)
    if timestamp_token is not None:
        header["timestamp_token"] = (
            timestamp_token.to_dict() if hasattr(timestamp_token, "to_dict") else timestamp_token
        )

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
    header: dict[str, Any], signature: str, verify_key: nacl.signing.VerifyKey
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
    header_without_hash = {
        k: v for k, v in header.items() if k not in ["header_hash", "signature", "timestamp_token"]
    }
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


def get_verify_key_from_signing_key(
    signing_key: nacl.signing.SigningKey,
) -> nacl.signing.VerifyKey:
    """
    Get Ed25519 verification key from signing key.

    Args:
        signing_key: Ed25519 signing key

    Returns:
        Ed25519 verification key
    """
    return signing_key.verify_key
