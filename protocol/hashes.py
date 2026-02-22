"""
Cryptographic hash functions for Olympus

This module provides the canonical hash functions used throughout the Olympus protocol.
All hashes must be deterministic and collision-resistant.
Uses BLAKE3 for all cryptographic hashing.
"""

import json
from typing import Any

import blake3


# BN128 scalar field prime (alt_bn128) used by Circom/snarkjs
SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Hash field separator for structured data
HASH_SEPARATOR = "|"

# Hash domain separation prefixes - DO NOT CHANGE
# These prefixes are protocol-critical. Changing them breaks all historical proofs.
KEY_PREFIX = b"OLY:KEY:V1"
LEAF_PREFIX = b"OLY:LEAF:V1"
NODE_PREFIX = b"OLY:NODE:V1"
HDR_PREFIX = b"OLY:HDR:V1"
FOREST_PREFIX = b"OLY:FOREST:V1"
POLICY_PREFIX = b"OLY:POLICY:V1"
LEDGER_PREFIX = b"OLY:LEDGER:V1"


def blake3_hash(parts: list[bytes]) -> bytes:
    """
    Compute BLAKE3 hash with deterministic concatenation.

    Args:
        parts: List of byte strings to hash together

    Returns:
        32-byte BLAKE3 hash
    """
    return blake3.blake3(b"".join(parts)).digest()


def record_key(record_type: str, record_id: str, version: int) -> bytes:
    """
    Generate a deterministic 32-byte key for a record.

    Args:
        record_type: Type of record (e.g., "document", "policy")
        record_id: Unique identifier for the record
        version: Version number of the record

    Returns:
        32-byte key using KEY_PREFIX domain separation
    """
    key_data = f"{record_type}:{record_id}:{version}".encode()
    return blake3_hash([KEY_PREFIX, key_data])


def leaf_hash(key: bytes, value_hash: bytes) -> bytes:
    """
    Compute hash of a leaf node in sparse Merkle tree.

    Args:
        key: 32-byte key
        value_hash: 32-byte hash of the value

    Returns:
        32-byte leaf hash using LEAF_PREFIX domain separation
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    if len(value_hash) != 32:
        raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")
    return blake3_hash([LEAF_PREFIX, key, value_hash])


def node_hash(left: bytes, right: bytes) -> bytes:
    """
    Compute hash of an internal node in Merkle tree.

    Args:
        left: 32-byte hash of left child
        right: 32-byte hash of right child

    Returns:
        32-byte node hash using NODE_PREFIX domain separation
    """
    if len(left) != 32:
        raise ValueError(f"Left hash must be 32 bytes, got {len(left)}")
    if len(right) != 32:
        raise ValueError(f"Right hash must be 32 bytes, got {len(right)}")
    return blake3_hash([NODE_PREFIX, left, right])


def merkle_root(leaves: list[bytes]) -> bytes:
    """
    Compute Merkle root from leaf hashes.
    Duplicates last leaf if odd number of leaves.

    Args:
        leaves: List of 32-byte leaf hashes

    Returns:
        32-byte Merkle root hash
    """
    if not leaves:
        raise ValueError("Cannot compute Merkle root of empty list")

    for leaf in leaves:
        if len(leaf) != 32:
            raise ValueError(f"All leaves must be 32 bytes, got {len(leaf)}")

    current_level = leaves[:]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # Duplicate last leaf if odd number
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            next_level.append(node_hash(left, right))
        current_level = next_level

    return current_level[0]


def shard_header_hash(fields_dict: dict[str, Any]) -> bytes:
    """
    Compute hash of a shard header using canonical JSON.

    Args:
        fields_dict: Dictionary of shard header fields

    Returns:
        32-byte shard header hash using HDR_PREFIX domain separation
    """
    # Canonical JSON: sorted keys, compact separators, UTF-8
    canonical_json = json.dumps(
        fields_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    canonical_bytes = canonical_json.encode("utf-8")
    return blake3_hash([HDR_PREFIX, canonical_bytes])


def forest_root(header_hashes: list[bytes]) -> bytes:
    """
    Compute global forest root from shard header hashes.

    Args:
        header_hashes: List of 32-byte shard header hashes

    Returns:
        32-byte forest root hash using FOREST_PREFIX domain separation
    """
    if not header_hashes:
        raise ValueError("Cannot compute forest root of empty list")

    for h in header_hashes:
        if len(h) != 32:
            raise ValueError(f"All header hashes must be 32 bytes, got {len(h)}")

    # Sort header hashes for determinism
    sorted_hashes = sorted(header_hashes)
    # Compute Merkle root of sorted hashes
    root = merkle_root(sorted_hashes)
    # Apply forest domain prefix
    return blake3_hash([FOREST_PREFIX, root])


# Legacy compatibility - these will be removed in future versions
# For now, keep them to avoid breaking existing code
def hash_bytes(data: bytes) -> bytes:
    """Legacy: Compute BLAKE3 hash of raw bytes."""
    return blake3.blake3(data).digest()


def hash_string(data: str) -> bytes:
    """Legacy: Compute BLAKE3 hash of a UTF-8 string."""
    return hash_bytes(data.encode("utf-8"))


def merkle_parent_hash(left: bytes, right: bytes) -> bytes:
    """
    Legacy: Compute parent hash in Merkle tree.
    This function is more lenient for backward compatibility.
    It accepts any byte strings, not just 32-byte hashes.
    """
    # For legacy compatibility, accept any byte strings
    # Hash them first if they're not already 32 bytes
    if len(left) != 32:
        left = hash_bytes(left)
    if len(right) != 32:
        right = hash_bytes(right)
    return node_hash(left, right)


def blake3_to_field_element(data: bytes) -> str:
    """
    Hash raw data with BLAKE3 and map it into the BN128 scalar field.

    Args:
        data: Raw bytes to hash.

    Returns:
        Decimal string representation of the field element (required by snarkjs).
    """
    digest = blake3.blake3(data).digest()
    big_int = int.from_bytes(digest, byteorder="big")
    field_element = big_int % SNARK_SCALAR_FIELD
    return str(field_element)
