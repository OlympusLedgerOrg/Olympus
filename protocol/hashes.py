"""
Cryptographic hash functions for Olympus

This module provides the canonical hash functions used throughout the Olympus protocol.
All hashes must be deterministic and collision-resistant.
"""

import hashlib
from typing import Union


# Hash field separator for structured data
HASH_SEPARATOR = "|"

# Hash domain separation prefixes - DO NOT CHANGE
# These prefixes are protocol-critical. Changing them breaks all historical proofs.
DOC_PREFIX = b"OLYMPUS_DOC_V1"
NS_PREFIX = b"OLYMPUS_NS_V1"
LEAF_PREFIX = b"OLYMPUS_LEAF_V1"
SHARD_PREFIX = b"OLYMPUS_SHARD_V1"
ANCHOR_PREFIX = b"OLYMPUS_ANCHOR_V1"


def hash_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of raw bytes.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        32-byte SHA-256 hash
    """
    return hashlib.sha256(data).digest()


def hash_string(data: str) -> bytes:
    """
    Compute SHA-256 hash of a UTF-8 string.
    
    Args:
        data: String to hash
        
    Returns:
        32-byte SHA-256 hash
    """
    return hash_bytes(data.encode('utf-8'))


def hash_hex(data: Union[bytes, str]) -> str:
    """
    Compute hash and return as hex string.
    
    Args:
        data: Bytes or string to hash
        
    Returns:
        64-character hex string
    """
    if isinstance(data, str):
        return hash_string(data).hex()
    return hash_bytes(data).hex()


def merkle_parent_hash(left: bytes, right: bytes) -> bytes:
    """
    Compute parent hash in Merkle tree.
    
    Args:
        left: Left child hash
        right: Right child hash
        
    Returns:
        Parent hash
    """
    return hash_bytes(left + right)
