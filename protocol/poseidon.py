"""
Poseidon hash function for BN254/BN128 curve - Rust-backed implementation.

This module provides Python bindings to the Rust Poseidon implementation
in olympus_core. The Rust implementation is mandatory - there is no Python
fallback.

Usage:
    from protocol.poseidon import poseidon_hash, poseidon_leaf_hash, poseidon_node_hash
"""

from olympus_core.poseidon import (
    bytes_to_field_element,
    get_bn254_scalar_field,
    poseidon_hash_bn254_bigint as _poseidon_hash_bigint,
    poseidon_leaf_hash_bn254 as _poseidon_leaf_hash,
    poseidon_node_hash_bn254 as _poseidon_node_hash,
)


# Re-export the BN254 scalar field modulus
SNARK_SCALAR_FIELD = int(get_bn254_scalar_field())

# Domain separation constants (must match Rust implementation)
POSEIDON_DOMAIN_LEAF = 0
POSEIDON_DOMAIN_NODE = 1


def poseidon_hash(a: int, b: int) -> int:
    """Compute Poseidon hash of two field elements.

    Args:
        a: First field element (integer)
        b: Second field element (integer)

    Returns:
        Hash result as integer in BN254 scalar field
    """
    result = _poseidon_hash_bigint(str(a), str(b))
    return int(result)


def poseidon_hash_bn128(a: int, b: int) -> int:
    """Alias for poseidon_hash for backward compatibility."""
    return poseidon_hash(a, b)


def poseidon_leaf_hash(key: int, value: int) -> int:
    """Compute domain-separated Poseidon leaf hash.

    Computes: Poseidon(Poseidon(DOMAIN_LEAF, key), value)

    Args:
        key: Leaf key as field element
        value: Leaf value as field element

    Returns:
        Leaf hash as integer
    """
    result = _poseidon_leaf_hash(str(key), str(value))
    return int(result)


def poseidon_node_hash(left: int, right: int) -> int:
    """Compute domain-separated Poseidon node hash.

    Computes: Poseidon(Poseidon(DOMAIN_NODE, left), right)

    Args:
        left: Left child hash as field element
        right: Right child hash as field element

    Returns:
        Node hash as integer
    """
    result = _poseidon_node_hash(str(left), str(right))
    return int(result)


def value_hash_to_field(value_hash: bytes) -> int:
    """Convert a 32-byte value hash to a BN254 field element.

    Applies modular reduction by the BN254 scalar field prime.

    Args:
        value_hash: 32-byte hash value

    Returns:
        Field element as integer
    """
    if len(value_hash) != 32:
        raise ValueError(f"value_hash must be 32 bytes, got {len(value_hash)}")
    result = bytes_to_field_element(value_hash)
    return int(result)


# Alias for backward compatibility with api/ingest.py
value_hash_to_poseidon_field = value_hash_to_field


def resolved_poseidon_root(persisted_root: str | None, fallback_root: str) -> str:
    """Resolve persisted Poseidon root with a deterministic fallback.

    Args:
        persisted_root: Persisted root value (may be None)
        fallback_root: Fallback root value to use if persisted is None

    Returns:
        The resolved root as a string
    """
    return persisted_root if persisted_root is not None else fallback_root


__all__ = [
    "SNARK_SCALAR_FIELD",
    "POSEIDON_DOMAIN_LEAF",
    "POSEIDON_DOMAIN_NODE",
    "poseidon_hash",
    "poseidon_hash_bn128",
    "poseidon_leaf_hash",
    "poseidon_node_hash",
    "value_hash_to_field",
    "value_hash_to_poseidon_field",
    "resolved_poseidon_root",
]
