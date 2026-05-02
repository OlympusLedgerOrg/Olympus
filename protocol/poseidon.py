"""
Poseidon hash function for BN254/BN128 curve - Rust-backed implementation.

This module provides Python bindings to the Rust Poseidon implementation
in olympus_core. The Rust implementation is mandatory - there is no Python
fallback.

The Rust implementation uses the exact same round constants and MDS matrix
as circomlibjs/src/poseidon_constants.json (t=3, nRoundsF=8, nRoundsP=57),
producing bit-for-bit identical outputs to circomlibjs and the circom
Poseidon circuit used by Olympus ZK redaction proofs.

Usage:
    from protocol.poseidon import poseidon_hash, poseidon_leaf_hash, poseidon_node_hash
"""

from typing import cast

from olympus_core.poseidon import (
    bytes_to_field_element,
    get_bn254_scalar_field,
    poseidon_hash_bn254 as _poseidon_hash,
    poseidon_leaf_hash_bn254 as _poseidon_leaf_hash,
    poseidon_node_hash_bn254 as _poseidon_node_hash,
)


# Re-export the BN254 scalar field modulus
SNARK_SCALAR_FIELD = int(get_bn254_scalar_field())

# Domain separation constants (must match Rust implementation)
POSEIDON_DOMAIN_LEAF = 0
POSEIDON_DOMAIN_NODE = 1

# The canonical identifier for the Poseidon hash suite used in all Olympus circuits.
# This constant is emitted in proof bundle metadata so verifiers can select
# the correct parameter set. MUST NOT be changed — see ADR-0009.
HASH_SUITE_VERSION: str = "poseidon-bn254-v1"

# Full parameter set for poseidon-bn254-v1 — pinned per ADR-0009.
# These values MUST match circomlibjs/src/poseidon_constants.json exactly.
POSEIDON_PARAMS: dict = {
    "suite_id": "poseidon-bn254-v1",
    "curve": "BN254",
    "width": 3,          # t=3: capacity=1, rate=2
    "arity": 2,          # 2 inputs per hash call
    "n_rounds_f": 8,     # full rounds (4 before + 4 after partial)
    "n_rounds_p": 57,    # partial rounds
    "sbox_exponent": 5,  # x^5 mod p
    "field_modulus": 21888242871839275222246405745257275088548364400416034343698204186575808495617,
    "domain_tag_leaf": 0,
    "domain_tag_node": 1,
    "constants_source": "circomlibjs/src/poseidon_constants.json",
}


def poseidon_hash(a: int, b: int) -> int:
    """Compute Poseidon hash of two field elements.

    Args:
        a: First field element (integer)
        b: Second field element (integer)

    Returns:
        Hash result as integer in BN254 scalar field
    """
    return cast(int, _poseidon_hash(a, b))


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
    return cast(int, _poseidon_leaf_hash(key, value))


def poseidon_node_hash(left: int, right: int) -> int:
    """Compute domain-separated Poseidon node hash.

    Computes: Poseidon(Poseidon(DOMAIN_NODE, left), right)

    Args:
        left: Left child hash as field element
        right: Right child hash as field element

    Returns:
        Node hash as integer
    """
    return cast(int, _poseidon_node_hash(left, right))


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
    "HASH_SUITE_VERSION",
    "POSEIDON_PARAMS",
    "poseidon_hash",
    "poseidon_hash_bn128",
    "poseidon_leaf_hash",
    "poseidon_node_hash",
    "value_hash_to_field",
    "value_hash_to_poseidon_field",
    "resolved_poseidon_root",
]
