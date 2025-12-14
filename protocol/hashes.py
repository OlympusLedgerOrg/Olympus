"""BLAKE3 hashing utilities with domain separation for Olympus."""

from typing import Iterable, List, Union
from blake3 import blake3
from .canonical import canonicalize_json

# Hash field separator for structured data (used in legacy ledger concatenation)
HASH_SEPARATOR = "|"

# Domain separation prefixes (frozen)
KEY_PREFIX = b"OLY:KEY:V1"
LEAF_PREFIX = b"OLY:LEAF:V1"
NODE_PREFIX = b"OLY:NODE:V1"
HDR_PREFIX = b"OLY:HDR:V1"
FOREST_PREFIX = b"OLY:FOREST:V1"
POLICY_PREFIX = b"OLY:POLICY:V1"


def _as_bytes(part: Union[str, bytes]) -> bytes:
    if isinstance(part, bytes):
        return part
    return str(part).encode("utf-8")


def blake3_hash(parts: Iterable[Union[str, bytes]]) -> bytes:
    """Compute BLAKE3 over concatenated parts."""
    h = blake3()
    for part in parts:
        h.update(_as_bytes(part))
    return h.digest()


def hash_bytes(data: bytes) -> bytes:
    """Hash raw bytes with BLAKE3."""
    return blake3_hash([data])


def hash_string(data: str) -> bytes:
    """Hash UTF-8 string with BLAKE3."""
    return blake3_hash([data.encode("utf-8")])


def hash_hex(data: Union[bytes, str]) -> str:
    """Hash input and return hex-encoded digest."""
    if isinstance(data, str):
        return hash_string(data).hex()
    return hash_bytes(data).hex()


def record_key(record_type: str, record_id: str, version: str) -> bytes:
    """Deterministic composite record key."""
    return blake3_hash([KEY_PREFIX, record_type, record_id, version])


def leaf_hash(key: bytes, value_hash: bytes) -> bytes:
    """Sparse Merkle leaf hash."""
    return blake3_hash([LEAF_PREFIX, key, value_hash])


def node_hash(left: bytes, right: bytes) -> bytes:
    """Sparse Merkle internal node hash."""
    return blake3_hash([NODE_PREFIX, left, right])


def merkle_root(leaves: List[bytes]) -> bytes:
    """Compute ordered Merkle root (duplication on odd)."""
    if not leaves:
        return blake3_hash([NODE_PREFIX, b"", b""])
    layer = leaves[:]
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            next_layer.append(node_hash(left, right))
        layer = next_layer
    return layer[0]


def shard_header_hash(header_fields: dict) -> bytes:
    """Hash canonical shard header fields."""
    return blake3_hash([HDR_PREFIX, canonicalize_json(header_fields)])


def forest_root(header_hashes: List[bytes]) -> bytes:
    """Compute global forest root over shard header hashes."""
    ordered = sorted(header_hashes)
    return blake3_hash([FOREST_PREFIX, merkle_root(ordered)])
