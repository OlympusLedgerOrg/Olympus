"""
Cryptographic hash functions for Olympus

This module provides the canonical hash functions used throughout the Olympus protocol.
All hashes must be deterministic and collision-resistant.
Uses BLAKE3 for all cryptographic hashing.

Protocol notes:
- Federation vote hashing uses **length-prefixed encoding (V2)**: each UTF-8
  field is prefixed with its 4-byte big-endian length before hashing with
  ``FEDERATION_PREFIX``. This prevents field-injection collisions when fields
  contain literal ``|`` characters.
"""

import warnings
from typing import Any

import blake3

from .canonical_json import canonical_json_bytes


# BN128 scalar field prime (alt_bn128) used by Circom/snarkjs
SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Hash field separator for structured data
HASH_SEPARATOR = "|"
_SEP = HASH_SEPARATOR.encode("utf-8")

# Hash domain separation prefixes - DO NOT CHANGE
# These prefixes are protocol-critical. Changing them breaks all historical proofs.
KEY_PREFIX = b"OLY:KEY:V1"
LEAF_PREFIX = b"OLY:LEAF:V1"
NODE_PREFIX = b"OLY:NODE:V1"
HDR_PREFIX = b"OLY:HDR:V1"
FOREST_PREFIX = b"OLY:FOREST:V1"
POLICY_PREFIX = b"OLY:POLICY:V1"
LEDGER_PREFIX = b"OLY:LEDGER:V1"
FEDERATION_PREFIX = b"OLY:FEDERATION:V1"
EVENT_PREFIX = b"OLY:EVENT:V1"
CHECKPOINT_PREFIX = b"OLY:CHECKPOINT:V1"


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
    """Compute hash of a sparse-tree leaf with domain separation."""
    return blake3_hash([LEAF_PREFIX, _SEP, key, _SEP, value_hash])


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute hash of an internal Merkle node."""
    return blake3_hash([NODE_PREFIX, _SEP, left, _SEP, right])


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
    # Canonical JSON: sorted keys, compact separators, ASCII-escaped, NaN/Infinity rejected
    return blake3_hash([HDR_PREFIX, canonical_json_bytes(fields_dict)])


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
def hash_bytes(payload: bytes) -> bytes:
    return blake3.blake3(payload).digest()


def hash_string(text: str) -> bytes:
    return hash_bytes(text.encode("utf-8"))


def merkle_parent_hash(left: bytes, right: bytes) -> bytes:
    """
    Legacy: Compute parent hash in Merkle tree.
    This function is more lenient for backward compatibility.
    It accepts any byte strings, not just 32-byte hashes.

    Deprecated: will be removed in a future release (merkle_v2). Use
    :func:`node_hash` directly for domain-separated internal nodes.
    """
    warnings.warn(
        "merkle_parent_hash is deprecated and will be removed in merkle_v2; "
        "use node_hash(left, right) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    # For legacy compatibility, accept any byte strings
    # Hash them first if they're not already 32 bytes
    if len(left) != 32:
        left = hash_bytes(left)
    if len(right) != 32:
        right = hash_bytes(right)
    return node_hash(left, right)


def create_dual_root_commitment(blake3_root: bytes, poseidon_root: bytes) -> bytes:
    """
    Create an atomic commitment that binds a BLAKE3 Merkle root to a Poseidon Merkle root.

    Prevents verification attacks where valid proofs from different documents could be
    mixed by tying both roots together under a single BLAKE3 binding hash.  The returned
    bytes encode both roots and their binding hash so that
    :func:`parse_dual_root_commitment` can later extract and re-verify them.

    Format (binary)::

        [2-byte big-endian len(blake3_root)]
        [blake3_root bytes]
        [2-byte big-endian len(poseidon_root)]
        [poseidon_root bytes]
        [32-byte binding_hash]

    where ``binding_hash = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])``.

    Args:
        blake3_root: BLAKE3 Merkle root bytes (typically 32 bytes).
        poseidon_root: Poseidon Merkle root bytes (typically 32 bytes).

    Returns:
        Serialized commitment bytes containing both roots and the binding hash.

    Raises:
        ValueError: If either root is empty.
    """
    if not blake3_root:
        raise ValueError("blake3_root must not be empty")
    if not poseidon_root:
        raise ValueError("poseidon_root must not be empty")

    binding_hash = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])

    b3_len = len(blake3_root).to_bytes(2, byteorder="big")
    pos_len = len(poseidon_root).to_bytes(2, byteorder="big")

    return b3_len + blake3_root + pos_len + poseidon_root + binding_hash


def parse_dual_root_commitment(commitment: bytes) -> tuple[bytes, bytes]:
    """
    Parse a dual-root commitment to extract the BLAKE3 and Poseidon roots.

    Re-derives the binding hash from the extracted roots and compares it to the
    stored hash, ensuring the commitment has not been tampered with.

    Args:
        commitment: Bytes returned by :func:`create_dual_root_commitment`.

    Returns:
        Tuple of ``(blake3_root, poseidon_root)`` as originally supplied.

    Raises:
        ValueError: If the commitment is malformed or the binding hash is invalid.
    """
    # Minimum valid size: 2 (b3_len) + 1 (blake3_root) + 2 (pos_len) + 1 (poseidon_root) + 32 (hash)
    _MIN_SIZE = 2 + 1 + 2 + 1 + 32
    if len(commitment) < _MIN_SIZE:
        raise ValueError(
            f"Commitment too short: expected at least {_MIN_SIZE} bytes, got {len(commitment)}"
        )

    offset = 0

    # Extract blake3_root
    b3_len = int.from_bytes(commitment[offset : offset + 2], byteorder="big")
    offset += 2
    if b3_len == 0:
        raise ValueError("Commitment contains empty blake3_root")
    if offset + b3_len > len(commitment):
        raise ValueError("Commitment is malformed: blake3_root length exceeds available bytes")
    blake3_root = commitment[offset : offset + b3_len]
    offset += b3_len

    # Extract poseidon_root
    if offset + 2 > len(commitment):
        raise ValueError("Commitment is malformed: missing poseidon_root length")
    pos_len = int.from_bytes(commitment[offset : offset + 2], byteorder="big")
    offset += 2
    if pos_len == 0:
        raise ValueError("Commitment contains empty poseidon_root")
    if offset + pos_len > len(commitment):
        raise ValueError("Commitment is malformed: poseidon_root length exceeds available bytes")
    poseidon_root = commitment[offset : offset + pos_len]
    offset += pos_len

    # Extract and verify binding hash — must be exactly 32 bytes at the end
    if len(commitment) - offset != 32:
        raise ValueError("Commitment is malformed: unexpected trailing bytes after binding hash")
    stored_hash = commitment[offset:]

    expected_hash = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])
    if stored_hash != expected_hash:
        raise ValueError(
            "Commitment binding hash verification failed: commitment may be tampered with"
        )

    return blake3_root, poseidon_root


def blake3_to_field_element(seed: bytes) -> str:
    """
    Hash raw seed material with BLAKE3 and map it into the BN128 scalar field.

    Args:
        seed: Raw bytes to hash.

    Returns:
        Decimal string representation of the field element (required by snarkjs).
    """
    digest = blake3.blake3(seed).digest()
    big_int = int.from_bytes(digest, byteorder="big")
    field_element = big_int % SNARK_SCALAR_FIELD
    return str(field_element)


def event_id(shard_id: str, header_hash: str, timestamp: str) -> str:
    """
    Compute a deterministic event ID for a shard header event.

    The event ID binds a federation signature to a specific shard header
    commitment using domain separation. It is computed as:
        hash(EVENT_PREFIX || shard_id || "|" || header_hash || "|" || timestamp)

    Args:
        shard_id: Shard identifier
        header_hash: Hex-encoded header hash
        timestamp: ISO 8601 timestamp

    Returns:
        Hex-encoded event ID
    """
    event_data = HASH_SEPARATOR.join([shard_id, header_hash, timestamp])
    return blake3_hash([EVENT_PREFIX, _SEP, event_data.encode("utf-8")]).hex()


def federation_vote_hash(
    node_id: str,
    shard_id: str,
    header_hash: str,
    timestamp: str,
    event_id_hex: str,
) -> bytes:
    """
    Compute the hash that a federation node signs when voting on a shard header.

    Federation votes sign a structured payload that binds the signature to:
    - The federation protocol domain (FEDERATION_PREFIX)
    - The specific node making the vote (node_id)
    - The shard being voted on (shard_id)
    - The specific header commitment (header_hash)
    - The timestamp of the event (timestamp)
    - The unique event identifier (event_id)

    Encoding (version 2):
        - domain is always "olympus.federation.v1" for the current protocol version
        - each field is encoded as: [4-byte big-endian length] || [UTF-8 bytes]
        - payload = concat(fields)
        - vote_hash = blake3(FEDERATION_PREFIX || "|" || payload)

    Length-prefixing prevents field-injection collisions (e.g., literal "|" characters
    inside node_id or shard_id) while preserving deterministic, auditable encoding.

    Args:
        node_id: Federation node identifier
        shard_id: Shard identifier
        header_hash: Hex-encoded header hash
        timestamp: ISO 8601 timestamp
        event_id_hex: Hex-encoded event ID

    Returns:
        32-byte hash to be signed by the federation node
    """
    domain = "olympus.federation.v1"
    fields = [domain, node_id, shard_id, header_hash, timestamp, event_id_hex]
    encoded_fields = []
    for value in fields:
        field_bytes = value.encode("utf-8")
        encoded_fields.append(len(field_bytes).to_bytes(4, byteorder="big"))
        encoded_fields.append(field_bytes)

    payload = b"".join(encoded_fields)
    return blake3_hash([FEDERATION_PREFIX, _SEP, payload])
