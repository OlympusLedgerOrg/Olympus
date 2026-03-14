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
LEGACY_BYTES_PREFIX = b"OLY:LEGACY-BYTES:V1"
LEGACY_STRING_PREFIX = b"OLY:LEGACY-STRING:V1"
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
TREE_HEAD_PREFIX = b"OLY:TREE-HEAD:V1"
VRF_SELECTION_PREFIX = b"OLY:VRF-SELECTION:V1"
_VRF_COMMIT_REVEAL_PREFIX = b"OLY:VRF-COMMIT-REVEAL:V1"


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
    Compute Merkle root from leaf hashes using CT-style promotion.
    If an odd number of leaves, the lone node is promoted without hashing.

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
            if i + 1 < len(current_level):
                # Pair exists: hash left and right
                right = current_level[i + 1]
                next_level.append(node_hash(left, right))
            else:
                # CT-style promotion: lone node is promoted without hashing
                next_level.append(left)
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
    """Legacy raw-bytes hashing with explicit domain separation."""
    return blake3.blake3(LEGACY_BYTES_PREFIX + payload).digest()


def hash_string(text: str) -> bytes:
    """Legacy UTF-8 string hashing with explicit domain separation."""
    payload = text.encode("utf-8")
    return blake3.blake3(LEGACY_STRING_PREFIX + payload).digest()


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
        hash(concat(EVENT_PREFIX, "|", payload))

    Payload encoding (length-prefixed):
        - each field is encoded as: [4-byte big-endian length] || [UTF-8 bytes]
        - payload = [len(shard_id)]||shard_id || [len(header_hash)]||header_hash
          || [len(timestamp)]||timestamp

    Length-prefixing prevents field-injection collisions when ``|`` characters
    appear inside shard identifiers or other fields.

    Args:
        shard_id: Shard identifier
        header_hash: Hex-encoded header hash
        timestamp: ISO 8601 timestamp

    Returns:
        Hex-encoded event ID
    """
    fields = [shard_id, header_hash, timestamp]
    encoded_fields: list[bytes] = []
    for value in fields:
        field_bytes = value.encode("utf-8")
        # Prefix each field with its 4-byte big-endian length.
        encoded_fields.append(len(field_bytes).to_bytes(4, byteorder="big"))
        encoded_fields.append(field_bytes)

    payload = b"".join(encoded_fields)
    return blake3_hash([EVENT_PREFIX, _SEP, payload]).hex()


def create_dual_root_commitment(blake3_root: bytes, poseidon_root: bytes) -> bytes:
    """
    Create an atomic dual-root commitment binding a BLAKE3 and Poseidon Merkle root.

    This commitment is used as the primary entry hash for ledger entries that
    include both a BLAKE3 SMT root and a Poseidon Merkle root. It ensures that
    both roots are atomically bound together and cannot be swapped independently.

    Args:
        blake3_root: 32-byte BLAKE3 Merkle root (e.g., shard root from the SMT).
        poseidon_root: 32-byte Poseidon Merkle root encoded as a big-endian
            unsigned integer (BN128 field element).

    Returns:
        Length-prefixed, self-verifying commitment wire format:
        [2B len(blake3_root)][blake3_root][2B len(poseidon_root)][poseidon_root][32B binding_hash]

    Raises:
        ValueError: If either root is not exactly 32 bytes.
    """
    if len(blake3_root) != 32:
        raise ValueError(f"BLAKE3 root must be 32 bytes, got {len(blake3_root)}")
    if len(poseidon_root) != 32:
        raise ValueError(f"Poseidon root must be 32 bytes, got {len(poseidon_root)}")

    binding_hash = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])
    return b"".join(
        [
            len(blake3_root).to_bytes(2, byteorder="big"),
            blake3_root,
            len(poseidon_root).to_bytes(2, byteorder="big"),
            poseidon_root,
            binding_hash,
        ]
    )


def parse_dual_root_commitment(commitment: bytes) -> tuple[bytes, bytes]:
    """
    Parse a serialized dual-root commitment into its constituent roots.

    The serialized commitment is the length-prefixed wire format produced by
    :func:`create_dual_root_commitment`, which includes a binding hash so the
    payload is self-verifying.

    Args:
        commitment: Commitment wire format produced by :func:`create_dual_root_commitment`.

    Returns:
        Tuple of ``(blake3_root, poseidon_root)``, each exactly 32 bytes.

    Raises:
        ValueError: If ``commitment`` is malformed or fails integrity verification.
    """
    expected_length = 2 + 32 + 2 + 32 + 32
    if len(commitment) != expected_length:
        raise ValueError(f"Dual root commitment must be {expected_length} bytes, got {len(commitment)}")

    idx = 0
    blake3_len = int.from_bytes(commitment[idx : idx + 2], byteorder="big")
    idx += 2
    blake3_root = commitment[idx : idx + blake3_len]
    idx += blake3_len
    poseidon_len = int.from_bytes(commitment[idx : idx + 2], byteorder="big")
    idx += 2
    poseidon_root = commitment[idx : idx + poseidon_len]
    idx += poseidon_len
    binding_hash = commitment[idx:]

    if blake3_len != len(blake3_root) or poseidon_len != len(poseidon_root):
        raise ValueError("Dual root commitment length metadata is invalid")
    if blake3_len != 32 or poseidon_len != 32 or len(binding_hash) != 32:
        raise ValueError("Dual root commitment length metadata is invalid")

    expected_binding_hash = blake3_hash([LEDGER_PREFIX, blake3_root, _SEP, poseidon_root])
    if binding_hash != expected_binding_hash:
        raise ValueError("tampered commitment")

    return blake3_root, poseidon_root


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
