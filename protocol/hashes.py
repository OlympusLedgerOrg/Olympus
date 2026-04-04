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

import os
from typing import Any

import blake3

from .canonical_json import canonical_json_bytes


# ---------------------------------------------------------------------------
# Optional Rust acceleration — import from olympus_core.crypto if built,
# fall back to pure-Python implementations below when it is not present.
# ---------------------------------------------------------------------------
try:
    from olympus_core.crypto import (
        blake3_hash as _rust_blake3_hash,
        global_key as _rust_global_key,
        leaf_hash as _rust_leaf_hash,
        node_hash as _rust_node_hash,
        record_key as _rust_record_key,
    )

    _RUST_CRYPTO_AVAILABLE = True  # pragma: no cover — requires maturin build
except ImportError:
    _RUST_CRYPTO_AVAILABLE = False
    if os.getenv("OLYMPUS_REQUIRE_RUST", "").strip().lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError(
            "Rust crypto extension required by OLYMPUS_REQUIRE_RUST=1, "
            "but olympus_core.crypto could not be imported"
        ) from None


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
KEY_ROTATION_PREFIX = b"OLY:KEY-ROTATION:V1"
LEAF_PREFIX = b"OLY:LEAF:V1"
NODE_PREFIX = b"OLY:NODE:V1"
HDR_PREFIX = b"OLY:HDR:V1"
POLICY_PREFIX = b"OLY:POLICY:V1"
LEDGER_PREFIX = b"OLY:LEDGER:V1"
FEDERATION_PREFIX = b"OLY:FEDERATION:V1"
EVENT_PREFIX = b"OLY:EVENT:V1"
CHECKPOINT_PREFIX = b"OLY:CHECKPOINT:V1"
TREE_HEAD_PREFIX = b"OLY:TREE-HEAD:V1"
VRF_SELECTION_PREFIX = b"OLY:VRF-SELECTION:V1"
_VRF_COMMIT_REVEAL_PREFIX = b"OLY:VRF-COMMIT-REVEAL:V1"
ANCHOR_PREFIX = b"OLY:ANCHOR:V1"
ATTESTATION_PREFIX = b"OLY:ATTESTATION:V1"
DATASET_PREFIX = b"OLY:DATASET:V1"
DATASET_COMMIT_PREFIX = b"OLY:DATASET-COMMIT:V1"
DATASET_LINEAGE_PREFIX = b"OLY:DATASET-LINEAGE:V1"
GLOBAL_KEY_PREFIX = b"OLY:GLOBAL-KEY:V1"
EVENT_ID_FIELD_NAMES = ("shard_id", "header_hash", "timestamp")
MAX_EVENT_ID_FIELD_LENGTH = (1 << 32) - 1
_MAX_LENGTH_PREFIXED_FIELD_SIZE = (1 << 32) - 1
_GLOBAL_SMT_KEY_CONTEXT = "olympus 2025-12 global-smt-leaf-key"


def blake3_hash(parts: list[bytes]) -> bytes:
    """
    Compute BLAKE3 hash with deterministic concatenation.

    Args:
        parts: List of byte strings to hash together

    Returns:
        32-byte BLAKE3 hash
    """
    if _RUST_CRYPTO_AVAILABLE:  # pragma: no cover — Rust FFI path
        result: bytes = _rust_blake3_hash(parts)
        return result
    return blake3.blake3(b"".join(parts)).digest()


def _length_prefixed_bytes(field_name: str, value: bytes) -> bytes:
    """Encode variable-length bytes with a 4-byte big-endian length prefix."""
    if len(value) > _MAX_LENGTH_PREFIXED_FIELD_SIZE:
        raise ValueError(f"{field_name} exceeds maximum length")  # pragma: no cover — 4 GB alloc
    return len(value).to_bytes(4, "big") + value


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
    if version < 0:
        raise ValueError(f"version must be non-negative, got {version}")
    if version > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("version exceeds maximum supported value")

    if _RUST_CRYPTO_AVAILABLE:  # pragma: no cover — Rust FFI path
        result: bytes = _rust_record_key(record_type, record_id, version)
        return result

    key_data = b"".join(
        [
            KEY_PREFIX,
            _length_prefixed_bytes("record_type", record_type.encode("utf-8")),
            _length_prefixed_bytes("record_id", record_id.encode("utf-8")),
            version.to_bytes(8, "big"),
        ]
    )
    return blake3.blake3(key_data).digest()


# BLAKE3 derive_key mode bakes the domain into the hash state, so no separator is
# needed; length prefixes commit the shard / record field boundaries explicitly.
def global_key(shard_id: str, record_key_bytes: bytes) -> bytes:
    """
    Generate a global SMT key for CD-HS-ST (Constant-Depth Hierarchical Sparse Tree).

    This function implements hierarchical key derivation that encodes shard identity into the
    global SMT key space, enabling a single SMT to replace separate per-shard SMTs and forest SMTs.

    The key derivation uses explicit domain separation with the shard_id and record key to ensure:
    - Cryptographic isolation between shards
    - Deterministic mapping from (shard_id, record_key) -> global_key
    - No collisions between different shards

    Args:
        shard_id: Shard identifier (e.g., "watauga:2025:budget")
        record_key_bytes: Record key bytes, typically the 32-byte output from record_key()

    Returns:
        32-byte global SMT key

    Example:
        >>> rec_key = record_key("document", "doc123", 1)
        >>> g_key = global_key("watauga:2025:budget", rec_key)
    """
    if _RUST_CRYPTO_AVAILABLE:  # pragma: no cover — Rust FFI path
        result: bytes = _rust_global_key(shard_id, record_key_bytes)
        return result

    shard_bytes = shard_id.encode("utf-8")
    key_material = b"".join(
        [
            _length_prefixed_bytes("shard_id", shard_bytes),
            _length_prefixed_bytes("record_key", record_key_bytes),
        ]
    )
    # Use BLAKE3 derive_key mode so the domain is fixed in the hash state itself.
    # The length prefixes commit the field boundaries, so there is no separator to collide with.
    result = blake3.blake3(
        key_material,
        derive_key_context=_GLOBAL_SMT_KEY_CONTEXT,
    ).digest()
    if len(result) != 32:  # pragma: no cover — BLAKE3 always produces 32 bytes
        raise ValueError(f"BLAKE3 derive_key returned {len(result)} bytes, expected 32")
    return result


def leaf_hash(key: bytes, value_hash: bytes) -> bytes:
    """Compute hash of a sparse-tree leaf with domain separation."""
    if _RUST_CRYPTO_AVAILABLE:  # pragma: no cover — Rust FFI path
        result: bytes = _rust_leaf_hash(key, value_hash)
        return result
    return blake3_hash([LEAF_PREFIX, _SEP, key, _SEP, value_hash])


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute hash of an internal Merkle node."""
    if _RUST_CRYPTO_AVAILABLE:  # pragma: no cover — Rust FFI path
        result: bytes = _rust_node_hash(left, right)
        return result
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

    Uses domain-separated hashing with ``OLY:FIELD-ELEMENT:V1`` prefix to
    ensure the mapping is context-specific and non-invertible across domains.

    Args:
        seed: Raw bytes to hash.

    Returns:
        Decimal string representation of the field element (required by snarkjs).
    """
    tagged = blake3.blake3(b"OLY:FIELD-ELEMENT:V1" + seed).digest()
    big_int = int.from_bytes(tagged, byteorder="big")
    field_element = big_int % SNARK_SCALAR_FIELD
    return str(field_element)


def event_id(shard_id: str, header_hash: str, timestamp: str) -> str:
    """
    Compute a deterministic event ID for a shard header event.

    The event ID binds a federation signature to a specific shard header
    commitment using domain separation. It is computed as:
        hash(concat(EVENT_PREFIX, "|", payload))

    Payload encoding (length-prefixed):
        - each field is encoded as: [4-byte big-endian length] followed by UTF-8 bytes
        - payload concatenates the length-prefixed shard_id, header_hash, and timestamp in order

    Length-prefixing prevents field-injection collisions when ``|`` characters
    appear inside shard identifiers or other fields.

    Args:
        shard_id: Shard identifier
        header_hash: Hex-encoded header hash
        timestamp: ISO 8601 timestamp

    Returns:
        Hex-encoded event ID
    """
    field_values = (shard_id, header_hash, timestamp)
    encoded_fields: list[bytes] = []
    for field_name, value in zip(EVENT_ID_FIELD_NAMES, field_values):
        field_bytes = value.encode("utf-8")
        if len(field_bytes) > MAX_EVENT_ID_FIELD_LENGTH:
            raise ValueError(
                f"event_id field '{field_name}' length {len(field_bytes)} exceeds 4-byte limit "
                f"{MAX_EVENT_ID_FIELD_LENGTH}"
            )
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
        raise ValueError(
            f"Dual root commitment must be {expected_length} bytes, got {len(commitment)}"
        )

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

    if blake3_len != len(blake3_root) or poseidon_len != len(
        poseidon_root
    ):  # pragma: no cover — guarded by overall length check
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


# ---------------------------------------------------------------------------
# Dataset provenance (ADR-0010)
# ---------------------------------------------------------------------------


def dataset_key(
    dataset_name: str,
    source_uri: str,
    canonical_namespace: str,
    committer_pubkey: str,
) -> str:
    """Deterministic dataset identity.

    ``canonical_namespace`` scopes identity to prevent collisions across orgs.
    ``committer_pubkey`` further scopes identity so two orgs using the same
    namespace and dataset name never collide.

    Examples: ``"commoncrawl.org"``, ``"huggingface.co/datasets"``,
    ``"internal.acme.com"``.

    Args:
        dataset_name: Human-readable dataset name.
        source_uri: Origin URI of the dataset.
        canonical_namespace: Namespace scoping identity.
        committer_pubkey: Ed25519 public key (hex) of the committer.

    Returns:
        64-character hex-encoded BLAKE3 hash.
    """
    key_data = b"".join(
        [
            _length_prefixed_bytes("canonical_namespace", canonical_namespace.encode("utf-8")),
            _length_prefixed_bytes("source_uri", source_uri.encode("utf-8")),
            _length_prefixed_bytes("dataset_name", dataset_name.encode("utf-8")),
            _length_prefixed_bytes("committer_pubkey", committer_pubkey.encode("utf-8")),
        ]
    )
    return blake3_hash([DATASET_PREFIX, key_data]).hex()


def compute_dataset_commit_id(
    dataset_id: str,
    parent_commit_id: str,
    manifest_hash: str,
    committer_pubkey: str,
) -> str:
    """Deterministic commit ID — reproducible by any verifier.

    Identity is derived from **content only**; timestamp is attested
    separately via RFC 3161.  This prevents clock skew from changing
    the commit identity.

    Args:
        dataset_id: Hex-encoded logical dataset identity.
        parent_commit_id: Previous commit hash (empty string for genesis).
        manifest_hash: BLAKE3 hex of the canonical manifest JSON.
        committer_pubkey: Ed25519 public key (hex).

    Returns:
        64-character hex-encoded BLAKE3 hash.
    """
    key_data = b"".join(
        [
            _length_prefixed_bytes("dataset_id", dataset_id.encode("utf-8")),
            _length_prefixed_bytes("parent_commit_id", parent_commit_id.encode("utf-8")),
            _length_prefixed_bytes("manifest_hash", manifest_hash.encode("utf-8")),
            _length_prefixed_bytes("committer_pubkey", committer_pubkey.encode("utf-8")),
        ]
    )
    return blake3_hash([DATASET_COMMIT_PREFIX, key_data]).hex()
