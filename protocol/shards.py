"""
Shard header protocol for Olympus

This module implements shard header hashing and signature verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import nacl.encoding
import nacl.exceptions
import nacl.signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical_json import canonical_json_bytes
from .events import CanonicalEvent
from .hashes import HASH_SEPARATOR, hash_bytes, shard_header_hash


# Fields excluded from the canonical commitment bytes (derived or post-commitment metadata)
_HEADER_EXCLUDED_FIELDS: frozenset[str] = frozenset(
    {"header_hash", "signature", "timestamp_token", "quorum_certificate_hash"}
)

# HKDF domain separation constants for key derivation.
# salt provides domain separation from other HKDF usages; info labels bind
# each derived key to its specific purpose.  These values are protocol-critical:
# changing them will produce different keys for the same inputs.
#
# L5-A: _HKDF_SALT is now a 32-byte domain-separated constant for proper HKDF
# salt size alignment with BLAKE3/SHA-256 output lengths.
_HKDF_SALT_DOMAIN = b"olympus:hkdf:salt:v1"  # 20 bytes
_HKDF_SALT: bytes = _HKDF_SALT_DOMAIN + b"\x00" * (32 - len(_HKDF_SALT_DOMAIN))
if len(_HKDF_SALT) != 32:
    raise ValueError(f"_HKDF_SALT must be 32 bytes, got {len(_HKDF_SALT)}")

_HKDF_INFO_SEED_KEY: bytes = b"OLY:SEED-KEY:V1"
_HKDF_INFO_NODE_KEY: bytes = b"OLY:NODE-KEY:V1"
_HKDF_INFO_SHARD_SIGNING_KEY: bytes = b"OLY:SHARD-SIGNING-KEY:V1"


if TYPE_CHECKING:
    from .federation import FederationRegistry
    from .rfc3161 import TimestampToken


@dataclass(frozen=True)
class ShardNamespacePartitioner:
    """Deterministically map namespace strings to shard identifiers."""

    shard_count: int
    prefix: str = "shard"

    def __post_init__(self) -> None:
        if self.shard_count <= 0:
            raise ValueError("shard_count must be a positive integer")
        if not isinstance(self.prefix, str) or not self.prefix:
            raise ValueError("prefix must be a non-empty string")

    def shard_id_for_namespace(self, namespace: str) -> str:
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("namespace must be a non-empty string")
        payload = HASH_SEPARATOR.join([self.prefix, namespace]).encode("utf-8")
        digest = hash_bytes(payload)
        index = int.from_bytes(digest, byteorder="big") % self.shard_count
        return f"{self.prefix}-{index}"


def _hkdf_derive(ikm: bytes, info: bytes, length: int = 32) -> bytearray:
    """
    Derive key material using HKDF-SHA256 with Olympus domain separation.

    Uses ``_HKDF_SALT`` as a fixed salt shared by all Olympus HKDF usages;
    callers differentiate derivation contexts through the ``info`` label.

    Returns a mutable ``bytearray`` so callers can zero-fill the buffer after
    extracting the key material.

    Args:
        ikm: Input key material.
        info: Context-specific info label that binds the derived key to its use.
        length: Length in bytes of the derived output (default 32).

    Returns:
        Derived key material as a zeroisable ``bytearray``.
    """
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=_HKDF_SALT,
        info=info,
    ).derive(ikm)
    return bytearray(raw)


def canonical_header(header: dict[str, Any]) -> bytes:
    """
    Serialize the committed fields of a shard header to canonical JSON bytes.

    Produces a deterministic byte sequence suitable for hashing: keys are
    sorted alphabetically, separators are compact (no whitespace), and
    non-ASCII characters are ASCII-escaped.  Fields that are derived from
    or attached *after* the hash commitment (``header_hash``, ``signature``,
    ``timestamp_token``) are excluded so that the serialization is stable
    regardless of whether those fields are present.

    Args:
        header: Shard header dictionary.

    Returns:
        Canonical JSON bytes for the header commitment fields.
    """
    fields = {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
    return canonical_json_bytes(fields)


def create_shard_header(
    shard_id: str,
    root_hash: bytes,
    timestamp: str,
    height: int = 0,
    round_number: int = 0,
    tree_size: int | None = None,
    previous_header_hash: str = "",
    timestamp_token: TimestampToken | dict[str, str] | None = None,
    federation_registry: FederationRegistry | None = None,
) -> dict[str, Any]:
    """
    Create a shard header dictionary.

    Args:
        shard_id: Identifier for the shard
        root_hash: 32-byte root hash of the shard's sparse Merkle tree
        timestamp: ISO 8601 timestamp
        height: Consensus height for the shard header (non-negative integer)
        round_number: Consensus round for the shard header (non-negative integer)
        tree_size: Number of leaves committed by ``root_hash`` (non-negative integer)
        previous_header_hash: Hex-encoded hash of previous header (empty for genesis)
        timestamp_token: Optional RFC 3161 timestamp token for the header hash.
            If provided, the token's serialized form is included in the returned
            header under the ``"timestamp_token"`` key (not part of the hash
            commitment, since the token is obtained after hashing).
        federation_registry: Optional FederationRegistry for federation-bound headers.
            If provided, ``federation_epoch`` and ``membership_hash`` are included
            in the header commitment.

    Returns:
        Dictionary containing shard header fields
    """
    if len(root_hash) != 32:
        raise ValueError(f"Root hash must be 32 bytes, got {len(root_hash)}")
    try:
        normalized_height = int(height)
        normalized_round = int(round_number)
    except (TypeError, ValueError) as exc:
        raise ValueError("height and round_number must be integers") from exc
    if normalized_height < 0 or normalized_round < 0:
        raise ValueError("height and round_number must be non-negative")
    normalized_tree_size = 0 if tree_size is None else int(tree_size)
    if normalized_tree_size < 0:
        raise ValueError("tree_size must be non-negative")

    header: dict[str, Any] = {
        "shard_id": shard_id,
        "root_hash": root_hash.hex(),
        "timestamp": timestamp,
        "height": normalized_height,
        "round": normalized_round,
        "tree_size": normalized_tree_size,
        "previous_header_hash": previous_header_hash,
    }

    # Include federation fields if registry is provided (L3-A)
    if federation_registry is not None:
        header["federation_epoch"] = federation_registry.epoch
        header["membership_hash"] = federation_registry.membership_hash()

    # Compute header hash
    header["header_hash"] = shard_header_hash(
        {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
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
    header_without_hash = {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
    expected_hash = shard_header_hash(header_without_hash).hex()

    if header.get("header_hash") != expected_hash:
        return False

    # Verify signature
    try:
        header_hash_bytes = bytes.fromhex(header["header_hash"])
        signature_bytes = bytes.fromhex(signature)
        verify_key.verify(header_hash_bytes, signature_bytes)
        return True
    except (TypeError, ValueError, nacl.exceptions.BadSignatureError):
        return False


def _parse_timestamp(timestamp: str) -> datetime:
    """Parse an ISO 8601 timestamp that may use a ``Z`` suffix."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def _sign_rotation_payload(payload: dict[str, Any], signing_key: nacl.signing.SigningKey) -> str:
    """Sign a canonicalized rotation payload and return the hex signature."""
    payload_hash = hash_bytes(canonical_json_bytes(payload))
    return signing_key.sign(payload_hash).signature.hex()


def _verify_rotation_payload(
    payload: dict[str, Any], signature: str, verify_key: nacl.signing.VerifyKey
) -> bool:
    """Verify a canonicalized rotation payload signature."""
    try:
        payload_hash = hash_bytes(canonical_json_bytes(payload))
        verify_key.verify(payload_hash, bytes.fromhex(signature))
        return True
    except (TypeError, ValueError, nacl.exceptions.BadSignatureError):
        return False


def create_key_revocation_record(
    *,
    old_verify_key: nacl.signing.VerifyKey,
    new_signing_key: nacl.signing.SigningKey,
    compromise_timestamp: str,
    last_good_sequence: int,
    reason: str = "compromise",
) -> dict[str, Any]:
    """
    Create a signed Ed25519 key revocation record.

    The revocation record is signed by the replacement key and references the
    compromised public key, the effective compromise timestamp, and the last
    header sequence that verifiers may still accept from the old key.

    Args:
        old_verify_key: Compromised Ed25519 verification key.
        new_signing_key: Replacement Ed25519 signing key.
        compromise_timestamp: Effective compromise timestamp in ISO 8601 format.
        last_good_sequence: Last accepted shard header sequence signed by the old key.
        reason: Human-readable reason code for the rotation.

    Returns:
        Signed revocation record dictionary.
    """
    payload = {
        "event_type": "key_revocation",
        "old_pubkey": old_verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("ascii"),
        "new_pubkey": new_signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode(
            "ascii"
        ),
        "compromise_timestamp": compromise_timestamp,
        "last_good_sequence": last_good_sequence,
        "reason": reason,
    }
    return {
        **payload,
        "signature": _sign_rotation_payload(payload, new_signing_key),
    }


def verify_key_revocation_record(record: dict[str, Any]) -> bool:
    """
    Verify a signed Ed25519 key revocation record.

    Args:
        record: Revocation record produced by :func:`create_key_revocation_record`.

    Returns:
        ``True`` when the record is well-formed and the replacement key's
        signature is valid.
    """
    required_fields = {
        "event_type",
        "old_pubkey",
        "new_pubkey",
        "compromise_timestamp",
        "last_good_sequence",
        "reason",
        "signature",
    }
    if not required_fields.issubset(record):
        return False
    if record.get("event_type") != "key_revocation":
        return False
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(record["new_pubkey"]))
        _parse_timestamp(record["compromise_timestamp"])
        if int(record["last_good_sequence"]) < 0:
            return False
    except (TypeError, ValueError):
        return False
    payload = {key: record[key] for key in required_fields if key != "signature"}
    return _verify_rotation_payload(payload, record["signature"], verify_key)


def create_superseding_signature(
    *,
    header_hash: str,
    old_verify_key: nacl.signing.VerifyKey,
    new_signing_key: nacl.signing.SigningKey,
    supersedes_from: str,
) -> dict[str, Any]:
    """
    Create a signed superseding attestation for a historical shard header hash.

    Args:
        header_hash: Hex-encoded shard header hash being attested to.
        old_verify_key: Compromised Ed25519 verification key being superseded.
        new_signing_key: Replacement Ed25519 signing key.
        supersedes_from: Effective compromise timestamp or other audit marker
            carried forward from the rotation record.

    Returns:
        Signed superseding attestation dictionary.
    """
    payload = {
        "event_type": "superseding_signature",
        "header_hash": header_hash,
        "old_pubkey": old_verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("ascii"),
        "new_pubkey": new_signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode(
            "ascii"
        ),
        "supersedes_from": supersedes_from,
    }
    return {
        **payload,
        "signature": _sign_rotation_payload(payload, new_signing_key),
    }


def verify_superseding_signature(
    superseding_signature: dict[str, Any],
    *,
    header_hash: str,
    revocation_record: dict[str, Any],
) -> bool:
    """
    Verify a superseding Ed25519 attestation against a revocation record.

    Args:
        superseding_signature: Superseding attestation payload.
        header_hash: Hex-encoded shard header hash being attested to.
        revocation_record: Verified revocation record linking the old and new keys.

    Returns:
        ``True`` when the attestation is valid and matches the revocation record.
    """
    required_fields = {
        "event_type",
        "header_hash",
        "old_pubkey",
        "new_pubkey",
        "supersedes_from",
        "signature",
    }
    if not required_fields.issubset(superseding_signature):
        return False
    if superseding_signature.get("event_type") != "superseding_signature":
        return False
    if not verify_key_revocation_record(revocation_record):
        return False
    if superseding_signature.get("header_hash") != header_hash:
        return False
    if superseding_signature.get("old_pubkey") != revocation_record.get("old_pubkey"):
        return False
    if superseding_signature.get("new_pubkey") != revocation_record.get("new_pubkey"):
        return False
    if superseding_signature.get("supersedes_from") != revocation_record.get(
        "compromise_timestamp"
    ):
        return False
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(superseding_signature["new_pubkey"]))
    except (TypeError, ValueError):
        return False
    payload = {key: superseding_signature[key] for key in required_fields if key != "signature"}
    return _verify_rotation_payload(payload, superseding_signature["signature"], verify_key)


def verify_header_with_rotation(
    header: dict[str, Any],
    signature: str,
    verify_key: nacl.signing.VerifyKey,
    *,
    header_sequence: int | None = None,
    revocation_record: dict[str, Any] | None = None,
    superseding_signature: dict[str, Any] | None = None,
) -> bool:
    """
    Verify a shard header while enforcing key-rotation compromise rules.

    Args:
        header: Shard header dictionary.
        signature: Hex-encoded Ed25519 signature on the header hash.
        verify_key: Verification key corresponding to the supplied signature.
        header_sequence: Optional shard header sequence for compromise cutoff checks.
        revocation_record: Optional signed revocation record for the compromised key.
        superseding_signature: Optional signed attestation by the new key over the
            original header hash.

    Returns:
        ``True`` when the header is valid under the rotation policy.
    """
    if not verify_header(header, signature, verify_key):
        return False
    if revocation_record is None:
        return True
    if not verify_key_revocation_record(revocation_record):
        return False

    verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("ascii")
    old_pubkey = revocation_record["old_pubkey"]
    new_pubkey = revocation_record["new_pubkey"]
    if verify_key_hex == new_pubkey:
        return True
    if verify_key_hex != old_pubkey:
        return True

    header_timestamp = _parse_timestamp(header["timestamp"])
    compromise_timestamp = _parse_timestamp(revocation_record["compromise_timestamp"])
    post_compromise = header_timestamp >= compromise_timestamp
    if header_sequence is not None:
        post_compromise = post_compromise or header_sequence > int(
            revocation_record["last_good_sequence"]
        )
    if not post_compromise:
        return True
    if superseding_signature is None:
        return False
    return verify_superseding_signature(
        superseding_signature,
        header_hash=header["header_hash"],
        revocation_record=revocation_record,
    )


def rotation_record_to_event(
    record: dict[str, Any],
    schema_version: str = "olympus.key-rotation.v1",
    revocation_record: dict[str, Any] | None = None,
) -> CanonicalEvent:
    """
    Convert a verified key-rotation record into a canonical ledger event.

    Args:
        record: Signed key revocation or superseding signature payload.
        schema_version: Schema version to attach to the canonical event.
        revocation_record: Verified revocation record required when committing a
            superseding signature event.

    Returns:
        Canonical event suitable for append-only ledger commitment.

    Raises:
        ValueError: If the supplied record is not a supported, verified rotation payload.
    """
    event_type = record.get("event_type")
    if event_type == "key_revocation":
        if not verify_key_revocation_record(record):
            raise ValueError("Invalid key revocation record")
    elif event_type == "superseding_signature":
        if revocation_record is None:
            raise ValueError("Superseding signature events require revocation_record")
        if not verify_superseding_signature(
            record,
            header_hash=record.get("header_hash", ""),
            revocation_record=revocation_record,
        ):
            raise ValueError("Invalid superseding signature record")
    else:
        raise ValueError(f"Unsupported rotation event_type: {event_type}")
    return CanonicalEvent.from_raw(record, schema_version)


def get_signing_key_from_seed(seed: bytes) -> nacl.signing.SigningKey:
    """
    Derive an Ed25519 signing key from seed material using HKDF domain separation.

    Rather than using the raw seed bytes directly as Ed25519 key material, the
    seed is treated as HKDF input key material.  HKDF-SHA256 with the Olympus
    domain-separation salt and a purpose-specific info label is applied to
    produce the actual 32-byte key material.  This ensures that knowing the
    seed bytes does not directly expose the private key, and that keys derived
    here cannot be confused with keys derived for other purposes.

    The intermediate key material buffer is zeroed before returning.

    Args:
        seed: 32-byte seed for deterministic key generation.

    Returns:
        Ed25519 signing key derived from the seed via HKDF-SHA256.
    """
    if len(seed) != 32:
        raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
    key_material = _hkdf_derive(seed, _HKDF_INFO_SEED_KEY)
    try:
        return nacl.signing.SigningKey(bytes(key_material))
    finally:
        key_material[:] = b"\x00" * len(key_material)


def derive_scoped_signing_key(
    master_seed: bytes, shard_id: str, node_id: str | None = None
) -> nacl.signing.SigningKey:
    """
    Derive a shard- and node-scoped Ed25519 signing key from master seed material.

    Uses a two-level HKDF-SHA256 hierarchy for domain separation::

        master_seed  →(HKDF, info=OLY:NODE-KEY:V1\\x00<node_id>)→  node_key
        node_key     →(HKDF, info=OLY:SHARD-SIGNING-KEY:V1\\x00<shard_id>)→  shard_key

    When no ``node_id`` is provided the derivation collapses to a single HKDF
    step directly from ``master_seed`` to ``shard_key``.  Both levels use an
    explicit ``b"olympus"`` salt and encode the identifier into the HKDF info
    label via a null-byte separator to prevent key-label confusion.

    The intermediate ``node_key`` buffer is zeroed immediately after the shard
    key is derived.

    Args:
        master_seed: Root seed material.
        shard_id: Shard identifier bound into the derived key.
        node_id: Optional node identifier.  When provided a node key is first
            derived from the master seed; that key is then used as input key
            material for the shard key derivation, preventing master seed reuse
            across nodes.  When omitted, a single HKDF step from master seed
            is used.

    Returns:
        Deterministically derived Ed25519 signing key.
    """
    if not master_seed:
        raise ValueError("master_seed must be non-empty")
    if not shard_id:
        raise ValueError("shard_id must be non-empty")
    if node_id == "":
        raise ValueError("node_id must be non-empty when provided")

    node_key: bytearray | None = None
    try:
        if node_id is not None:
            # Step 1: master_seed → node_key (bound to node_id)
            node_key = _hkdf_derive(
                master_seed,
                _HKDF_INFO_NODE_KEY + b"\x00" + node_id.encode("utf-8"),
            )
            ikm = bytes(node_key)
        else:
            ikm = master_seed

        # Step 2: node_key (or master_seed) → shard_key (bound to shard_id)
        key_material = _hkdf_derive(
            ikm,
            _HKDF_INFO_SHARD_SIGNING_KEY + b"\x00" + shard_id.encode("utf-8"),
        )
        try:
            return nacl.signing.SigningKey(bytes(key_material))
        finally:
            key_material[:] = b"\x00" * len(key_material)
    finally:
        if node_key is not None:
            node_key[:] = b"\x00" * len(node_key)


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
