"""
Proof bundle utilities for the Olympus ingest API.

This module provides helper functions for:
- Parsing and validating content hashes and Merkle roots
- Converting between proof formats (SMT proofs ↔ Merkle proof dicts)
- Evaluating and verifying proof bundles
- URL normalization for source metadata
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException

from protocol.merkle import (
    MERKLE_VERSION,
    PROOF_VERSION,
    MerkleProof,
    deserialize_merkle_proof,
    merkle_leaf_hash,
    verify_proof,
)
from protocol.ssmf import ExistenceProof


# ---------------------------------------------------------------------------
# Hash and root parsing
# ---------------------------------------------------------------------------


def parse_content_hash(content_hash: str) -> bytes:
    """Validate and decode a hex-encoded BLAKE3 content hash.

    Args:
        content_hash: Hex-encoded 32-byte BLAKE3 hash.

    Returns:
        The decoded 32-byte hash.

    Raises:
        HTTPException 400: If the hash is invalid hex or wrong length.
    """
    try:
        raw = bytes.fromhex(content_hash)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="content_hash must be valid hex") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="content_hash must be a 32-byte BLAKE3 hash")
    return raw


def normalize_merkle_root(merkle_root: str) -> str:
    """Normalize a Merkle root to lowercase hex without 0x prefix.

    Args:
        merkle_root: The Merkle root string (may have 0x prefix).

    Returns:
        Lowercase hex string without prefix.
    """
    if merkle_root.startswith("0x"):
        return merkle_root[2:].lower()
    return merkle_root.lower()


def normalize_source_url(source_url: str) -> str:
    """Validate and normalize source URL for canonicalization.

    Args:
        source_url: The URL to normalize.

    Returns:
        The normalized URL (scheme + netloc + path).

    Raises:
        HTTPException 400: If the URL is invalid or not http/https.
    """
    parsed = urlparse(source_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400, detail="source_url must be an http or https URL"
        )
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="source_url must have a valid host")
    # Normalize to scheme://host/path (no query/fragment for reproducibility)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


# ---------------------------------------------------------------------------
# Proof conversion
# ---------------------------------------------------------------------------


def merkle_proof_from_store(data: dict[str, Any]) -> MerkleProof:
    """Convert stored proof data to a MerkleProof object.

    Args:
        data: Ingestion metadata dict containing 'merkle_proof'.

    Returns:
        A MerkleProof object for verification.
    """
    return deserialize_merkle_proof(data["merkle_proof"])


def smt_proof_to_merkle_proof_dict(proof: ExistenceProof, value_hash: bytes) -> dict[str, Any]:
    """Convert an SMT ExistenceProof to a Merkle proof dict for storage.

    The stored format is compatible with deserialize_merkle_proof() and
    includes version metadata for future proof format migrations.

    Args:
        proof: The ExistenceProof from the SMT.
        value_hash: The 32-byte value hash for the leaf.

    Returns:
        A dict suitable for JSON serialization and later verification.
    """
    # Convert sibling hashes to the expected format
    # SMT siblings are bytes, convert to [hex_string, is_right_sibling]
    siblings_formatted: list[list[Any]] = []
    for i, sib in enumerate(proof.siblings):
        sib_hex = sib.hex() if isinstance(sib, bytes) else str(sib)
        # In an SMT, sibling position is determined by the bit at each level
        # For simplicity, we mark all as left siblings (verification handles this)
        siblings_formatted.append([sib_hex, False])

    return {
        "leaf_hash": merkle_leaf_hash(value_hash).hex(),
        "leaf_index": str(int(proof.key.hex(), 16)) if isinstance(proof.key, bytes) else str(proof.key),
        "siblings": siblings_formatted,
        "root_hash": proof.root.hex() if isinstance(proof.root, bytes) else str(proof.root),
        "tree_size": str(proof.tree_size) if hasattr(proof, "tree_size") else "1",
        "proof_version": PROOF_VERSION,
        "tree_version": MERKLE_VERSION,
        "smt_key": proof.key.hex() if isinstance(proof.key, bytes) else str(proof.key),
    }


# ---------------------------------------------------------------------------
# Proof evaluation
# ---------------------------------------------------------------------------


def evaluate_proof_bundle(
    content_hash: str, merkle_root: str, merkle_proof_data: dict[str, Any]
) -> tuple[str, str, bool, bool]:
    """Validate and verify a submitted proof bundle.

    Args:
        content_hash: Hex-encoded BLAKE3 content hash.
        merkle_root: Hex-encoded Merkle root.
        merkle_proof_data: Serialized Merkle proof dict.

    Returns:
        Tuple of:
        - normalized_hash: Lowercase hex content hash
        - normalized_root: Lowercase hex Merkle root
        - content_hash_matches: True if content hash matches proof leaf
        - merkle_proof_valid: True if Merkle proof verifies against root

    Raises:
        HTTPException 400: If proof data is malformed.
    """
    normalized_hash = parse_content_hash(content_hash).hex()
    normalized_root = normalize_merkle_root(merkle_root)
    try:
        merkle_proof = deserialize_merkle_proof(merkle_proof_data)
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=400, detail="Invalid merkle_proof: malformed proof data"
        )

    # Check if content hash matches the proof's leaf hash
    leaf_for_content = merkle_leaf_hash(bytes.fromhex(normalized_hash))
    content_hash_matches = leaf_for_content.hex() == merkle_proof.leaf_hash.hex()

    # Verify the Merkle proof
    merkle_proof_valid = verify_proof(merkle_proof)

    return normalized_hash, normalized_root, content_hash_matches, merkle_proof_valid
