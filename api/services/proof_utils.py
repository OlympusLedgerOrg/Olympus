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

from protocol.hashes import leaf_hash
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
        raise HTTPException(status_code=400, detail="source_url must be an http or https URL")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="source_url must have a valid host")
    # Normalize to scheme://host/path (no query/fragment for reproducibility)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


# ---------------------------------------------------------------------------
# Proof conversion
# ---------------------------------------------------------------------------


def merkle_proof_from_store(data: dict[str, Any]) -> MerkleProof:
    """Convert stored ingestion proof metadata into a MerkleProof instance."""
    proof_data = data["merkle_proof"]
    return deserialize_merkle_proof(proof_data)


def evaluate_proof_bundle(
    content_hash: str, merkle_root: str, merkle_proof_data: dict[str, Any]
) -> tuple[str, str, bool, bool]:
    """Validate and verify a submitted proof bundle."""
    normalized_hash = parse_content_hash(content_hash).hex()
    normalized_root = normalize_merkle_root(merkle_root)
    try:
        merkle_proof = deserialize_merkle_proof(merkle_proof_data)
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=400, detail="Invalid merkle_proof: malformed proof data"
        ) from None

    content_hash_bytes = bytes.fromhex(normalized_hash)
    expected_leaf_hash = merkle_leaf_hash(content_hash_bytes)
    smt_key_hex = merkle_proof_data.get("smt_key")
    if smt_key_hex is not None:
        try:
            smt_key = bytes.fromhex(str(smt_key_hex))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="smt_key must be valid hex") from exc
        if len(smt_key) != 32:
            raise HTTPException(
                status_code=400, detail="smt_key must be a 32-byte key (64 hex chars)"
            )
        bundle_parser_id = merkle_proof_data.get("parser_id")
        bundle_cpv = merkle_proof_data.get("canonical_parser_version")
        if not isinstance(bundle_parser_id, str) or not bundle_parser_id:
            raise HTTPException(
                status_code=400,
                detail="parser_id is required and must be a non-empty string",
            )
        if not isinstance(bundle_cpv, str) or not bundle_cpv:
            raise HTTPException(
                status_code=400,
                detail="canonical_parser_version is required and must be a non-empty string",
            )
        expected_leaf_hash = leaf_hash(smt_key, content_hash_bytes, bundle_parser_id, bundle_cpv)

    content_hash_matches_proof = merkle_proof.leaf_hash == expected_leaf_hash
    if merkle_proof.root_hash.hex() != normalized_root:
        return normalized_hash, normalized_root, content_hash_matches_proof, False

    try:
        merkle_proof_valid = content_hash_matches_proof and verify_proof(merkle_proof)
    except ValueError:
        merkle_proof_valid = False

    return normalized_hash, normalized_root, content_hash_matches_proof, merkle_proof_valid


def smt_proof_to_merkle_proof_dict(proof: ExistenceProof, value_hash: bytes) -> dict[str, Any]:
    """Convert a sparse Merkle proof to the MerkleProof serialization used by the ingest API."""
    if len(value_hash) != 32:
        raise ValueError("value_hash must be 32 bytes")
    if len(proof.key) != 32:
        raise ValueError("proof.key must be 32 bytes")
    if len(proof.root_hash) != 32:
        raise ValueError("proof.root_hash must be 32 bytes")
    if not proof.parser_id:
        raise ValueError("proof.parser_id must be a non-empty string")
    if not proof.canonical_parser_version:
        raise ValueError("proof.canonical_parser_version must be a non-empty string")

    leaf_index = int.from_bytes(proof.key, byteorder="big", signed=False)
    siblings_with_positions: list[list[str | bool]] = []
    for level, sibling_hash in enumerate(proof.siblings):
        if len(sibling_hash) != 32:
            raise ValueError(f"sibling at level {level} must be 32 bytes")
        is_right = ((leaf_index >> level) & 1) == 0
        siblings_with_positions.append([sibling_hash.hex(), is_right])

    smt_leaf_hash = leaf_hash(
        proof.key,
        value_hash,
        proof.parser_id,
        proof.canonical_parser_version,
    )

    return {
        "leaf_hash": smt_leaf_hash.hex(),
        "leaf_index": str(leaf_index),
        "siblings": siblings_with_positions,
        "root_hash": proof.root_hash.hex(),
        "tree_size": str(1 << 256),
        "proof_version": PROOF_VERSION,
        "tree_version": MERKLE_VERSION,
        "smt_key": proof.key.hex(),
        "parser_id": proof.parser_id,
        "canonical_parser_version": proof.canonical_parser_version,
    }


def sequencer_proof_to_merkle_proof_dict(
    proof: Any,
    value_hash: bytes,
    parser_id: str,
    canonical_parser_version: str,
) -> dict[str, Any]:
    """Convert a Go sequencer inclusion proof to the API merkle_proof dict."""
    if len(value_hash) != 32:
        raise ValueError("value_hash must be 32 bytes")
    if not parser_id:
        raise ValueError("parser_id must be a non-empty string")
    if not canonical_parser_version:
        raise ValueError("canonical_parser_version must be a non-empty string")

    smt_key_hex = proof.global_key
    smt_key_bytes = bytes.fromhex(smt_key_hex)
    if len(smt_key_bytes) != 32:
        raise ValueError("sequencer global_key must decode to 32 bytes")

    root_bytes = bytes.fromhex(proof.root)
    if len(root_bytes) != 32:
        raise ValueError("sequencer root must decode to 32 bytes")

    if len(proof.siblings) != 256:
        raise ValueError(f"sequencer proof must have 256 siblings, got {len(proof.siblings)}")

    leaf_index = int.from_bytes(smt_key_bytes, byteorder="big", signed=False)
    siblings_with_positions: list[list[str | bool]] = []
    for level, sibling_hex in enumerate(proof.siblings):
        sibling_bytes = bytes.fromhex(sibling_hex)
        if len(sibling_bytes) != 32:
            raise ValueError(f"sequencer sibling at level {level} must decode to 32 bytes")
        is_right = ((leaf_index >> level) & 1) == 0
        siblings_with_positions.append([sibling_hex, is_right])

    smt_leaf_hash = leaf_hash(
        smt_key_bytes,
        value_hash,
        parser_id,
        canonical_parser_version,
    )

    return {
        "leaf_hash": smt_leaf_hash.hex(),
        "leaf_index": str(leaf_index),
        "siblings": siblings_with_positions,
        "root_hash": proof.root,
        "tree_size": str(1 << 256),
        "proof_version": PROOF_VERSION,
        "tree_version": MERKLE_VERSION,
        "smt_key": smt_key_hex,
        "parser_id": parser_id,
        "canonical_parser_version": canonical_parser_version,
    }
