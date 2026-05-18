"""Chunk Merkle commitments for byte-level redaction subset proofs."""

from __future__ import annotations

import blake3


CHUNK_SIZE = 1024
CHUNKING_VERSION = "raw_bytes_fixed_1024_zero_pad_v1"
MATCH_STRATEGY = "merkle_subset_v1"
LEAF_PREFIX = b"OLYMPUS:REDACTION:LEAF:v1"
NODE_PREFIX = b"OLYMPUS:REDACTION:NODE:v1"
ZERO_HASH = b"\x00" * 32


def _u64be(value: int) -> bytes:
    if value < 0:
        raise ValueError("index must be non-negative")
    return value.to_bytes(8, "big")


def redaction_leaf_hash(index: int, chunk: bytes) -> bytes:
    """Hash a raw byte chunk with domain separation and position binding."""
    h = blake3.blake3()
    h.update(LEAF_PREFIX)
    h.update(_u64be(index))
    h.update(chunk)
    return h.digest()


def redaction_node_hash(left: bytes, right: bytes) -> bytes:
    """Hash an internal redaction Merkle node with domain separation."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node children must be 32-byte hashes")
    h = blake3.blake3()
    h.update(NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


def chunk_bytes(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    """Split raw bytes into fixed-size chunks; empty files commit one empty chunk."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if not data:
        return [b""]
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def _next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


def build_redaction_merkle_levels(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[list[bytes]]:
    """Build padded Merkle levels for raw byte chunks.

    Padding is explicit for v1: leaf level is padded to the next power of two
    with 32 zero bytes, then internal nodes use the redaction node hash.
    """
    chunks = chunk_bytes(data, chunk_size)
    leaves = [redaction_leaf_hash(i, chunk) for i, chunk in enumerate(chunks)]
    padded_count = _next_power_of_two(len(leaves))
    level = leaves + [ZERO_HASH] * (padded_count - len(leaves))
    levels = [level]
    while len(level) > 1:
        level = [redaction_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def compute_redaction_chunk_metadata(data: bytes) -> dict[str, int | str]:
    """Return the persisted chunk commitment metadata for a raw file."""
    levels = build_redaction_merkle_levels(data, CHUNK_SIZE)
    return {
        "chunk_merkle_root": levels[-1][0].hex(),
        "chunk_size": CHUNK_SIZE,
        "chunk_count": len(chunk_bytes(data, CHUNK_SIZE)),
        "chunking_version": CHUNKING_VERSION,
    }


def create_redaction_merkle_proof(data: bytes, index: int) -> list[str]:
    """Create an ordered bottom-up sibling proof for a raw chunk index."""
    chunks = chunk_bytes(data, CHUNK_SIZE)
    if index < 0 or index >= len(chunks):
        raise IndexError("chunk index out of range")
    levels = build_redaction_merkle_levels(data, CHUNK_SIZE)
    proof: list[str] = []
    current = index
    for level in levels[:-1]:
        sibling_index = current ^ 1
        proof.append(level[sibling_index].hex())
        current >>= 1
    return proof


def validate_digest_hex(value: str) -> bytes:
    """Parse a hex digest and require exactly 32 bytes."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("digest must be valid hex") from exc
    if len(raw) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    return raw


def verify_redaction_merkle_inclusion(
    leaf_hash_hex: str,
    leaf_index: int,
    proof_hex: list[str],
    root_hex: str,
) -> bool:
    """Verify a v1 redaction chunk inclusion proof against a Merkle root."""
    if leaf_index < 0:
        return False
    try:
        current = validate_digest_hex(leaf_hash_hex)
        expected_root = validate_digest_hex(root_hex)
        current_index = leaf_index
        for sibling_hex in proof_hex:
            sibling = validate_digest_hex(sibling_hex)
            if current_index & 1:
                current = redaction_node_hash(sibling, current)
            else:
                current = redaction_node_hash(current, sibling)
            current_index >>= 1
    except ValueError:
        return False
    return current == expected_root
