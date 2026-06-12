"""Domain-separated BLAKE3 primitives — a byte-exact port of ``olympus-crypto``.

Every constant and byte layout here MUST match
``crates/olympus-crypto/src/lib.rs`` and ``…/smt.rs`` exactly; the parity test
(``tests/test_parity.py``) pins them against vectors emitted by the Rust source
of truth. Do not "tidy" a layout without regenerating those vectors.
"""

from __future__ import annotations

import struct

from blake3 import blake3

# ── domain constants (ADR-0003/0004/0005) ───────────────────────────────────
KEY_PREFIX = b"OLY:KEY:V1"
NODE_PREFIX = b"OLY:NODE:V1"
SEP = b"|"
EMPTY_LEAF_PREFIX = b"OLY:EMPTY-LEAF:V1"
SHARD_PREFIX_DOMAIN = b"OLY:SHARD-PREFIX:V1"

OLY_STRUCT_MARKER = 0x01
OLY_NAMESPACE = b"OLY"
LEAF_OBJECT_TYPE = 0x01
LEAF_VERSION = 0x01
LEAF_BODY_FIELD_COUNT = 0x05

SMT_DEPTH = 256
SHARD_PREFIX_BYTES = 8

# Record-type tag folded into every manifest record key (matches
# ``olympus_manifest::RECORD_TYPE``).
RECORD_TYPE = "olympus.dataset-record"


def b3(*parts: bytes) -> bytes:
    """BLAKE3-256 over the concatenation of ``parts`` (32 raw bytes)."""
    h = blake3()
    for p in parts:
        h.update(p)
    return h.digest()


def length_prefixed(data: bytes) -> bytes:
    """4-byte big-endian length prefix followed by ``data`` (ADR-0005)."""
    if len(data) > 0xFFFFFFFF:
        raise ValueError("length_prefixed: data exceeds u32::MAX")
    return struct.pack(">I", len(data)) + data


def record_key(record_type: str, record_id: str, version: int) -> bytes:
    """Deterministic 32-byte record key (matches ``olympus_crypto::record_key``)."""
    body = (
        KEY_PREFIX
        + length_prefixed(record_type.encode("utf-8"))
        + length_prefixed(record_id.encode("utf-8"))
        + struct.pack(">Q", version)
    )
    return b3(body)


def shard_prefix(shard_id: str) -> bytes:
    """The 64-bit shard prefix = first 8 bytes of BLAKE3(domain || shard_id)."""
    return b3(SHARD_PREFIX_DOMAIN, shard_id.encode("utf-8"))[:SHARD_PREFIX_BYTES]


def shard_record_key(shard_id: str, rkey: bytes) -> bytes:
    """32-byte tree key: shard prefix (8) ‖ low 192 bits of ``rkey``."""
    if len(rkey) != 32:
        raise ValueError("record_key must be 32 bytes")
    return shard_prefix(shard_id) + rkey[: 32 - SHARD_PREFIX_BYTES]


def shard_id_matches_key(shard_id: str, key: bytes) -> bool:
    """ADR-0005 authority: ``key``'s high 64 bits equal ``shard_prefix(shard_id)``."""
    return key[:SHARD_PREFIX_BYTES] == shard_prefix(shard_id)


def leaf_hash(
    shard_id: bytes,
    key: bytes,
    value_hash: bytes,
    parser_id: bytes,
    canonical_parser_version: bytes,
    model_hash: bytes,
) -> bytes:
    """ADR-0005 structured leaf hash (matches ``olympus_crypto::leaf_hash``)."""
    if len(key) != 32 or len(value_hash) != 32:
        raise ValueError("leaf_hash requires 32-byte key and value_hash")
    h = blake3()
    h.update(bytes([OLY_STRUCT_MARKER]))
    h.update(OLY_NAMESPACE)
    h.update(bytes([LEAF_OBJECT_TYPE]))
    h.update(bytes([LEAF_VERSION]))
    h.update(length_prefixed(shard_id))
    h.update(bytes([LEAF_BODY_FIELD_COUNT]))
    h.update(length_prefixed(key))
    h.update(value_hash)
    h.update(length_prefixed(parser_id))
    h.update(length_prefixed(canonical_parser_version))
    h.update(length_prefixed(model_hash))
    return h.digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Domain-separated internal-node hash (matches ``olympus_crypto::node_hash``)."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node_hash requires 32-byte halves")
    return b3(NODE_PREFIX, SEP, left, SEP, right)


def empty_leaf() -> bytes:
    """The domain-separated empty-leaf sentinel."""
    return b3(EMPTY_LEAF_PREFIX)


_EMPTY_TABLE: list[bytes] | None = None


def empty_subtree_hash(height: int) -> bytes:
    """Hash of a fully-empty subtree of the given ``height`` (0..=256)."""
    global _EMPTY_TABLE
    if _EMPTY_TABLE is None:
        table = [b"\x00" * 32] * (SMT_DEPTH + 1)
        table[0] = empty_leaf()
        for i in range(1, SMT_DEPTH + 1):
            table[i] = node_hash(table[i - 1], table[i - 1])
        _EMPTY_TABLE = table
    if not 0 <= height <= SMT_DEPTH:
        raise ValueError("height out of range")
    return _EMPTY_TABLE[height]


def _key_bit(key: bytes, i: int) -> int:
    return (key[i >> 3] >> (7 - (i & 7))) & 1


def fold_to_root(key: bytes, start: bytes, siblings: list[bytes]) -> bytes:
    """Fold a 256-sibling path from ``start`` up to a root, branching by ``key`` bits.

    Mirrors ``olympus_crypto::smt::fold_to_root``: siblings are ordered
    leaf→root (index 0 is the deepest, at bit 255).
    """
    current = start
    for level in range(SMT_DEPTH):
        bit_pos = SMT_DEPTH - 1 - level
        sib = siblings[level]
        if _key_bit(key, bit_pos) == 0:
            current = node_hash(current, sib)
        else:
            current = node_hash(sib, current)
    return current
