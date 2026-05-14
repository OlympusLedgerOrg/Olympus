"""
Module-level utilities shared across the storage layer.

This module is internal to the storage package (_pg_* convention).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast

from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.ssmf import _key_to_path_bits


# ---------------------------------------------------------------------------
# Rust SMT availability sentinel
# ---------------------------------------------------------------------------

try:
    from olympus_core import RustSparseMerkleTree

    _RUST_SMT_AVAILABLE = True
except ImportError:
    RustSparseMerkleTree = None  # noqa: N816
    _RUST_SMT_AVAILABLE = False
    if os.getenv("OLYMPUS_REQUIRE_RUST", "").strip().lower() in {"1", "true", "yes", "on"}:
        raise RuntimeError(
            "Rust SMT extension required by OLYMPUS_REQUIRE_RUST=1, "
            "but olympus_core could not be imported — install with `maturin develop`"
        ) from None


def _get_smt_class() -> type[Any]:
    """Return the RustSparseMerkleTree class, honouring test monkeypatches on storage.postgres."""
    import sys

    pg = sys.modules.get("storage.postgres")
    if pg is not None:
        cls = getattr(pg, "RustSparseMerkleTree", None)
        if cls is not None:
            return cast(type[Any], cls)
    return cast(type[Any], RustSparseMerkleTree)


def _require_rust_smt() -> None:
    """Raise RuntimeError if Rust SMT is not available."""
    import sys

    pg = sys.modules.get("storage.postgres")
    available = getattr(pg, "_RUST_SMT_AVAILABLE", _RUST_SMT_AVAILABLE)
    if not available:
        raise RuntimeError(
            "olympus_core is required for storage operations — install with `maturin develop`"
        )


# ---------------------------------------------------------------------------
# Path encoding (used by both module-level helpers and instance methods)
# ---------------------------------------------------------------------------


def _encode_path(path: tuple[int, ...]) -> bytes:
    """Encode a path tuple as packed bytes (MSB first, 8× space reduction).

    A 256-bit path becomes 32 bytes instead of 256 bytes.
    """
    if not path:
        return b""
    n = len(path)
    num_bytes = (n + 7) // 8
    result = bytearray(num_bytes)
    for i, bit in enumerate(path):
        if bit:
            result[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(result)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------


def _normalize_timestamp_iso(ts: datetime | str | None) -> str:
    """Normalize a timestamp to ISO 8601 format with 'Z' suffix."""
    if ts is None:
        return ""
    if isinstance(ts, datetime):
        return ts.isoformat().replace("+00:00", "Z")
    return str(ts)


# ---------------------------------------------------------------------------
# Poseidon SMT helpers (module-level, O(N) deprecated + O(256) incremental)
# ---------------------------------------------------------------------------


def _compute_poseidon_root_from_leaves(leaves: Mapping[bytes, bytes]) -> bytes:
    """Compute the authoritative Poseidon root from current SMT leaves.

    .. deprecated::
        O(N) rebuild retained only as a fallback for the first write when the
        ``poseidon_smt_nodes`` table is empty.  Use ``_poseidon_incremental_update``
        instead.
    """
    from protocol.poseidon_smt import PoseidonSMT

    poseidon_smt = PoseidonSMT()
    for key, value_hash in leaves.items():
        field_value = int.from_bytes(value_hash, byteorder="big") % SNARK_SCALAR_FIELD
        poseidon_smt.update(key, field_value)
    poseidon_int = int(poseidon_smt.get_root())
    return poseidon_int.to_bytes(32, byteorder="big")


def _poseidon_incremental_update(
    key: bytes,
    value_hash: bytes,
    siblings: list[int],
) -> tuple[int, list[tuple[int, bytes, str]]]:
    """Incrementally update the Poseidon SMT for a single key-value insertion.

    O(256) work instead of O(N). Mirrors ``PoseidonSMT.update()`` but operates
    on a flat sibling list fetched from ``poseidon_smt_nodes``.

    Returns:
        ``(new_root, node_deltas)`` — *new_root* is the Poseidon root as an int
        and *node_deltas* is a list of ``(db_level, packed_index, hash_decimal)``
        tuples for upserting into ``poseidon_smt_nodes``.
    """
    from protocol.poseidon_smt import _poseidon_hash_leaf, _poseidon_hash_node

    path = tuple(_key_to_path_bits(key))
    key_int = int.from_bytes(key, byteorder="big") % SNARK_SCALAR_FIELD
    field_value = int.from_bytes(value_hash, byteorder="big") % SNARK_SCALAR_FIELD

    current_hash = _poseidon_hash_leaf(key_int, field_value)

    node_deltas: list[tuple[int, bytes, str]] = []

    for level in range(256):
        bit_pos = 255 - level
        sibling_hash = siblings[level]

        if path[bit_pos] == 0:
            parent_hash = _poseidon_hash_node(current_hash, sibling_hash)
        else:
            parent_hash = _poseidon_hash_node(sibling_hash, current_hash)

        parent_hash = parent_hash % SNARK_SCALAR_FIELD

        parent_path = path[:bit_pos] if bit_pos > 0 else ()
        packed_index = _encode_path(parent_path)
        node_deltas.append((len(parent_path), packed_index, str(parent_hash)))

        current_hash = parent_hash

    return current_hash, node_deltas


# ---------------------------------------------------------------------------
# Gate constant (BLAKE3 domain-separated session variable for the SMT trigger)
# ---------------------------------------------------------------------------

from storage.gates import derive_node_rehash_gate  # noqa: E402


_NODE_REHASH_GATE: str = derive_node_rehash_gate()
