"""
Protocol-critical state operations for the Olympus storage layer.

This module isolates all protocol-critical state — data whose corruption would
compromise cryptographic guarantees — from operational plumbing.

Protocol state tables:
    - smt_leaves: Sparse Merkle Tree leaf nodes (key-value pairs)
    - smt_nodes: Sparse Merkle Tree internal nodes (path-to-hash mappings)
    - shard_headers: Signed shard root commitments with chain linkage
    - ledger_entries: Append-only ledger chain linking records to shard roots

Separating these concerns makes security audits easier and reduces the blast
radius of bugs in operational code (rate limiting, ingestion batches, etc.).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from psycopg.rows import dict_row

from protocol.ssmf import SparseMerkleTree

if TYPE_CHECKING:
    import psycopg

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SMT leaf / node helpers
# ---------------------------------------------------------------------------


def load_tree_state(
    cur: psycopg.Cursor[Any],
    shard_id: str,
    up_to_ts: datetime | str | None = None,
) -> SparseMerkleTree:
    """
    Load sparse Merkle tree state from database.

    Read-only helper.  Must be called within an existing transaction.

    Args:
        cur: Database cursor
        shard_id: Shard identifier
        up_to_ts: Optional inclusive timestamp cutoff for historical snapshots

    Returns:
        SparseMerkleTree with all leaves loaded
    """
    tree = SparseMerkleTree()

    if up_to_ts is None:
        cur.execute(
            """
            SELECT key, value_hash FROM smt_leaves
            WHERE shard_id = %s
            ORDER BY ts ASC, key ASC
            """,
            (shard_id,),
        )
    else:
        cutoff = up_to_ts
        if isinstance(cutoff, str):
            cutoff = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
        cur.execute(
            """
            SELECT key, value_hash FROM smt_leaves
            WHERE shard_id = %s AND ts <= %s
            ORDER BY ts ASC, key ASC
            """,
            (shard_id, cutoff),
        )
    rows = cur.fetchall()

    for row in rows:
        key = bytes(_row_get(row, "key", 0))
        value_hash = bytes(_row_get(row, "value_hash", 1))
        tree.update(key, value_hash)

    return tree


def persist_tree_nodes(
    cur: psycopg.Cursor[Any],
    shard_id: str,
    tree: SparseMerkleTree,
    *,
    cache_put: Any | None = None,
) -> None:
    """
    Persist tree nodes to database (append-only).

    Args:
        cur: Database cursor
        shard_id: Shard identifier
        tree: SparseMerkleTree to persist
        cache_put: Optional callback ``(shard_id, level, path_bytes, hash_value)``
            to populate an in-memory node cache.
    """
    for path, hash_value in tree.nodes.items():
        path_bytes = encode_path(path)
        level = len(path)

        cur.execute(
            """
            INSERT INTO smt_nodes (shard_id, level, index, hash, ts)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (shard_id, level, index) DO NOTHING
            """,
            (shard_id, level, path_bytes, hash_value, datetime.now(timezone.utc)),
        )

        if cache_put is not None:
            cache_put(shard_id, level, path_bytes, hash_value)


def encode_path(path: tuple[int, ...]) -> bytes:
    """
    Encode path tuple as packed bytes (MSB first).

    A 256-bit path becomes 32 bytes instead of 256 — an 8× reduction.

    Args:
        path: Tuple of 0s and 1s (up to 256 elements)

    Returns:
        Packed bytes representation (ceil(len(path) / 8) bytes)
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
# Shard header helpers
# ---------------------------------------------------------------------------


def get_header_by_seq(
    cur: psycopg.Cursor[Any], shard_id: str, seq: int
) -> dict[str, Any] | None:
    """Retrieve a shard header row by sequence number."""
    cur.execute(
        """
        SELECT seq, root, header_hash, previous_header_hash, ts
        FROM shard_headers
        WHERE shard_id = %s AND seq = %s
        """,
        (shard_id, seq),
    )
    return cur.fetchone()


# ---------------------------------------------------------------------------
# Consistency checks
# ---------------------------------------------------------------------------


def assert_root_matches_state(
    cur: psycopg.Cursor[Any],
    shard_id: str,
    expected_root: bytes,
) -> None:
    """
    Recompute the current shard root and ensure it matches ``expected_root``.

    Raises:
        ValueError: When the recomputed root diverges from ``expected_root``.
    """
    tree = load_tree_state(cur, shard_id)
    computed_root = tree.get_root()
    if computed_root != expected_root:
        raise ValueError(
            f"Computed root {computed_root.hex()} does not match persisted root "
            f"{expected_root.hex()} for shard '{shard_id}'"
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _row_get(row: Any, key: str, idx: int) -> Any:
    """Get value from row, supporting both dict and tuple rows."""
    if isinstance(row, Mapping):
        return row[key]
    return row[idx]
