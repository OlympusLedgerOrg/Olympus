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

import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from psycopg import sql

from protocol.ssmf import SparseMerkleTree
from storage.gates import derive_node_rehash_gate


if TYPE_CHECKING:
    import psycopg

logger = logging.getLogger(__name__)


# ADR-0001: BLAKE3 domain-separated gate for the smt_nodes rehash trigger.
_NODE_REHASH_GATE: str = derive_node_rehash_gate()


# ---------------------------------------------------------------------------
# SMT leaf / node helpers
# ---------------------------------------------------------------------------


def load_tree_state(
    cur: psycopg.Cursor[Any],
    shard_id: str | None = None,
    up_to_ts: datetime | str | None = None,
    *,
    batch_size: int = 10_000,
) -> SparseMerkleTree:
    """
    Load sparse Merkle tree state from database.

    .. deprecated::
        ADR-0001 deprecates this function.  Production callers should use
        the purpose-specific helpers on :class:`StorageLayer`:
        ``_get_proof_path``, ``get_current_root``, ``replay_tree_incremental``.

    Read-only helper.  Must be called within an existing transaction.

    RT-M2 Fix:
    ----------
    Rows are now fetched in batches of *batch_size* (default 10 000) via
    ``fetchmany()`` instead of a single ``fetchall()``.  This bounds peak
    memory to O(batch_size) rows rather than O(total_leaves), preventing
    OOM on historical replay of large shards.

    CD-HS-ST Design:
    ---------------
    This function now loads the GLOBAL SMT state. The shard_id parameter is kept
    for backwards compatibility but is deprecated. The global SMT contains all shards,
    with shard identity encoded in the key space via global_key(shard_id, record_key).

    To load a shard-specific view, the caller should filter by key prefix after loading,
    though this is not recommended for production use. The global SMT is the canonical
    source of truth.

    Args:
        cur: Database cursor
        shard_id: DEPRECATED - kept for backwards compatibility, should be None
        up_to_ts: Optional inclusive timestamp cutoff for historical snapshots
        batch_size: Number of rows to fetch per DB round-trip (default 10 000).
            Controls peak memory usage during tree reconstruction.

    Returns:
        SparseMerkleTree with all leaves loaded (global SMT)
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")

    tree = SparseMerkleTree()

    # CD-HS-ST: Load leaves from the global SMT (no shard_id filter)
    if up_to_ts is None:
        cur.execute(
            """
            SELECT key, value_hash FROM smt_leaves
            ORDER BY ts ASC, key ASC
            """
        )
    else:
        cutoff = up_to_ts
        if isinstance(cutoff, str):
            cutoff = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
        cur.execute(
            """
            SELECT key, value_hash FROM smt_leaves
            WHERE ts <= %s
            ORDER BY ts ASC, key ASC
            """,
            (cutoff,),
        )

    # RT-M2: Stream rows in batches to bound peak memory.
    while True:
        rows = cur.fetchmany(batch_size)
        if not rows:
            break
        for row in rows:
            key = bytes(_row_get(row, "key", 0))
            value_hash = bytes(_row_get(row, "value_hash", 1))
            tree.update(key, value_hash)

    return tree


def persist_tree_nodes(
    cur: psycopg.Cursor[Any],
    shard_id: str | None,
    tree: SparseMerkleTree,
    *,
    cache_put: Any | None = None,
) -> None:
    """
    Persist tree nodes to database.

    CD-HS-ST Design:
    ---------------
    This function now persists nodes to the GLOBAL SMT. The shard_id parameter is kept
    for backwards compatibility with the cache_put callback but is not used in the
    database INSERT (since the global SMT has no shard_id column).

    ADR-0001: Uses ``ON CONFLICT DO UPDATE`` so that rehashed ancestor
    nodes are kept current.  The ``smt_nodes_reject_update`` trigger
    requires the session variable ``olympus.allow_node_rehash`` to be set
    to the BLAKE3 domain-separated gate (``_NODE_REHASH_GATE``).

    Args:
        cur: Database cursor
        shard_id: DEPRECATED - kept for cache_put callback compatibility
        tree: SparseMerkleTree to persist
        cache_put: Optional callback ``(shard_id, level, path_bytes, hash_value)``
            to populate an in-memory node cache.
    """
    # Gate the trigger so the upsert is allowed.
    # H-1 Fix: Use psycopg.sql.Literal to avoid f-string SQL pattern that could
    # be cargo-culted into dynamic contexts.
    cur.execute(
        sql.SQL("SET LOCAL olympus.allow_node_rehash = {}").format(sql.Literal(_NODE_REHASH_GATE))
    )

    for path, hash_value in tree.nodes.items():
        path_bytes = encode_path(path)
        level = len(path)

        # CD-HS-ST: Insert into global SMT (no shard_id)
        cur.execute(
            """
            INSERT INTO smt_nodes (level, index, hash, ts)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (level, index)
            DO UPDATE SET hash = EXCLUDED.hash, ts = EXCLUDED.ts
            """,
            (level, path_bytes, hash_value, datetime.now(timezone.utc)),
        )

        if cache_put is not None:
            # Keep shard_id in cache_put for backwards compatibility
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


def get_header_by_seq(cur: psycopg.Cursor[Any], shard_id: str, seq: int) -> dict[str, Any] | None:
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
    shard_id: str | None,
    expected_root: bytes,
) -> None:
    """
    Recompute the current global SMT root and ensure it matches ``expected_root``.

    CD-HS-ST Design:
    ---------------
    This function now validates the GLOBAL SMT root, not a per-shard root.
    The shard_id parameter is kept for backwards compatibility but is deprecated.

    Raises:
        ValueError: When the recomputed root diverges from ``expected_root``.
    """
    tree = load_tree_state(cur, shard_id=None)
    computed_root = tree.get_root()
    if computed_root != expected_root:
        shard_msg = f" for shard '{shard_id}'" if shard_id else ""
        raise ValueError(
            f"Computed root {computed_root.hex()} does not match persisted root "
            f"{expected_root.hex()}{shard_msg}"
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _row_get(row: Any, key: str, idx: int) -> Any:
    """Get value from row, supporting both dict and tuple rows."""
    if isinstance(row, Mapping):
        return row[key]
    return row[idx]
