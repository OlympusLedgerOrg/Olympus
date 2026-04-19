"""
Poseidon SMT operations for the Olympus ingest path.

**ARCHITECTURAL NOTE:**
This module contains Poseidon SMT logic that is retained for backward compatibility
with the in-memory test/dev path. In production with PostgreSQL storage, the
authoritative Poseidon root computation is handled inside the SERIALIZABLE database
transaction in storage/postgres.py (O(log N) incremental updates per record).

Per the CD-HS-ST architecture documented in COPILOT_INSTRUCTIONS.md:
- Python MUST NOT implement operational SMT logic for production paths
- The Rust service is the authoritative source for CD-HS-ST operations
- This module exists solely to support:
  1. In-memory test mode (when DATABASE_URL is not set)
  2. Fallback paths during migration to Go/Rust services

When the Go sequencer and Rust CD-HS-ST service are fully deployed,
this module should be deprecated and eventually removed.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from protocol.poseidon_smt import PoseidonSMT
    from storage.postgres import StorageLayer

from protocol.poseidon_smt import key_to_smt_bytes as _key_to_smt_bytes


logger = logging.getLogger(__name__)


# BN128 scalar field prime for Poseidon hash compatibility
BN128_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def value_hash_to_poseidon_field(value_hash: bytes) -> int:
    """Convert a 32-byte value hash into a BN128 field element.

    Applies modular reduction by the BN128 scalar field prime so that
    the returned value is always a valid field element. Without this
    reduction, values derived from BLAKE3 hashes can exceed the prime
    (2^256 - 1 is ~5.3x the BN128 prime), causing incorrect Poseidon
    hash outputs and enabling hash collisions.

    Args:
        value_hash: 32-byte value hash (typically from BLAKE3).

    Returns:
        Integer reduced to BN128 field.

    Raises:
        ValueError: If value_hash is not exactly 32 bytes.
    """
    if len(value_hash) != 32:
        raise ValueError(f"value_hash must be 32 bytes, got {len(value_hash)}")
    return int.from_bytes(value_hash, byteorder="big") % BN128_FIELD_PRIME


def resolved_poseidon_root(persisted_root: str | None, fallback_root: str) -> str:
    """Resolve persisted Poseidon root with a deterministic fallback.

    Args:
        persisted_root: Root from storage, if available.
        fallback_root: Default root to use when persisted_root is None.

    Returns:
        The persisted root if not None, otherwise the fallback.
    """
    return persisted_root if persisted_root is not None else fallback_root


def build_poseidon_smt_for_storage_shard(
    storage: StorageLayer, shard_id: str, *, up_to_ts: datetime | str | None = None
) -> PoseidonSMT:
    """Rebuild the current PoseidonSMT view for a shard from persisted SMT leaves.

    **WARNING:** This is an O(N) leaf scan operation. It should only be called
    when Poseidon/ZK proofs are enabled AND the incremental update path cannot
    be used (e.g., first write when poseidon_smt_nodes table is empty).

    In production, prefer the O(log N) incremental update path in
    storage/postgres.py which maintains Poseidon state incrementally.

    Args:
        storage: The StorageLayer instance to read leaves from.
        shard_id: Shard identifier (currently unused, all leaves are global).
        up_to_ts: Optional timestamp cutoff for historical tree reconstruction.

    Returns:
        A PoseidonSMT instance populated with all leaves up to the cutoff.
    """
    from protocol.poseidon_smt import PoseidonSMT

    with storage._get_connection() as conn, conn.cursor() as cur:
        # O(N) leaf scan — only runs when Poseidon / ZK proofs are enabled.
        if up_to_ts is not None:
            if isinstance(up_to_ts, str):
                up_to_ts = datetime.fromisoformat(up_to_ts)
            cur.execute(
                "SELECT key, value_hash FROM smt_leaves WHERE ts <= %s ORDER BY key",
                (up_to_ts,),
            )
        else:
            cur.execute("SELECT key, value_hash FROM smt_leaves ORDER BY key")

        poseidon_smt = PoseidonSMT()
        for row in cur.fetchall():
            leaf_key = _key_to_smt_bytes(bytes(row["key"]))
            value_hash = bytes(row["value_hash"])
            poseidon_smt.update(leaf_key, value_hash_to_poseidon_field(value_hash))
    return poseidon_smt


def get_or_build_poseidon_smt(shard_id: str, storage: StorageLayer | None = None) -> PoseidonSMT:
    """Get a Poseidon SMT for the given shard, using storage if available.

    **NOTE:** This function exists for the in-memory fallback path.
    When storage is configured, production code should NOT call this;
    instead, use the incremental update path in storage/postgres.py.

    Args:
        shard_id: Shard identifier for the SMT.
        storage: Optional storage layer. If None, returns an empty SMT.

    Returns:
        A PoseidonSMT instance (either populated from storage or empty).
    """
    if storage is not None:
        return build_poseidon_smt_for_storage_shard(storage, shard_id)
    else:
        from protocol.poseidon_smt import PoseidonSMT

        return PoseidonSMT()


def create_empty_poseidon_smt() -> PoseidonSMT:
    """Create a new empty PoseidonSMT instance.

    This is the preferred way to get a local Poseidon SMT for tracking
    roots within a batch when storage is configured. The authoritative
    root is computed by storage/postgres.py; this local copy is only
    for metadata purposes within the batch.

    Returns:
        A new, empty PoseidonSMT instance.
    """
    from protocol.poseidon_smt import PoseidonSMT

    return PoseidonSMT()
