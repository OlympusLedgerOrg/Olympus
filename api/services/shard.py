"""
Shard assignment and state-root computation for the Olympus FOIA ledger.

Shard assignment uses a BLAKE3-based consistent-hashing ring.  Each shard
in the ring is replicated across 64 virtual nodes to ensure even key
distribution.  The ring is configured via the ``OLYMPUS_SHARD_RING``
environment variable (a JSON array of hex shard IDs).  When unset or set
to a single shard, all requests are routed to ``DEFAULT_SHARD_ID`` for
backward compatibility with Phase 0 single-shard operation.
"""

from __future__ import annotations

import bisect
import json
import logging
import os

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.services.merkle import build_tree
from protocol.hashes import hash_string


logger = logging.getLogger(__name__)

# Default shard — Phase 0 single-shard operation
DEFAULT_SHARD_ID = "0x4F3A"

# Number of virtual-node replicas per physical shard on the hash ring.
_VIRTUAL_NODES = 64


class _ShardRing:
    """Consistent-hashing ring backed by BLAKE3.

    The ring is read-only after construction and therefore safe for
    concurrent access from multiple threads.
    """

    def __init__(self, shard_ids: list[str]) -> None:
        self._shard_ids = list(shard_ids)
        self._keys: list[int] = []
        self._ring: dict[int, str] = {}

        for shard_id in self._shard_ids:
            for replica in range(_VIRTUAL_NODES):
                vnode_label = f"{shard_id}:{replica}"
                digest = hash_string(vnode_label)
                pos = int.from_bytes(digest, "big")
                self._keys.append(pos)
                self._ring[pos] = shard_id

        self._keys.sort()

    @property
    def single_shard(self) -> bool:
        """True when the ring contains only one physical shard."""
        return len(self._shard_ids) <= 1

    def assign(self, key: str) -> str:
        """Map *key* to the nearest shard clockwise on the ring."""
        if self.single_shard:
            return self._shard_ids[0] if self._shard_ids else DEFAULT_SHARD_ID

        digest = hash_string(key)
        pos = int.from_bytes(digest, "big")
        idx = bisect.bisect_right(self._keys, pos)
        if idx == len(self._keys):
            idx = 0
        return self._ring[self._keys[idx]]


def _load_ring() -> _ShardRing:
    """Build the shard ring from the environment (once at import time)."""
    raw = os.environ.get("OLYMPUS_SHARD_RING", "")
    if raw.strip():
        try:
            shard_ids = json.loads(raw)
            if not isinstance(shard_ids, list) or not all(isinstance(s, str) for s in shard_ids):
                raise TypeError("OLYMPUS_SHARD_RING must be a JSON array of strings")
        except (json.JSONDecodeError, TypeError):
            logger.warning(
                "Invalid OLYMPUS_SHARD_RING value %r; falling back to default shard.",
                raw,
            )
            shard_ids = [DEFAULT_SHARD_ID]
    else:
        shard_ids = [DEFAULT_SHARD_ID]

    return _ShardRing(shard_ids)


_RING: _ShardRing = _load_ring()


def assign_shard(request_id: str) -> str:
    """Return the shard identifier for the given request.

    Uses a BLAKE3-based consistent-hashing ring to map *request_id* to one
    of the configured shards.  When the ring contains a single shard (the
    default), ``DEFAULT_SHARD_ID`` is returned for every input, preserving
    backward compatibility.

    Args:
        request_id: UUID or display ID of the request.

    Returns:
        Hex shard identifier string.
    """
    return _RING.assign(request_id)


async def compute_state_root(shard_id: str, db: AsyncSession) -> str:
    """Compute the Merkle state root for all commits in a shard.

    Retrieves every ``doc_hash`` from DocCommit and ``manifest_hash`` from
    DatasetArtifact in the shard, builds a deterministic Merkle tree, and
    returns the root hash.  Returns a sentinel hash of 64 zero characters
    if the shard is empty.

    Args:
        shard_id: Hex shard identifier.
        db: Async SQLAlchemy session.

    Returns:
        Hex-encoded BLAKE3 Merkle root, or 64 zeros if the shard is empty.
    """
    # Import here to avoid circular imports at module level
    from api.models.dataset import DatasetArtifact  # noqa: PLC0415
    from api.models.document import DocCommit  # noqa: PLC0415

    doc_q = select(
        DocCommit.doc_hash.label("hash"),
        DocCommit.epoch_timestamp.label("ts"),
    ).where(DocCommit.shard_id == shard_id)

    ds_q = select(
        DatasetArtifact.manifest_hash.label("hash"),
        DatasetArtifact.epoch_timestamp.label("ts"),
    ).where(DatasetArtifact.shard_id == shard_id)

    # Deterministic ordering: timestamp first, then hash for tie-breaking.
    # This ensures identical tree structure across replicas even when
    # multiple commits share the same millisecond timestamp.
    union_q = doc_q.union_all(ds_q).order_by(text("ts"), text("hash"))
    result = await db.execute(union_q)
    hashes = [row.hash for row in result.all()]

    from protocol.log_sanitization import sanitize_for_log

    if not hashes:
        logger.debug("Shard %s is empty; returning zero root.", sanitize_for_log(shard_id))
        return "0" * 64

    tree = build_tree(hashes, preserve_order=True)
    logger.debug("Computed state root %s for shard %s.", sanitize_for_log(tree.root_hash), sanitize_for_log(shard_id))
    return tree.root_hash
