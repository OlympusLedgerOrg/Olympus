"""
Shard assignment and state-root computation for the Olympus FOIA ledger.

All records are currently assigned to a single shard (0x4F3A).  The
``assign_shard`` function is a trivial stub designed to be replaced when
multi-shard routing is implemented.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.services.merkle import build_tree


logger = logging.getLogger(__name__)

# Default shard — Phase 0 single-shard operation
DEFAULT_SHARD_ID = "0x4F3A"


def assign_shard(request_id: str) -> str:
    """Return the shard identifier for the given request.

    Args:
        request_id: UUID or display ID of the request (currently unused;
                    all records go to the default shard in Phase 0).

    Returns:
        Hex shard identifier string.
    """
    # TODO: Implement consistent-hashing shard routing for multi-shard Phase 1.
    return DEFAULT_SHARD_ID


async def compute_state_root(shard_id: str, db: AsyncSession) -> str:
    """Compute the Merkle state root for all commits in a shard.

    Retrieves every ``doc_hash`` in the shard, builds a deterministic
    Merkle tree, and returns the root hash.  Returns a sentinel hash of
    64 zero characters if the shard is empty.

    Args:
        shard_id: Hex shard identifier.
        db: Async SQLAlchemy session.

    Returns:
        Hex-encoded BLAKE3 Merkle root, or 64 zeros if the shard is empty.
    """
    # Import here to avoid circular imports at module level
    from api.models.document import DocCommit  # noqa: PLC0415

    result = await db.execute(
        select(DocCommit.doc_hash)
        .where(DocCommit.shard_id == shard_id)
        .order_by(DocCommit.epoch_timestamp)
    )
    hashes = list(result.scalars().all())

    if not hashes:
        logger.debug("Shard %s is empty; returning zero root.", shard_id)
        return "0" * 64

    tree = build_tree(hashes, preserve_order=True)
    logger.debug("Computed state root %s for shard %s.", tree.root_hash, shard_id)
    return tree.root_hash
