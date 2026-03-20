"""
MerkleNode ORM model for the Olympus FOIA ledger.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class MerkleNode(Base):
    """A node in the persistent Merkle tree for a given shard.

    The tree is rebuilt whenever new commits arrive in the shard.
    Leaf nodes correspond to individual DocCommit records.

    Attributes:
        id: UUID primary key.
        shard_id: The ledger shard this node belongs to.
        level: 0 = leaf, increasing = parent.
        position: Left-to-right position at this level.
        hash: Hex-encoded BLAKE3 hash of this node.
        left_child_id: FK to the left child node.
        right_child_id: FK to the right child node.
        created_at: When this node was persisted.
    """

    __tablename__ = "merkle_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    left_child_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("merkle_nodes.id"), nullable=True
    )
    right_child_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("merkle_nodes.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
