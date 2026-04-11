"""
DocCommit ORM model.

Records the cryptographic commitment of a document to the Olympus ledger.
Olympus stores hashes only — it never stores the underlying files.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base


if TYPE_CHECKING:
    from api.models.request import PublicRecordsRequest


class DocCommit(Base):
    """A cryptographic commitment anchoring a document hash to the ledger.

    Attributes:
        id: UUID primary key.
        request_id: Optional FK to the originating PublicRecordsRequest.
        doc_hash: BLAKE3 hex hash of the document content.
        commit_id: Unique ``0x``-prefixed hex commit identifier.
        epoch_timestamp: UTC timestamp of the commitment.
        shard_id: Ledger shard this commit belongs to.
        merkle_root: Merkle root of the shard at the time of this commit.
        zk_proof: Serialised Groth16 proof stub (populated asynchronously).
        embargo_until: If set, the commit is embargoed until this timestamp.
        is_multi_recipient: Whether this commit covers multiple recipients.
    """

    __tablename__ = "doc_commits"
    __table_args__ = (UniqueConstraint("doc_hash", name="ix_doc_commits_doc_hash_unique"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("public_records_requests.id"), nullable=True
    )
    doc_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_id: Mapped[str] = mapped_column(String(66), nullable=False, unique=True)
    epoch_timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, default="0x4F3A")
    merkle_root: Mapped[str | None] = mapped_column(String(64), nullable=True)
    zk_proof: Mapped[str | None] = mapped_column(Text, nullable=True)
    embargo_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_multi_recipient: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    request: Mapped[PublicRecordsRequest | None] = relationship(
        "PublicRecordsRequest", back_populates="doc_commits"
    )
