"""
ORM models for the witness protocol observation store.

Replaces the in-process OrderedDict with a persistent DB-backed store
so that observations survive restarts and are shared across workers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class WitnessObservation(Base):
    """A recorded checkpoint announcement from a specific origin.

    Attributes:
        id: UUID primary key.
        key: Unique composite key ``origin_hash:sequence``.
        origin: Transparency log origin identifier.
        sequence: Ledger sequence number from the checkpoint.
        checkpoint_hash: Hex-encoded checkpoint hash.
        checkpoint_timestamp: ISO 8601 UTC timestamp from the checkpoint.
        received_at: Server-assigned reception timestamp.
        nonce: Unique nonce used for replay-resistance.
        announcement_json: Full serialized WitnessAnnouncement for reconstruction.
        created_at: Row creation timestamp.
    """

    __tablename__ = "witness_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    origin: Mapped[str] = mapped_column(String(256), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    checkpoint_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    checkpoint_timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    announcement_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class WitnessNonce(Base):
    """Nonce deduplication table for witness announcements.

    Attributes:
        id: UUID primary key.
        nonce: Unique nonce string.
        created_at: Row creation timestamp.
    """

    __tablename__ = "witness_nonces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
