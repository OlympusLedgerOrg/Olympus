"""
Purchase ORM model for revenue tracking.

Each row represents a completed purchase tied to a :class:`User`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class Purchase(Base):
    """A completed purchase event.

    Attributes:
        id: UUID primary key.
        user_id: FK to the purchasing user.
        price: Transaction amount (USD).
        description: Short human-readable description of the purchase.
        created_at: UTC timestamp of the transaction.
    """

    __tablename__ = "purchases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    price: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
