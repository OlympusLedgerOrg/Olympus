"""
User ORM model with role-based access control (RBAC).

Supports ``"user"`` and ``"admin"`` roles.  Admin users can access
platform statistics and the customer registry.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class User(Base):
    """Platform user with RBAC role.

    Attributes:
        id: UUID primary key.
        email: Unique email address.
        role: ``"user"`` (default) or ``"admin"``.
        plan: Subscription plan — ``"free"``, ``"pro"``, etc.
        created_at: UTC timestamp of account creation.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
