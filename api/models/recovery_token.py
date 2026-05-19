from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class PasswordRecoveryToken(Base):
    """Single-use password recovery token record.

    The raw token is returned only at creation/delivery time and is never
    stored. Verification hashes the presented token and looks up this row.
    """

    __tablename__ = "password_recovery_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Columns are intentionally naive-`DateTime` (not `DateTime(timezone=True)`)
    # to match the `_naive_utc()` comparison pattern used elsewhere in the
    # auth layer (api/routers/user_auth.py).  The default for `created_at`
    # is also naive UTC for the same reason — passing a tz-aware default
    # against a naive column would break direct Python comparisons even
    # though postgres would coerce the stored value.
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
