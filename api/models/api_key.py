from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class ApiKey(Base):
    """Database-backed API key.

    The raw key is never stored — only the BLAKE3 hash matching auth._hash_key.
    The raw key is returned once at creation and never again.

    Operator-bound keys carry ``operator_id`` and ``ed25519_public_key`` so
    every authenticated request can answer:
        "which Ed25519 identity made this call?"
        "which SBT/role credential authorises it?"

    Legacy user-only keys (created before operator support) leave the operator
    columns NULL and continue to work via the existing ``user_id`` FK.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # ── User account binding (legacy; kept for backward compatibility) ─────────
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True, index=True
    )
    # ── Operator identity binding ─────────────────────────────────────────────
    # When operator_id is set this key belongs to an Operator entity.
    # ed25519_public_key is denormalised from the Operator row for fast
    # per-request identity resolution without an extra join.
    operator_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("operators.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    ed25519_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # The SBT/role credential currently granting authority to this key.
    # Nullable — an operator key may be minted before the SBT is issued.
    credential_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("key_credentials.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # ── Key metadata ──────────────────────────────────────────────────────────
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default='["ingest","verify"]')
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Updated on every authenticated request (DB-lookup path only).
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
