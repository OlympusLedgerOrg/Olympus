"""
KeyCredential ORM model (SBT-style, non-transferable).

Credentials are anchored to the ledger at issuance and revocation time.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class KeyCredential(Base):
    """A non-transferable soulbound credential anchored to the ledger.

    Attributes:
        id: UUID primary key.
        holder_key: Public key or identifier of the credential holder.
        credential_type: Role descriptor, e.g. "journalist", "researcher".
        issued_at: UTC timestamp of issuance.
        revoked_at: UTC timestamp of revocation, or ``None`` if still active.
        issuer: Identifier of the issuing authority.
        sbt_nontransferable: Always ``True``; credentials cannot be transferred.
        commit_id: Ledger commit ID that anchors the issuance of this credential.
        revocation_commit_id: Ledger commit ID that anchors the revocation, or ``None`` if active.
    """

    __tablename__ = "key_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    holder_key: Mapped[str] = mapped_column(String(512), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)
    sbt_nontransferable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    commit_id: Mapped[str] = mapped_column(String(66), nullable=False, default="")
    revocation_commit_id: Mapped[str | None] = mapped_column(String(66), nullable=True)
