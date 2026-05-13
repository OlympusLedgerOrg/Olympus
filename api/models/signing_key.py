from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class AccountSigningKey(Base):
    """Account-bound Ed25519 public signing key.

    Only the public verification key is stored. Private key material is generated
    and kept by the operator/user outside the database.
    """

    __tablename__ = "account_signing_keys"

    key_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    public_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False, default="dataset")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_by_key_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    replaced_by_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AccountWalletBinding(Base):
    """Ethereum wallet proof bound to an account signing key.

    This records wallet control for later SBT mint eligibility. It stores only
    the wallet address and challenge metadata, never Ed25519 private key
    material or wallet secrets.
    """

    __tablename__ = "account_wallet_bindings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    signing_key_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("account_signing_keys.key_id"), nullable=False, index=True
    )
    wallet_address: Mapped[str] = mapped_column(String(42), nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    challenge_message: Mapped[str] = mapped_column(String(512), nullable=False)
    erc_standard: Mapped[str] = mapped_column(String(16), nullable=False, default="ERC-5484")
    burn_authorization: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
