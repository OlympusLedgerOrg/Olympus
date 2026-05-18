"""
Operator — Ed25519 identity bound to a role-granting SBT credential.

An Operator is a node, agency, or platform operator that controls an Ed25519
keypair.  The public key IS the identity; email/password accounts are optional.

Lifecycle:
  pending   → created, SBT not yet issued (credential_id is None)
  active    → SBT bound (credential_id set, activated_at set)
  revoked   → revoked_at set; all API keys for this operator stop working

API keys minted via POST /auth/operator/keys carry operator_id so every
authenticated request can answer: "which Ed25519 identity made this call, and
what SBT role authorises it?"
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class Operator(Base):
    """Ed25519 identity with a role-granting SBT credential.

    Attributes:
        id: UUID primary key.
        ed25519_public_key: Hex-encoded 32-byte Ed25519 public key (64 hex chars).
            This IS the operator's cryptographic identity — no email required.
        credential_id: FK to ``key_credentials.id`` — the SBT that grants this
            role.  NULL until the SBT is issued; the operator is ``pending``
            until then.
        role: Well-known role string.  Known values:
            ``"node_operator"``, ``"agency_operator"``, ``"admin"``,
            ``"auditor"``.  Custom roles are allowed; authorization logic
            checks scopes on the API key rather than this field.
        label: Human-readable display name (node hostname, agency name, etc.)
        created_at: UTC timestamp of operator record creation (naive, UTC).
        activated_at: UTC timestamp when the SBT was bound and the operator
            became active.  NULL while pending.
        revoked_at: UTC timestamp of revocation.  When set, all API keys
            minted for this operator are treated as expired.
    """

    __tablename__ = "operators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # The cryptographic identity — never derive identity from email alone.
    ed25519_public_key: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    # SBT/role credential.  Nullable until issuance; SET NULL on credential
    # deletion so the operator record survives (revocation path).
    credential_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("key_credentials.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="node_operator")
    label: Mapped[str] = mapped_column(String(256), nullable=False)
    # Naive UTC — matches the rest of the schema (SQLAlchemy DateTime without tz)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
