"""
CredentialConsent — chain-agnostic explicit holder consent before SBT issuance.

The holder signs a canonical JSON payload with their Ed25519 signing key to
prove they explicitly requested a credential with the stated burn_authorization.
No Ethereum wallet or EVM chain is required.

Consent is recorded and verified before KeyCredential.issued_at is set.
It is the permanent audit artifact proving the holder requested this credential
under these exact terms.  If the holder later wants an on-chain ERC-5484 mirror
they bind a wallet separately (AccountWalletBinding); that path is optional and
does not alter this record.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class CredentialConsent(Base):
    """Explicit holder consent to receive a credential under stated terms.

    The holder signs ``consent_payload`` (JCS/RFC 8785 canonical JSON) with the
    Ed25519 private key corresponding to ``signing_key_id``.  The signature is
    stored in ``consent_signature`` and re-verified at issuance time so that the
    issuer cannot mint a credential the holder never requested.

    Lifecycle:
        pending  → accepted_at is None, revoked_at is None  (awaiting issuance)
        accepted → accepted_at is set                       (credential minted)
        revoked  → revoked_at is set                        (consent withdrawn before issuance)
    """

    __tablename__ = "credential_consents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    signing_key_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("account_signing_keys.key_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Credential parameters the holder explicitly agreed to
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)
    burn_authorization: Mapped[str] = mapped_column(
        String(32), nullable=False, default="issuer_only"
    )

    # The exact JCS-encoded payload that was signed.  Stored verbatim so any
    # verifier can re-derive the signature without trusting the API.
    # Set in the challenge step; never changes after creation.
    consent_payload: Mapped[str] = mapped_column(Text, nullable=False)

    # Hex-encoded Ed25519 signature (128 hex chars = 64 raw bytes).
    # NULL while the consent is in the pending-challenge state; set in the accept step.
    consent_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Random nonce preventing replay of an old consent for a new credential.
    nonce: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Set when the credential is issued against this consent (one-to-one).
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Set if the holder withdraws consent before issuance.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
