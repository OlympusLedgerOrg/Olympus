"""
KeyCredential ORM model — Olympus-native non-transferable credential.

Credentials are account-bound, signing-key-bound, and anchored to the ledger
at every lifecycle event (issuance, revocation).  Non-transferability is a
design invariant enforced at the application layer: there is no transfer
operation, and the DB schema has no destination-key column.

ERC-5484 on-chain mirroring is optional.  If the holder later binds an
Ethereum wallet (AccountWalletBinding) and requests a mirror, the contract
records the same burn_authorization value, but the Olympus-native credential
is the authoritative source of truth regardless of whether a mirror exists.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class KeyCredential(Base):
    """A non-transferable credential anchored to the Olympus ledger.

    Identity axes:
        account-bound    — holder_account_id links to users.id
        signing-key-bound — holder_key is the hex Ed25519 public key registered
                            in account_signing_keys; the holder proved possession
                            via Ed25519 signature at consent time

    Non-transferability is enforced by design: there is no ``transfer`` operation
    and no target-account column.  ``sbt_nontransferable`` is kept for API
    compatibility and is always True.

    Lifecycle events are recorded in CredentialLedgerEvent (one row per event)
    so that issuance and revocation can both be independently verified via SMT
    inclusion proofs without querying this table directly.
    """

    __tablename__ = "key_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # ── Identity binding ────────────────────────────────────────────────────────
    holder_key: Mapped[str] = mapped_column(String(512), nullable=False)
    # FK to users.id — account-bound; NULL for legacy pre-account credentials.
    holder_account_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # FK to credential_consents.id — the explicit Ed25519-signed consent artifact.
    # NULL for legacy credentials issued before consent tracking was added.
    consent_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("credential_consents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Credential metadata ─────────────────────────────────────────────────────
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer: Mapped[str] = mapped_column(String(256), nullable=False)

    # Chain-agnostic burn authorization (same vocabulary as ERC-5484 BurnAuth
    # so values can be passed directly to the optional Ethereum mirror).
    # "issuer_only" | "owner_only" | "both" | "neither"
    burn_authorization: Mapped[str] = mapped_column(
        String(32), nullable=False, default="issuer_only"
    )

    # ── Lifecycle ───────────────────────────────────────────────────────────────
    issued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Always True; kept for API compatibility.
    sbt_nontransferable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Ledger anchors ──────────────────────────────────────────────────────────
    # Primary commit anchoring the issuance event.
    commit_id: Mapped[str] = mapped_column(String(66), nullable=False, default="")
    revocation_commit_id: Mapped[str | None] = mapped_column(String(66), nullable=True)

    # API key that issued this credential — used for IDOR-safe revocation scoping.
    issued_by_key_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
