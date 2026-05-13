"""
CredentialLedgerEvent — auditable per-event log entry for credential lifecycle.

Every state change (issued, revoked, burned) is recorded here with its own
ledger commit_id.  The commit_id anchors the event to the Olympus SMT so that
any verifier can request an SMT inclusion proof for the event without trusting
the API.

The `inclusion_proof` and `smt_root` columns are populated asynchronously by
api/services/credential_anchor.py after the synchronous DB write succeeds.
They may be None for a brief window after event creation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class CredentialLedgerEvent(Base):
    """One immutable ledger event in the lifecycle of a KeyCredential.

    event_type values:
        "issued"  — credential was minted (first event for a credential)
        "revoked" — issuer or holder invoked revocation
        "burned"  — alias for revoked used when the ERC-5484 mirror is also burned

    The combination (credential_id, event_type, ledger_commit_id) is the
    canonical identity of the event for cross-node federation verification.
    """

    __tablename__ = "credential_ledger_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    credential_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("key_credentials.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # "issued" | "revoked" | "burned"
    event_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    # 0x-prefixed random commit hash — same format as KeyCredential.commit_id.
    # This is the primary key into the Olympus ledger for this event.
    ledger_commit_id: Mapped[str] = mapped_column(
        String(66), nullable=False, unique=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # SMT state at the time of the event — populated by credential_anchor service.
    # JSON-encoded list of {"direction": "left"|"right", "hash": "0x…"} sibling nodes.
    inclusion_proof: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Hex-encoded SMT root when the inclusion_proof was generated.
    smt_root: Mapped[str | None] = mapped_column(String(66), nullable=True)
