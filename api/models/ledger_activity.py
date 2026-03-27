"""
LedgerActivity ORM model for human-readable ledger events.

Stores plain-English descriptions of ledger operations so that
non-technical users can follow what is happening without needing to
understand cryptographic primitives.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base


class LedgerActivity(Base):
    """Human-readable ledger activity log for non-technical users.

    Every significant ledger operation (document submission, verification,
    error) is recorded here in plain English alongside the technical commit
    reference.

    Attributes:
        id: UUID primary key.
        timestamp: When the activity occurred (UTC).
        activity_type: Machine-readable category such as ``"DOCUMENT_SUBMITTED"``,
            ``"VERIFICATION_SUCCESS"``, or ``"ERROR"``.
        title: Short human-readable title, e.g. "Document Successfully Added".
        description: Plain-English explanation of what happened.
        related_commit_id: Optional link to the underlying ``DocCommit``.
        related_request_id: Optional link to the originating FOIA request.
        user_friendly_status: Display badge such as "✓ Complete" or "✗ Failed".
        details_json: Optional JSON blob with additional context.
        error_help_text: What the user should do if this is an error event.
    """

    __tablename__ = "ledger_activities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    related_commit_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    related_request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    user_friendly_status: Mapped[str] = mapped_column(String(32), nullable=False)
    details_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_help_text: Mapped[str | None] = mapped_column(Text, nullable=True)
