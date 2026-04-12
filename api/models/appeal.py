"""
Appeal ORM model.

An appeal challenges an agency response (or non-response) to a public-records
request.  Each appeal is anchored to the ledger via a BLAKE3 commit hash.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base


class AppealGrounds(str, enum.Enum):
    """Grounds for filing an appeal."""

    NO_RESPONSE = "NO_RESPONSE"
    IMPROPER_EXEMPTION = "IMPROPER_EXEMPTION"
    PARTIAL_RESPONSE = "PARTIAL_RESPONSE"
    EXCESSIVE_FEE = "EXCESSIVE_FEE"
    BAD_FAITH = "BAD_FAITH"


class AppealStatus(str, enum.Enum):
    """Lifecycle status of an appeal."""

    UNDER_REVIEW = "UNDER_REVIEW"
    UPHELD = "UPHELD"
    OVERTURNED = "OVERTURNED"
    DENIED_ON_APPEAL = "DENIED_ON_APPEAL"


class Appeal(Base):
    """An appeal against an agency's response to a public-records request.

    Attributes:
        id: UUID primary key.
        request_id: FK to the original PublicRecordsRequest.
        grounds: Legal grounds for the appeal.
        statement: Narrative statement supporting the appeal.
        filed_at: UTC timestamp of filing.
        status: Current review status.
        commit_hash: BLAKE3 hex of the canonical appeal at filing time.
    """

    __tablename__ = "appeals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("public_records_requests.id"), nullable=False
    )
    grounds: Mapped[str] = mapped_column(
        SAEnum(AppealGrounds, name="appeal_grounds"), nullable=False
    )
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    filed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[str] = mapped_column(
        SAEnum(AppealStatus, name="appeal_status"),
        nullable=False,
        default=AppealStatus.UNDER_REVIEW,
    )
    commit_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # Relationships
    request: Mapped[Any] = relationship(
        "PublicRecordsRequest", back_populates="appeal"
    )
