"""
PublicRecordsRequest ORM model.

Covers both NC Public Records requests (G.S. § 132) and Federal FOIA
requests (5 U.S.C. § 552).  The commit_hash anchors the request to the
cryptographic ledger at filing time.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum as SAEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base


if TYPE_CHECKING:
    from api.models.agency import Agency
    from api.models.appeal import Appeal


class RequestType(str, enum.Enum):
    """Legal basis for the request."""

    NC_PUBLIC_RECORDS = "NC_PUBLIC_RECORDS"  # G.S. § 132
    FEDERAL_FOIA = "FEDERAL_FOIA"            # 5 U.S.C. § 552
    FERPA = "FERPA"


class RequestStatus(str, enum.Enum):
    """Lifecycle status of a public-records request."""

    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_REVIEW = "IN_REVIEW"
    FULFILLED = "FULFILLED"
    DENIED = "DENIED"
    OVERDUE = "OVERDUE"
    APPEALED = "APPEALED"


class RequestPriority(str, enum.Enum):
    """Processing priority of the request."""

    STANDARD = "STANDARD"
    EXPEDITED_SAFETY = "EXPEDITED_SAFETY"
    EXPEDITED_PUBLIC_INTEREST = "EXPEDITED_PUBLIC_INTEREST"


class PublicRecordsRequest(Base):
    """A public-records or FOIA request anchored to the Olympus ledger.

    The ``commit_hash`` field contains the SHA-256 of the canonical request
    content at filing time, giving a tamper-evident record of the original
    request.  Olympus stores hashes only — never the underlying documents.

    Attributes:
        id: UUID primary key.
        display_id: Human-readable identifier, e.g. "OLY-0042".
        subject: One-line subject of the request.
        description: Full narrative description of the requested records.
        agency_id: FK to the receiving Agency.
        request_type: Legal framework (NC Public Records, FOIA, FERPA).
        status: Current lifecycle status.
        date_from: Optional start of the date range being requested.
        date_to: Optional end of the date range being requested.
        response_format: Preferred delivery format, e.g. "electronic".
        fee_waiver_basis: Grounds for fee waiver, if requested.
        priority: Processing priority.
        filed_at: Timestamp the request was filed (UTC).
        deadline: Computed statutory deadline (UTC).
        fulfilled_at: Timestamp of fulfillment, if applicable.
        commit_hash: SHA-256 hex of the canonical request at filing time.
        shard_id: Ledger shard this request is anchored to.
    """

    __tablename__ = "public_records_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    display_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    agency_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("agencies.id"), nullable=True
    )
    request_type: Mapped[str] = mapped_column(
        SAEnum(RequestType, name="request_type"),
        nullable=False,
        default=RequestType.NC_PUBLIC_RECORDS,
    )
    status: Mapped[str] = mapped_column(
        SAEnum(RequestStatus, name="request_status"),
        nullable=False,
        default=RequestStatus.PENDING,
    )
    date_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    date_to: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    response_format: Mapped[str] = mapped_column(String(128), nullable=False, default="electronic")
    fee_waiver_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(
        SAEnum(RequestPriority, name="request_priority"),
        nullable=False,
        default=RequestPriority.STANDARD,
    )
    filed_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    deadline: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    fulfilled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    commit_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    shard_id: Mapped[str] = mapped_column(String(32), nullable=False, default="0x4F3A")

    # Relationships
    agency: Mapped[Agency | None] = relationship("Agency", back_populates="requests")
    appeal: Mapped[Appeal | None] = relationship(
        "Appeal", back_populates="request", uselist=False
    )
    doc_commits: Mapped[list] = relationship("DocCommit", back_populates="request")
