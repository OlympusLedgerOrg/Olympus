"""
Agency ORM model.

Represents a government agency that receives public-records requests.
Response-rate statistics are computed at query time and stored as cached
values here for dashboard performance.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum as SAEnum, Float, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base


class AgencyLevel(str, enum.Enum):
    """Jurisdictional level of a government agency."""

    MUNICIPAL = "MUNICIPAL"
    COUNTY = "COUNTY"
    STATE = "STATE"
    FEDERAL = "FEDERAL"


class Agency(Base):
    """Government agency that receives public-records or FOIA requests.

    Attributes:
        id: UUID primary key.
        name: Full legal name of the agency.
        short_name: Abbreviated display name.
        level: Jurisdictional level (municipal → federal).
        category: Functional category, e.g. "Law Enforcement".
        avg_response_days: Cached average calendar days to respond.
        compliance_rate: Cached fraction (0–1) of on-time responses.
        requests: Back-reference to all linked PublicRecordsRequest rows.
    """

    __tablename__ = "agencies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    short_name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    level: Mapped[str] = mapped_column(
        SAEnum(AgencyLevel, name="agency_level"), nullable=False, default=AgencyLevel.STATE
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    avg_response_days: Mapped[float | None] = mapped_column(Float, nullable=True)
    compliance_rate: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationships
    requests: Mapped[list] = relationship("PublicRecordsRequest", back_populates="agency")
