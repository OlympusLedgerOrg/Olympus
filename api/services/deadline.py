"""
Statutory deadline computation for public-records requests.

Handles business-day calculation for:
- NC Public Records (G.S. § 132) — no explicit statutory deadline, but
  Olympus flags requests as OVERDUE after configurable thresholds.
- Federal FOIA (5 U.S.C. § 552(a)(6)(A)) — 20 business days.
- FERPA — treated the same as NC Public Records for now.

Business days exclude weekends (Saturday, Sunday).  Holiday exclusion is
not yet implemented but is designed in as an extension point.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone


def _now_utc() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# NC Public Records: no explicit statutory deadline, but we flag OVERDUE
# after STATUTORY_NC_FULFILL_DAYS business days without fulfilment.
STATUTORY_NC_ACK_DAYS = 14    # G.S. § 132 — acknowledgment threshold
STATUTORY_NC_FULFILL_DAYS = 30  # G.S. § 132 — fulfilment threshold

# Federal FOIA: 20 business days per 5 U.S.C. § 552(a)(6)(A)
STATUTORY_FOIA_DAYS = 20


def _add_business_days(start: datetime, business_days: int) -> datetime:
    """Return a datetime that is ``business_days`` business days after ``start``.

    Weekends (Saturday = 5, Sunday = 6) are skipped.

    Args:
        start: Starting datetime (UTC).
        business_days: Number of business days to add (must be ≥ 0).

    Returns:
        Datetime representing the deadline.
    """
    if business_days < 0:
        raise ValueError("business_days must be non-negative.")

    current: date = start.date()
    remaining = business_days

    while remaining > 0:
        current += timedelta(days=1)
        # 0=Monday … 4=Friday are business days; 5=Sat, 6=Sun are not
        if current.weekday() < 5:
            remaining -= 1

    # Preserve the original time-of-day component
    return datetime.combine(current, start.time(), tzinfo=start.tzinfo)


def compute_deadline(filed_at: datetime, request_type: str) -> datetime:
    """Compute the statutory deadline for a public-records request.

    Args:
        filed_at: Filing timestamp (UTC).
        request_type: One of ``"NC_PUBLIC_RECORDS"``, ``"FEDERAL_FOIA"``,
                      or ``"FERPA"``.

    Returns:
        Deadline datetime.  For NC Public Records and FERPA, this is the
        *fulfilment* threshold (30 business days) because there is no explicit
        statutory limit.
    """
    if request_type == "FEDERAL_FOIA":
        # 5 U.S.C. § 552(a)(6)(A) — 20 business days
        return _add_business_days(filed_at, STATUTORY_FOIA_DAYS)

    # NC Public Records (G.S. § 132) and FERPA — use the fulfilment threshold
    return _add_business_days(filed_at, STATUTORY_NC_FULFILL_DAYS)


def is_overdue(request) -> bool:
    """Return True if a request should be transitioned to OVERDUE.

    Args:
        request: A :class:`api.models.request.PublicRecordsRequest` instance.

    Returns:
        ``True`` if the deadline has passed and the request is still open.
    """
    from api.models.request import RequestStatus  # noqa: PLC0415

    open_statuses = {
        RequestStatus.PENDING,
        RequestStatus.ACKNOWLEDGED,
        RequestStatus.IN_REVIEW,
    }
    if request.status not in open_statuses:
        return False

    if request.deadline is None:
        return False

    # Normalise naive deadlines stored by SQLite to UTC-aware for comparison
    deadline = request.deadline
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return _now_utc() > deadline

