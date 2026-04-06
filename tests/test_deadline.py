"""
Tests for api.services.deadline — Statutory deadline computation.

Covers:
- _add_business_days() weekend skipping
- compute_deadline() for each request type
- is_overdue() status checks
- Edge cases: Friday filing, zero business days
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from api.services.deadline import (
    STATUTORY_FOIA_DAYS,
    STATUTORY_NC_ACK_DAYS,
    STATUTORY_NC_FULFILL_DAYS,
    _add_business_days,
    compute_deadline,
    is_overdue,
)


# ------------------------------------------------------------------ #
# _add_business_days
# ------------------------------------------------------------------ #


class TestAddBusinessDays:
    """Tests for the _add_business_days() helper."""

    def test_zero_business_days(self) -> None:
        """Zero business days returns the same date."""
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday
        result = _add_business_days(start, 0)
        assert result.date() == start.date()

    def test_one_business_day_monday(self) -> None:
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday
        result = _add_business_days(start, 1)
        assert result.date().weekday() == 1  # Tuesday

    def test_five_business_days_spans_week(self) -> None:
        """5 business days from Monday = next Monday."""
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday
        result = _add_business_days(start, 5)
        assert result.date() == datetime(2024, 1, 22).date()  # Next Monday

    def test_weekend_skipping(self) -> None:
        """Filing on Friday: 1 business day = next Monday."""
        friday = datetime(2024, 1, 19, 9, 0, tzinfo=timezone.utc)  # Friday
        result = _add_business_days(friday, 1)
        assert result.date() == datetime(2024, 1, 22).date()  # Monday
        assert result.date().weekday() == 0

    def test_preserves_time_of_day(self) -> None:
        start = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        result = _add_business_days(start, 1)
        assert result.hour == 14
        assert result.minute == 30
        assert result.second == 45

    def test_preserves_timezone(self) -> None:
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)
        result = _add_business_days(start, 1)
        assert result.tzinfo == timezone.utc

    def test_twenty_business_days(self) -> None:
        """20 business days = 4 calendar weeks."""
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday
        result = _add_business_days(start, 20)
        assert result.date() == datetime(2024, 2, 12).date()  # 4 weeks later Monday

    def test_negative_business_days_rejected(self) -> None:
        start = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="non-negative"):
            _add_business_days(start, -1)

    def test_saturday_start(self) -> None:
        """Starting on Saturday: 1 business day = Monday."""
        saturday = datetime(2024, 1, 20, 9, 0, tzinfo=timezone.utc)
        result = _add_business_days(saturday, 1)
        assert result.date() == datetime(2024, 1, 22).date()  # Monday

    def test_sunday_start(self) -> None:
        """Starting on Sunday: 1 business day = Monday."""
        sunday = datetime(2024, 1, 21, 9, 0, tzinfo=timezone.utc)
        result = _add_business_days(sunday, 1)
        assert result.date() == datetime(2024, 1, 22).date()  # Monday


# ------------------------------------------------------------------ #
# compute_deadline
# ------------------------------------------------------------------ #


class TestComputeDeadline:
    """Tests for compute_deadline()."""

    def test_federal_foia(self) -> None:
        filed = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)  # Monday
        deadline = compute_deadline(filed, "FEDERAL_FOIA")
        expected = _add_business_days(filed, STATUTORY_FOIA_DAYS)
        assert deadline == expected

    def test_nc_public_records(self) -> None:
        filed = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)
        deadline = compute_deadline(filed, "NC_PUBLIC_RECORDS")
        expected = _add_business_days(filed, STATUTORY_NC_FULFILL_DAYS)
        assert deadline == expected

    def test_ferpa_same_as_nc(self) -> None:
        filed = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)
        deadline = compute_deadline(filed, "FERPA")
        expected = _add_business_days(filed, STATUTORY_NC_FULFILL_DAYS)
        assert deadline == expected

    def test_unknown_type_defaults_to_nc(self) -> None:
        """Unknown request types fall through to the NC/FERPA default."""
        filed = datetime(2024, 1, 15, 9, 0, tzinfo=timezone.utc)
        deadline = compute_deadline(filed, "UNKNOWN_TYPE")
        expected = _add_business_days(filed, STATUTORY_NC_FULFILL_DAYS)
        assert deadline == expected

    def test_constants_are_positive(self) -> None:
        assert STATUTORY_NC_ACK_DAYS > 0
        assert STATUTORY_NC_FULFILL_DAYS > 0
        assert STATUTORY_FOIA_DAYS > 0


# ------------------------------------------------------------------ #
# is_overdue
# ------------------------------------------------------------------ #


class TestIsOverdue:
    """Tests for is_overdue()."""

    def _make_request(
        self,
        status: str,
        deadline: datetime | None,
    ) -> MagicMock:
        """Create a mock PublicRecordsRequest."""
        from api.models.request import RequestStatus

        mock = MagicMock()
        mock.status = RequestStatus(status)
        mock.deadline = deadline
        return mock

    def test_overdue_pending_request(self) -> None:
        past_deadline = datetime(2020, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("PENDING", past_deadline)
        assert is_overdue(req)

    def test_overdue_acknowledged_request(self) -> None:
        past_deadline = datetime(2020, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("ACKNOWLEDGED", past_deadline)
        assert is_overdue(req)

    def test_overdue_in_review_request(self) -> None:
        past_deadline = datetime(2020, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("IN_REVIEW", past_deadline)
        assert is_overdue(req)

    def test_not_overdue_future_deadline(self) -> None:
        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("PENDING", future)
        assert not is_overdue(req)

    def test_not_overdue_fulfilled(self) -> None:
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("FULFILLED", past)
        assert not is_overdue(req)

    def test_not_overdue_denied(self) -> None:
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        req = self._make_request("DENIED", past)
        assert not is_overdue(req)

    def test_not_overdue_no_deadline(self) -> None:
        req = self._make_request("PENDING", None)
        assert not is_overdue(req)

    def test_naive_deadline_treated_as_utc(self) -> None:
        """Naive deadline (from SQLite) should be treated as UTC."""
        past_naive = datetime(2020, 1, 1)  # No tzinfo
        req = self._make_request("PENDING", past_naive)
        assert is_overdue(req)
