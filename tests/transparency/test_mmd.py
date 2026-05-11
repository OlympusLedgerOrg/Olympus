from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.transparency.mmd import MaximumMergeDelay, check_mmd


def test_mmd_passes_when_within_window() -> None:
    submission = datetime.now(timezone.utc)
    inclusion = submission + timedelta(seconds=45)
    assert check_mmd(submission, inclusion, MaximumMergeDelay(seconds=60)) is None


def test_mmd_violation_when_beyond_window() -> None:
    submission = datetime.now(timezone.utc)
    inclusion = submission + timedelta(seconds=90)
    violation = check_mmd(submission, inclusion, MaximumMergeDelay(seconds=60))
    assert violation is not None
    assert violation.observed_lag_seconds >= 90


def test_mmd_naive_datetime_raises() -> None:
    submission = datetime(2026, 1, 1, 0, 0, 0)  # no tzinfo
    inclusion = datetime(2026, 1, 1, 0, 1, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        check_mmd(submission, inclusion)
