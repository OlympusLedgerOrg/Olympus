from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
