"""Maximum Merge Delay (MMD) scaffolds.

Why this module exists:
    MMD gives submitters objective evidence when a queued record is not merged
    into a publicly signed root within the promised time window.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MaximumMergeDelay:
    """MMD configuration for transparency checks."""

    seconds: int = 60


@dataclass(frozen=True, slots=True)
class MMDViolation:
    """Cryptographic evidence candidate for merge-delay policy breach."""

    submission_time: str
    inclusion_root_time: str
    max_merge_delay_seconds: int
    observed_lag_seconds: int


def check_mmd(
    submission_time: datetime,
    inclusion_root_time: datetime,
    mmd: MaximumMergeDelay | None = None,
) -> MMDViolation | None:
    """Return an ``MMDViolation`` when inclusion exceeds configured delay."""
    try:
        effective_mmd = mmd or MaximumMergeDelay()
        if submission_time.tzinfo is None or inclusion_root_time.tzinfo is None:
            raise ValueError("submission_time and inclusion_root_time must be timezone-aware")

        submission_utc = submission_time.astimezone(timezone.utc)
        inclusion_utc = inclusion_root_time.astimezone(timezone.utc)

        if inclusion_utc <= submission_utc + timedelta(seconds=effective_mmd.seconds):
            return None

        lag_seconds = int((inclusion_utc - submission_utc).total_seconds())
        return MMDViolation(
            submission_time=submission_utc.isoformat().replace("+00:00", "Z"),
            inclusion_root_time=inclusion_utc.isoformat().replace("+00:00", "Z"),
            max_merge_delay_seconds=effective_mmd.seconds,
            observed_lag_seconds=lag_seconds,
        )
    except Exception:
        logger.error("Failed to evaluate maximum merge delay", exc_info=True)
        raise
