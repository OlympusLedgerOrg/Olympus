"""
Timestamp utilities for Olympus.

Provides RFC3339 / ISO-8601 UTC timestamps with Z suffix.
"""

from datetime import UTC, datetime


def current_timestamp() -> str:
    """
    Return the current UTC timestamp in RFC3339 / ISO-8601 format.

    The timestamp is timezone-aware, uses the Python 3.12 UTC alias,
    and normalizes the offset to a trailing 'Z'.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
