"""Timestamp utilities for Olympus protocol."""

from datetime import UTC, datetime


def current_timestamp() -> str:
    """Return current UTC timestamp in RFC 3339 format with Z suffix."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
