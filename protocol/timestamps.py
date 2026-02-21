"""Timestamp utilities for Olympus.

Provides RFC3339 / ISO-8601 UTC timestamps with Z suffix for ledger entries.

This module generates wall-clock timestamps. For cryptographic timestamp
anchoring via an external Timestamp Authority (RFC 3161 trusted timestamping),
see protocol/rfc3161.py instead.
"""

from datetime import UTC, datetime


def current_timestamp() -> str:
    """
    Return the current UTC timestamp in RFC3339 / ISO-8601 format.

    The timestamp is timezone-aware, uses the standard datetime.UTC alias,
    and normalizes the offset to a trailing 'Z'.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
