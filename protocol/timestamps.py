"""Timestamp utilities for Olympus.

Provides RFC3339 / ISO-8601 UTC timestamps with Z suffix for ledger entries.

This module generates wall-clock timestamps. For cryptographic timestamp
anchoring via an external Timestamp Authority (RFC 3161 trusted timestamping),
see protocol/rfc3161.py instead.
"""

import time
from datetime import datetime, timezone


_last_timestamp_us = 0


def current_timestamp() -> str:
    """
    Return the current UTC timestamp in RFC3339 / ISO-8601 format.

    The timestamp is timezone-aware and normalizes the offset to a trailing 'Z'.
    """
    global _last_timestamp_us

    timestamp_us = time.time_ns() // 1_000
    if timestamp_us <= _last_timestamp_us:
        timestamp_us = _last_timestamp_us + 1
    _last_timestamp_us = timestamp_us

    return datetime.fromtimestamp(timestamp_us / 1_000_000, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
