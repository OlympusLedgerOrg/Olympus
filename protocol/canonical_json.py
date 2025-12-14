"""
Canonical JSON encoder for Olympus protocol.

This module provides a single canonical JSON encoding used consistently
across ledger hashing, shard header hashing, and policy hashing.

All JSON output must be deterministic and reproducible.
"""

import json
import math
from typing import Any


def canonical_json_encode(obj: Any) -> str:
    """
    Encode object to canonical JSON string.

    Rules:
    - UTF-8 encoding
    - Sorted keys
    - No whitespace (compact separators)
    - Reject NaN and Infinity
    - Deterministic and stable output

    Args:
        obj: Object to encode (must be JSON-serializable)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains NaN or Infinity
        TypeError: If object is not JSON-serializable
    """
    # Check for NaN/Infinity in numeric values
    _validate_no_special_floats(obj)

    # Canonical JSON: sorted keys, compact separators, ASCII escape, deterministic
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
        allow_nan=False
    )


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Encode object to canonical JSON bytes.

    Args:
        obj: Object to encode

    Returns:
        Canonical JSON as UTF-8 bytes
    """
    return canonical_json_encode(obj).encode('utf-8')


def _validate_no_special_floats(obj: Any) -> None:
    """
    Recursively validate that object contains no NaN or Infinity values.

    Args:
        obj: Object to validate

    Raises:
        ValueError: If NaN or Infinity found
    """
    if isinstance(obj, float):
        if math.isnan(obj):
            raise ValueError("NaN is not allowed in canonical JSON")
        if math.isinf(obj):
            raise ValueError("Infinity is not allowed in canonical JSON")
    elif isinstance(obj, dict):
        for value in obj.values():
            _validate_no_special_floats(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_no_special_floats(item)
