"""
Canonical JSON encoder for Olympus protocol.

This module provides a single canonical JSON encoding used consistently
across ledger hashing, shard header hashing, and policy hashing.

All JSON output must be deterministic and reproducible.
"""

import json
import math
from decimal import Decimal, InvalidOperation
from typing import Any

MIN_FIXED_POINT_EXPONENT = -6
MAX_FIXED_POINT_EXPONENT = 20


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

    return _serialize_canonical(obj)


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Encode object to canonical JSON bytes.

    Args:
        obj: Object to encode

    Returns:
        Canonical JSON as UTF-8 bytes
    """
    return canonical_json_encode(obj).encode("utf-8")


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


def _serialize_canonical(obj: Any) -> str:
    """
    Serialize object to canonical JSON following JCS-style rules.

    Rules enforced:
    - Sorted object keys
    - Compact separators (no whitespace)
    - ASCII-escaped output
    - Numbers encoded without trailing zeros and without scientific notation
      unless magnitude requires it
    """
    if isinstance(obj, dict):
        items = []
        for key in sorted(obj.keys()):
            key_str = json.dumps(key, ensure_ascii=True)
            value_str = _serialize_canonical(obj[key])
            items.append(f"{key_str}:{value_str}")
        return "{" + ",".join(items) + "}"

    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize_canonical(item) for item in obj) + "]"

    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)

    if isinstance(obj, float):
        return _format_number(obj)

    # Leverage json.dumps for remaining primitives/strings while maintaining ASCII escaping
    return json.dumps(obj, ensure_ascii=True, allow_nan=False)


def _format_number(value: float) -> str:
    """
    Format numbers to avoid trailing zeros and scientific notation unless required.
    """
    try:
        decimal_value = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Invalid number for canonical JSON") from exc

    normalized = decimal_value.normalize()

    # Use fixed-point for commonly encountered magnitudes to keep output compact;
    # switch to scientific notation only when fixed-point would add many leading/trailing zeros.
    exponent = normalized.adjusted()
    if exponent < MIN_FIXED_POINT_EXPONENT or exponent > MAX_FIXED_POINT_EXPONENT:
        return _format_scientific(normalized)

    # Use fixed-point representation to avoid scientific notation
    # At this range, fixed-point remains reasonably sized while staying human-auditable.
    text = format(normalized, "f")

    # Strip trailing zeros in fractional part while preserving at least one digit if needed
    if "." in text:
        text = text.rstrip("0").rstrip(".")

    # Handle negative zero edge case
    if text == "-0":
        text = "0"

    return text


def _format_scientific(decimal_value: Decimal) -> str:
    """
    Render Decimal in scientific notation with normalized exponent and no trailing zeros.
    """
    # Normalize using Python's scientific notation, then strip padding so output is stable
    # and minimal (e.g., '1e+21', '1e-7').
    sci = format(decimal_value, "e")
    significand, exp = sci.split("e")
    significand = significand.rstrip("0").rstrip(".")
    if significand == "-0":
        significand = "0"

    exp_int = int(exp)
    # Always include sign, but intentionally avoid zero-padding to keep strings compact.
    return f"{significand}e{exp_int:+d}"
