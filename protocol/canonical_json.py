"""
Canonical JSON encoder for Olympus protocol.

Provides a single deterministic encoding used across ledger hashing, shard
header hashing, and policy hashing. Number formatting is pinned to avoid
cross-language divergence:
* Reject NaN/±Infinity
* Integers emitted in base-10 without leading zeros
* Non-integers trimmed of insignificant trailing zeros
* Fixed notation when -6 <= exp10 <= 20; otherwise scientific
* Scientific notation uses one digit before the decimal and exponent form
  e[+|-]D with no leading zeros
* -0 normalized to 0
"""

from decimal import Decimal, InvalidOperation
import math
from typing import Any

from json.encoder import encode_basestring_ascii


def canonical_json_encode(obj: Any) -> str:
    """
    Encode object to canonical JSON string.

    Rules:
    - UTF-8 encoding (ASCII-escaped)
    - Sorted keys
    - No whitespace (compact separators)
    - Reject NaN and Infinity
    - Deterministic, stable numeric formatting (see module docstring)

    Args:
        obj: Object to encode (must be JSON-serializable)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains NaN or Infinity
        TypeError: If object is not JSON-serializable
    """
    _validate_no_special_floats(obj)
    return _encode_value(obj)


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
    elif isinstance(obj, Decimal):
        if not obj.is_finite():
            raise ValueError("Infinity is not allowed in canonical JSON")
    elif isinstance(obj, dict):
        for value in obj.values():
            _validate_no_special_floats(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_no_special_floats(item)


def _encode_value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return encode_basestring_ascii(value)
    if isinstance(value, (int, Decimal, float)) and not isinstance(value, bool):
        return _encode_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode_value(item) for item in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise TypeError("Object keys must be strings for canonical JSON")
            items.append(f"{encode_basestring_ascii(key)}:{_encode_value(value[key])}")
        return "{" + ",".join(items) + "}"
    raise TypeError(f"Type {type(value)} is not JSON-serializable")


def _encode_number(value: int | float | Decimal) -> str:
    dec_value = _to_decimal(value)
    if dec_value.is_zero():
        return "0"

    dec_value = dec_value.normalize()
    sign = "-" if dec_value.is_signed() else ""
    dec_value = abs(dec_value)

    digits = "".join(str(d) for d in dec_value.as_tuple().digits)
    exponent = dec_value.as_tuple().exponent
    adjusted_exponent = dec_value.adjusted()

    if -6 <= adjusted_exponent <= 20:
        formatted = _format_fixed(digits, exponent)
    else:
        formatted = _format_scientific(digits, adjusted_exponent)

    return sign + formatted


def _to_decimal(value: int | float | Decimal) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Infinity is not allowed in canonical JSON")
        try:
            return Decimal(str(value))
        except InvalidOperation as exc:  # pragma: no cover - defensive
            raise ValueError("Invalid float value for canonical JSON") from exc
    return Decimal(value)


def _format_fixed(digits: str, exponent: int) -> str:
    if exponent >= 0:
        return digits + ("0" * exponent)

    idx = len(digits) + exponent
    if idx > 0:
        return digits[:idx] + "." + digits[idx:]
    return "0." + ("0" * -idx) + digits


def _format_scientific(digits: str, adjusted_exponent: int) -> str:
    if len(digits) == 1:
        mantissa = digits
    else:
        mantissa = digits[0] + "." + digits[1:]
    exponent_part = f"e{adjusted_exponent:+d}"
    return mantissa + exponent_part
