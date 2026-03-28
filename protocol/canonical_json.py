"""
Canonical JSON encoder for Olympus protocol.

Provides a single deterministic encoding used across ledger hashing, shard
header hashing, and policy hashing.  The encoding follows RFC 8785 (JCS —
JSON Canonicalization Scheme) so that any standards-compliant JCS library
produces byte-for-byte identical output:

* Normalize all object keys and string values to Unicode NFC
* Reject language-native float values (require Decimal for non-integers)
* Reject NaN/±Infinity
* Integers emitted in base-10 without leading zeros
* Non-integers trimmed of insignificant trailing zeros
* Fixed notation when -6 <= exp10 <= 20; otherwise scientific
* Scientific notation uses one digit before the decimal and exponent form
  e[+|-]D with no leading zeros
* -0 normalized to 0
* Non-ASCII characters emitted as raw UTF-8 (NOT \\uXXXX); control characters
  U+0000–U+001F use standard JSON escapes (\\b \\t \\n \\f \\r \\uXXXX)
"""

import json
import math
import unicodedata
from decimal import Decimal
from typing import Any


# ---------------------------------------------------------------------------
# Optional Rust acceleration — import from olympus_core.canonical if built,
# fall back to the pure-Python implementation below when it is not present.
# ---------------------------------------------------------------------------
try:
    from olympus_core.canonical import (  # type: ignore[import-not-found]
        canonical_json_encode as _rust_canonical_json_encode,
    )

    _RUST_CANONICAL_AVAILABLE = True
except ImportError:
    _RUST_CANONICAL_AVAILABLE = False


def canonical_json_encode(obj: Any) -> str:
    """
    Encode object to canonical JSON string.

    Rules:
    - UTF-8 encoding with raw non-ASCII (JCS / RFC 8785 compliant)
    - Sorted keys
    - No whitespace (compact separators)
    - Unicode NFC normalization for all keys and string values
    - Reject language-native floats, NaN, and Infinity
    - Deterministic, stable numeric formatting (see module docstring)

    Args:
        obj: Object to encode (must be JSON-serializable)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains NaN or Infinity
        TypeError: If object is not JSON-serializable
    """
    if _RUST_CANONICAL_AVAILABLE:
        result: str = _rust_canonical_json_encode(obj)
        return result
    normalized = _normalize_for_canonical_json(obj)
    return _encode_value(normalized)


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Encode object to canonical JSON bytes.

    Args:
        obj: Object to encode

    Returns:
        Canonical JSON as UTF-8 bytes
    """
    return canonical_json_encode(obj).encode("utf-8")


def _normalize_for_canonical_json(obj: Any) -> Any:
    """
    Normalize object values before canonical JSON encoding.

    Args:
        obj: Object to normalize.

    Returns:
        Object transformed into normalized canonical values.

    Raises:
        ValueError: If non-finite values or floats are found, or if normalized
            dictionary keys collide.
        TypeError: If dictionary keys are not strings.
    """
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, int):
        return obj
    if isinstance(obj, Decimal):
        if not obj.is_finite():
            raise ValueError("Infinity is not allowed in canonical JSON")
        return obj
    if isinstance(obj, float):
        if math.isnan(obj):
            raise ValueError("NaN is not allowed in canonical JSON")
        if math.isinf(obj):
            raise ValueError("Infinity is not allowed in canonical JSON")
        raise ValueError("Float values are not allowed in canonical JSON; use Decimal")
    if isinstance(obj, list | tuple):
        return [_normalize_for_canonical_json(item) for item in obj]
    if isinstance(obj, dict):
        normalized_obj: dict[str, Any] = {}
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError("Object keys must be strings for canonical JSON")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized_obj:
                raise ValueError(f"Duplicate key after NFC normalization: {normalized_key!r}")
            normalized_obj[normalized_key] = _normalize_for_canonical_json(value)
        return normalized_obj
    # Reject all other types explicitly - prevents silent type fallthrough
    raise TypeError(f"Type {type(obj).__name__} is not JSON-serializable for canonical JSON")


def _encode_value(value: Any) -> str:
    """
    Recursively encode a value to canonical JSON string.

    String values are encoded using ``json.dumps(s, ensure_ascii=False)`` so
    that non-ASCII code points are emitted as raw UTF-8, matching RFC 8785 /
    JCS behaviour.  Control characters (U+0000–U+001F) are still escaped with
    standard JSON sequences.

    Args:
        value: Value to encode

    Returns:
        Canonical JSON string representation

    Raises:
        TypeError: If value is not JSON-serializable or object keys are not strings
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        # ensure_ascii=False: non-ASCII emitted as raw UTF-8 (JCS-compliant).
        # json.dumps raises UnicodeEncodeError for lone surrogates — correct.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int | Decimal) and not isinstance(value, bool):
        return _encode_number(value)
    if isinstance(value, list | tuple):
        return "[" + ",".join(_encode_value(item) for item in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise TypeError("Object keys must be strings for canonical JSON")
            items.append(f"{json.dumps(key, ensure_ascii=False)}:{_encode_value(value[key])}")
        return "{" + ",".join(items) + "}"
    raise TypeError(f"Type {type(value)} is not JSON-serializable")


def _encode_number(value: int | Decimal) -> str:
    """
    Encode a number to canonical JSON format.

    Uses fixed notation when -6 <= exp10 <= 20, otherwise scientific notation.
    Normalizes -0 to 0 and strips trailing zeros.

    Args:
        value: Number to encode

    Returns:
        Canonical JSON number string
    """
    dec_value = _to_decimal(value)
    if dec_value.is_zero():
        return "0"

    dec_value = dec_value.normalize()
    sign = "-" if dec_value.is_signed() else ""
    dec_value = abs(dec_value)

    dec_tuple = dec_value.as_tuple()
    digits = "".join(str(d) for d in dec_tuple.digits)
    exponent: int = int(dec_tuple.exponent)
    adjusted_exponent = dec_value.adjusted()

    if -6 <= adjusted_exponent <= 20:
        formatted = _format_fixed(digits, exponent)
    else:
        formatted = _format_scientific(digits, adjusted_exponent)

    return sign + formatted


def _to_decimal(value: int | Decimal) -> Decimal:
    """
    Convert a numeric value to Decimal for precise formatting.

    Args:
        value: Numeric value to convert

    Returns:
        Decimal representation

    Raises:
        ValueError: If value is infinite or invalid
    """
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    raise ValueError(
        "Only int and Decimal numeric values are allowed for canonical JSON, "
        f"got {type(value).__name__}"
    )


def _format_fixed(digits: str, exponent: int) -> str:
    """
    Format a number in fixed notation (no scientific notation).

    Args:
        digits: Digit string of the number
        exponent: Decimal exponent

    Returns:
        Fixed notation string
    """
    if exponent >= 0:
        return digits + ("0" * exponent)

    idx = len(digits) + exponent
    if idx > 0:
        return digits[:idx] + "." + digits[idx:]
    return "0." + ("0" * -idx) + digits


def _format_scientific(digits: str, adjusted_exponent: int) -> str:
    """
    Format a number in scientific notation.

    Args:
        digits: Digit string of the number
        adjusted_exponent: Adjusted exponent value

    Returns:
        Scientific notation string (e.g., "1.23e+4")
    """
    if len(digits) == 1:
        mantissa = digits
    else:
        mantissa = digits[0] + "." + digits[1:]
    exponent_part = f"e{adjusted_exponent:+d}"
    return mantissa + exponent_part
