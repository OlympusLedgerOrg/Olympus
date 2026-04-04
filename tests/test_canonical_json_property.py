"""Property-based tests for canonical JSON encoding invariants."""

import json
import unicodedata
from decimal import Decimal

from hypothesis import given, strategies as st

from protocol.canonical_json import canonical_json_encode


decimal_values = st.decimals(
    allow_nan=False,
    allow_infinity=False,
    places=10,
    min_value=Decimal("-1e20"),
    max_value=Decimal("1e20"),
)

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    decimal_values,
    st.text(),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(), children, max_size=5),
    ),
    max_leaves=20,
)


@given(json_values)
def test_canonical_json_encode_is_deterministic(value):
    """Canonical encoding should be stable across repeated calls."""
    assert canonical_json_encode(value) == canonical_json_encode(value)


@given(st.dictionaries(st.text(), json_values, min_size=1, max_size=5))
def test_canonical_json_encode_key_order_invariant(value):
    """Dict insertion order should not affect canonical output."""
    reversed_value = dict(reversed(list(value.items())))
    assert canonical_json_encode(value) == canonical_json_encode(reversed_value)


@given(st.text())
def test_canonical_json_encode_unicode_roundtrip(value):
    """Unicode strings are emitted as raw UTF-8 (JCS) and JSON round-trip correctly."""
    encoded = canonical_json_encode({"value": value})
    # Output is valid UTF-8 (not necessarily ASCII).
    encoded.encode("utf-8")
    assert json.loads(encoded) == {"value": unicodedata.normalize("NFC", value)}


@given(decimal_values)
def test_canonical_json_encode_decimal_roundtrip(value):
    """Finite Decimal values should round-trip through canonical JSON."""
    encoded = canonical_json_encode({"value": value})
    decoded = json.loads(encoded, parse_float=Decimal, parse_int=Decimal)["value"]
    # Canonical JSON normalizes both +0 and -0 to 0.
    expected = Decimal("0") if value == 0 else value.normalize()
    assert decoded == expected
