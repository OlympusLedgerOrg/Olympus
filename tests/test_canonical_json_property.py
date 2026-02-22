"""Property-based tests for canonical JSON encoding invariants."""

import json
import math
from decimal import Decimal

from hypothesis import given, strategies as st

from protocol.canonical_json import canonical_json_encode


json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
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
    """Unicode strings should be ASCII-safe and JSON round-trippable."""
    encoded = canonical_json_encode({"value": value})
    encoded.encode("ascii")
    assert json.loads(encoded) == {"value": value}


@given(st.floats(allow_nan=False, allow_infinity=False))
def test_canonical_json_encode_float_roundtrip(value):
    """Finite floats should round-trip through canonical JSON."""
    encoded = canonical_json_encode({"value": value})
    decoded = json.loads(encoded)["value"]
    if math.copysign(1.0, value) < 0 and value == 0.0:
        assert decoded == 0
    else:
        assert Decimal(str(decoded)) == Decimal(str(value))
