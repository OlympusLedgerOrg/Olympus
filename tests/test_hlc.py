"""
Tests for protocol.hlc — Hybrid Logical Clock.

Covers:
- HLCTimestamp construction and validation
- Canonical byte encoding / decoding round-trip
- Comparison operators (total ordering)
- advance_hlc() monotonicity guarantees
- Edge cases: zero, max counter, backwards wall clock
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from protocol.hlc import HLC_BYTE_LENGTH, HLC_ZERO, HLCTimestamp, advance_hlc


# ------------------------------------------------------------------ #
# Construction & validation
# ------------------------------------------------------------------ #


class TestHLCTimestampConstruction:
    """Tests for HLCTimestamp creation and validation."""

    def test_valid_construction(self) -> None:
        ts = HLCTimestamp(wall_ms=1000, counter=0)
        assert ts.wall_ms == 1000
        assert ts.counter == 0

    def test_zero_values_allowed(self) -> None:
        ts = HLCTimestamp(wall_ms=0, counter=0)
        assert ts.wall_ms == 0
        assert ts.counter == 0

    def test_negative_wall_ms_rejected(self) -> None:
        with pytest.raises(ValueError, match="wall_ms must be non-negative"):
            HLCTimestamp(wall_ms=-1, counter=0)

    def test_negative_counter_rejected(self) -> None:
        with pytest.raises(ValueError, match="counter must be non-negative"):
            HLCTimestamp(wall_ms=0, counter=-1)

    def test_frozen_dataclass(self) -> None:
        ts = HLCTimestamp(wall_ms=100, counter=5)
        with pytest.raises(AttributeError):
            ts.wall_ms = 200  # type: ignore[misc]

    def test_large_values(self) -> None:
        ts = HLCTimestamp(wall_ms=2**63 - 1, counter=2**31 - 1)
        assert ts.wall_ms == 2**63 - 1
        assert ts.counter == 2**31 - 1


# ------------------------------------------------------------------ #
# Byte encoding round-trip
# ------------------------------------------------------------------ #


class TestHLCByteEncoding:
    """Tests for to_bytes() and from_bytes() canonical encoding."""

    def test_round_trip_zero(self) -> None:
        ts = HLCTimestamp(wall_ms=0, counter=0)
        assert HLCTimestamp.from_bytes(ts.to_bytes()) == ts

    def test_round_trip_typical(self) -> None:
        ts = HLCTimestamp(wall_ms=1_700_000_000_000, counter=42)
        decoded = HLCTimestamp.from_bytes(ts.to_bytes())
        assert decoded == ts

    def test_byte_length(self) -> None:
        ts = HLCTimestamp(wall_ms=12345, counter=67)
        encoded = ts.to_bytes()
        assert len(encoded) == HLC_BYTE_LENGTH
        assert HLC_BYTE_LENGTH == 12

    def test_big_endian_encoding(self) -> None:
        ts = HLCTimestamp(wall_ms=256, counter=1)
        encoded = ts.to_bytes()
        # wall_ms=256 => 8 bytes big-endian: 0x0000000000000100
        assert encoded[:8] == b"\x00\x00\x00\x00\x00\x00\x01\x00"
        # counter=1 => 4 bytes big-endian: 0x00000001
        assert encoded[8:] == b"\x00\x00\x00\x01"

    def test_from_bytes_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="12 bytes"):
            HLCTimestamp.from_bytes(b"\x00" * 10)

    def test_from_bytes_empty(self) -> None:
        with pytest.raises(ValueError, match="12 bytes"):
            HLCTimestamp.from_bytes(b"")


# ------------------------------------------------------------------ #
# Comparison operators
# ------------------------------------------------------------------ #


class TestHLCComparison:
    """Tests for HLCTimestamp ordering."""

    def test_lt_by_wall_ms(self) -> None:
        a = HLCTimestamp(wall_ms=100, counter=0)
        b = HLCTimestamp(wall_ms=200, counter=0)
        assert a < b
        assert b > a

    def test_lt_by_counter(self) -> None:
        a = HLCTimestamp(wall_ms=100, counter=0)
        b = HLCTimestamp(wall_ms=100, counter=1)
        assert a < b

    def test_le(self) -> None:
        a = HLCTimestamp(wall_ms=100, counter=5)
        b = HLCTimestamp(wall_ms=100, counter=5)
        assert a <= b
        assert b <= a

    def test_gt(self) -> None:
        a = HLCTimestamp(wall_ms=200, counter=0)
        b = HLCTimestamp(wall_ms=100, counter=999)
        assert a > b

    def test_ge(self) -> None:
        a = HLCTimestamp(wall_ms=100, counter=5)
        b = HLCTimestamp(wall_ms=100, counter=5)
        assert a >= b
        assert b >= a

    def test_equality(self) -> None:
        a = HLCTimestamp(wall_ms=42, counter=7)
        b = HLCTimestamp(wall_ms=42, counter=7)
        assert a == b

    def test_total_order_wall_ms_dominates(self) -> None:
        """wall_ms=200,counter=0 > wall_ms=100,counter=999."""
        a = HLCTimestamp(wall_ms=200, counter=0)
        b = HLCTimestamp(wall_ms=100, counter=999)
        assert a > b


# ------------------------------------------------------------------ #
# HLC_ZERO sentinel
# ------------------------------------------------------------------ #


class TestHLCZero:
    """Tests for the HLC_ZERO sentinel."""

    def test_zero_values(self) -> None:
        assert HLC_ZERO.wall_ms == 0
        assert HLC_ZERO.counter == 0

    def test_zero_is_minimum(self) -> None:
        any_ts = HLCTimestamp(wall_ms=1, counter=0)
        assert HLC_ZERO < any_ts

    def test_zero_bytes(self) -> None:
        assert HLC_ZERO.to_bytes() == b"\x00" * 12


# ------------------------------------------------------------------ #
# advance_hlc()
# ------------------------------------------------------------------ #


class TestAdvanceHLC:
    """Tests for the advance_hlc() function."""

    def test_advances_past_zero(self) -> None:
        result = advance_hlc(HLC_ZERO)
        assert result > HLC_ZERO

    def test_monotonically_increasing(self) -> None:
        ts = HLC_ZERO
        for _ in range(100):
            new_ts = advance_hlc(ts)
            assert new_ts > ts
            ts = new_ts

    def test_wall_clock_advance_resets_counter(self) -> None:
        """When wall clock advances, counter resets to 0."""
        last = HLCTimestamp(wall_ms=1000, counter=42)
        # Mock time.time() to return a time ahead of last.wall_ms
        with patch("protocol.hlc.time.time", return_value=2.0):  # 2000 ms
            result = advance_hlc(last)
        assert result.wall_ms == 2000
        assert result.counter == 0

    def test_same_wall_increments_counter(self) -> None:
        """When wall clock hasn't advanced, counter increments."""
        last = HLCTimestamp(wall_ms=5000, counter=10)
        # Mock time.time() to return same or earlier time
        with patch("protocol.hlc.time.time", return_value=4.0):  # 4000 ms < 5000
            result = advance_hlc(last)
        assert result.wall_ms == 5000
        assert result.counter == 11

    def test_backward_clock_maintains_monotonicity(self) -> None:
        """Even if wall clock goes backward, result is still > last."""
        last = HLCTimestamp(wall_ms=10000, counter=0)
        # Simulate clock going backwards
        with patch("protocol.hlc.time.time", return_value=5.0):  # 5000 ms
            result = advance_hlc(last)
        assert result > last
        assert result.wall_ms == 10000
        assert result.counter == 1

    def test_rapid_succession(self) -> None:
        """Multiple advances at the same wall time produce increasing counters."""
        fixed_ms = 1_700_000_000_000
        with patch("protocol.hlc.time.time", return_value=fixed_ms / 1000):
            ts = HLCTimestamp(wall_ms=fixed_ms, counter=0)
            for i in range(1, 10):
                ts = advance_hlc(ts)
                assert ts.counter == i
                assert ts.wall_ms == fixed_ms
