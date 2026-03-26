"""
Hybrid Logical Clock (HLC) for Olympus ledger entry ordering.

HLC combines wall-clock time with a logical counter to guarantee strict
monotonicity without depending on wall-clock accuracy.  Each HLC timestamp
encodes a millisecond-resolution wall time and an integer counter that
disambiguates events occurring within the same millisecond.

The canonical byte encoding is 12 bytes: 8 bytes for wall_ms (big-endian)
followed by 4 bytes for counter (big-endian).  This encoding is included
in ledger entry hash inputs so that backdated entries invalidate the chain.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# Size of the canonical HLC byte encoding.
HLC_BYTE_LENGTH = 12


@dataclass(frozen=True)
class HLCTimestamp:
    """A hybrid logical clock timestamp.

    Attributes:
        wall_ms: Milliseconds since the Unix epoch.
        counter: Logical counter, incremented when wall_ms does not advance.
    """

    wall_ms: int
    counter: int

    def __post_init__(self) -> None:
        if self.wall_ms < 0:
            raise ValueError("wall_ms must be non-negative")
        if self.counter < 0:
            raise ValueError("counter must be non-negative")

    def to_bytes(self) -> bytes:
        """Canonical 12-byte encoding for inclusion in hash chain."""
        return self.wall_ms.to_bytes(8, "big") + self.counter.to_bytes(4, "big")

    @classmethod
    def from_bytes(cls, b: bytes) -> HLCTimestamp:
        """Decode from the canonical 12-byte representation."""
        if len(b) != HLC_BYTE_LENGTH:
            raise ValueError(f"HLC bytes must be {HLC_BYTE_LENGTH} bytes, got {len(b)}")
        return cls(
            wall_ms=int.from_bytes(b[:8], "big"),
            counter=int.from_bytes(b[8:], "big"),
        )

    def __lt__(self, other: HLCTimestamp) -> bool:
        return (self.wall_ms, self.counter) < (other.wall_ms, other.counter)

    def __le__(self, other: HLCTimestamp) -> bool:
        return (self.wall_ms, self.counter) <= (other.wall_ms, other.counter)

    def __gt__(self, other: HLCTimestamp) -> bool:
        return (self.wall_ms, self.counter) > (other.wall_ms, other.counter)

    def __ge__(self, other: HLCTimestamp) -> bool:
        return (self.wall_ms, self.counter) >= (other.wall_ms, other.counter)


# Sentinel value representing "no previous timestamp" (genesis).
HLC_ZERO = HLCTimestamp(wall_ms=0, counter=0)


def advance_hlc(last: HLCTimestamp) -> HLCTimestamp:
    """Return a new HLC timestamp strictly greater than *last*.

    If wall-clock time has advanced past *last.wall_ms*, the counter resets
    to 0.  Otherwise the counter is incremented on the same wall tick.

    Args:
        last: The most recent HLC timestamp in the chain.

    Returns:
        A new ``HLCTimestamp`` guaranteed to be strictly greater than *last*.
    """
    now_ms = int(time.time() * 1000)
    if now_ms > last.wall_ms:
        return HLCTimestamp(wall_ms=now_ms, counter=0)
    return HLCTimestamp(wall_ms=last.wall_ms, counter=last.counter + 1)
