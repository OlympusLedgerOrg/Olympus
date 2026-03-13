from datetime import datetime

try:
    from datetime import UTC
except ImportError:  # Python < 3.11
    from datetime import timezone

    UTC = timezone.utc

from protocol.timestamps import current_timestamp


def test_current_timestamp_returns_rfc3339_utc_with_z_suffix() -> None:
    ts = current_timestamp()

    assert ts.endswith("Z")
    assert "+00:00" not in ts
    assert "T" in ts

    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo == UTC
