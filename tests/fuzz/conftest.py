"""
Hypothesis profiles for the Olympus fuzzing framework.

Profiles
--------
fuzz_smoke
    Fast profile for PR CI (< 3 min total).  Low example count, small max
    size.  Registered as the default when ``HYPOTHESIS_PROFILE`` is unset and
    the ``fuzz`` marker is active.

fuzz_ci
    Medium profile for nightly CI runs (≈ 30 min per test module).  Writes
    failures to the shared ``.hypothesis/examples/`` directory so shrunk
    examples survive across CI runs.

fuzz_24h
    Long-running local profile for 24-hour reliability marathons.  Suppresses
    all health checks, enables stateful testing, and uses the shared failure
    database for corpus reuse.

Usage
-----
Select a profile before running::

    HYPOTHESIS_PROFILE=fuzz_24h pytest tests/fuzz/ -m fuzz -x

or from the Makefile targets::

    make fuzz-smoke
    make fuzz-security-smoke
    make fuzz-24h
    make fuzz-security-24h
"""

from __future__ import annotations

import os
from pathlib import Path

from hypothesis import HealthCheck, Phase, settings
from hypothesis.database import DirectoryBasedExampleDatabase


# ---------------------------------------------------------------------------
# Shared failure database — identical to the one used by the main conftest so
# that fuzz failures and regular Hypothesis failures share the same corpus.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_EXAMPLES_DIR = str(_REPO_ROOT / ".hypothesis" / "examples")

# ---------------------------------------------------------------------------
# Profile: fuzz_smoke — short, fast, deterministic, suitable for PR CI
# ---------------------------------------------------------------------------
settings.register_profile(
    "fuzz_smoke",
    max_examples=30,
    database=DirectoryBasedExampleDatabase(_EXAMPLES_DIR),
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
        HealthCheck.large_base_example,
    ],
    print_blob=True,
    deadline=None,
    # Run only the reuse and generate phases (no shrinking beyond what is fast)
    phases=[Phase.reuse, Phase.generate, Phase.shrink],
    stateful_step_count=10,
)

# ---------------------------------------------------------------------------
# Profile: fuzz_ci — medium depth, uploads failure corpus to CI artifacts
# ---------------------------------------------------------------------------
settings.register_profile(
    "fuzz_ci",
    max_examples=200,
    database=DirectoryBasedExampleDatabase(_EXAMPLES_DIR),
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
    print_blob=True,
    deadline=None,
    phases=[Phase.reuse, Phase.generate, Phase.target, Phase.shrink],
    stateful_step_count=20,
)

# ---------------------------------------------------------------------------
# Profile: fuzz_24h — maximum depth for overnight/weekend marathon runs
# ---------------------------------------------------------------------------
settings.register_profile(
    "fuzz_24h",
    max_examples=10_000,
    database=DirectoryBasedExampleDatabase(_EXAMPLES_DIR),
    suppress_health_check=list(HealthCheck),
    print_blob=True,
    deadline=None,
    phases=[Phase.reuse, Phase.generate, Phase.target, Phase.shrink, Phase.explain],
    stateful_step_count=50,
)

# ---------------------------------------------------------------------------
# Auto-select profile from environment (mirrors main conftest behaviour)
# ---------------------------------------------------------------------------
_profile = os.environ.get("HYPOTHESIS_PROFILE", "fuzz_smoke")
try:
    settings.load_profile(_profile)
except Exception:
    # Unknown profile — fall back to fuzz_smoke so tests still run
    settings.load_profile("fuzz_smoke")
