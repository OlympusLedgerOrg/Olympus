#!/usr/bin/env python3
"""Cross-platform fuzz loop runner for the Olympus fuzzing framework.

Detects the host OS and adjusts the pytest invocation accordingly:

- **Windows**: adds ``-p no:cacheprovider`` to prevent WinError 183 (cannot
  create a file when that file already exists) which arises when the pytest
  cache plugin races to (re-)create ``.pytest_cache`` across 8 xdist workers
  or rapid sequential re-runs.  Also sets ``NO_COLOR=1`` and
  ``PYTHONIOENCODING=utf-8`` for clean, portable terminal output.
- **Linux / macOS**: standard invocation; no extra flags needed.

Usage
-----
::

    # Smoke pass (< 3 min, equivalent to PR CI)
    python scripts/run_fuzz_loop.py --smoke

    # 24-hour marathon (all suites)
    python scripts/run_fuzz_loop.py --hours 24

    # 24-hour security-only marathon
    python scripts/run_fuzz_loop.py --security-only --hours 24

    # Exactly 100 iterations, stop on first failure
    python scripts/run_fuzz_loop.py --count 100 --stop-on-fail

    # Override OS detection (useful for CI image debugging)
    python scripts/run_fuzz_loop.py --os windows --smoke

Flags
-----
--smoke                 Single pass, ``fuzz_smoke`` profile (< 3 min).
                        This is the default when neither ``--hours`` nor
                        ``--count`` is provided.
--security-only         Run only ``test_security_invariants_fuzz.py``.
--storage-only          Run only ``test_storage_invariants_fuzz.py`` (requires
                        ``TEST_DATABASE_URL``).
--profile NAME          Hypothesis profile name.  Defaults to ``fuzz_smoke``
                        in smoke mode and ``fuzz_24h`` in marathon mode.
--hours N               Time-based loop: run for N hours (default: 24 in
                        marathon mode).  Mutually exclusive with ``--count``.
--count N               Count-based loop: run exactly N passes.  0 = unlimited
                        (time-bounded by ``--hours``).  Mutually exclusive
                        with ``--hours``.
--max N                 Override ``FUZZ_MAX_EXAMPLES`` (Hypothesis
                        ``max_examples`` per test).
--stop-on-fail          Exit with code 1 on the first failing pass instead of
                        continuing.
--seed N                Seed for the *first* pass (smoke) or base for per-pass
                        randomisation (marathon).  Default: 0 for smoke,
                        random for marathon.
--os {windows,linux,mac,auto}
                        Override OS detection.  Default: ``auto``.
"""

from __future__ import annotations

import argparse
import os
import platform
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Repo root (scripts/ is one level below the repo root)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="run_fuzz_loop.py",
        description="Cross-platform Olympus fuzz loop runner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode flags
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Single-pass smoke run (< 3 min).  Overrides --hours / --count.",
    )
    parser.add_argument(
        "--security-only",
        dest="security_only",
        action="store_true",
        help="Run only test_security_invariants_fuzz.py.",
    )
    parser.add_argument(
        "--storage-only",
        dest="storage_only",
        action="store_true",
        help="Run only test_storage_invariants_fuzz.py.",
    )

    # Profile / examples
    parser.add_argument(
        "--profile",
        default=None,
        metavar="NAME",
        help="Hypothesis profile (default: fuzz_smoke | fuzz_24h).",
    )
    parser.add_argument(
        "--max",
        dest="max_examples",
        type=int,
        default=None,
        metavar="N",
        help="Override FUZZ_MAX_EXAMPLES.",
    )

    # Duration — mutually exclusive
    duration_group = parser.add_mutually_exclusive_group()
    duration_group.add_argument(
        "--hours",
        type=float,
        default=None,
        metavar="N",
        help="Run for N hours (time-based loop).",
    )
    duration_group.add_argument(
        "--count",
        type=int,
        default=None,
        metavar="N",
        help="Run exactly N passes (0 = unlimited, bounded by --hours default).",
    )

    # Control
    parser.add_argument(
        "--stop-on-fail",
        dest="stop_on_fail",
        action="store_true",
        help="Exit 1 on first failure instead of continuing.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="N",
        help="Hypothesis seed (default: 0 for smoke, random for marathon).",
    )

    # Platform override
    parser.add_argument(
        "--os",
        dest="os_override",
        choices=["windows", "linux", "mac", "auto"],
        default="auto",
        help="Override OS detection (default: auto).",
    )

    args = parser.parse_args(argv)

    # Validate conflicting options
    if args.security_only and args.storage_only:
        parser.error("--security-only and --storage-only are mutually exclusive.")

    return args


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def _detect_platform(os_override: str) -> str:
    """Return a canonical platform name: ``'windows'``, ``'linux'``, or ``'mac'``.

    Args:
        os_override: One of ``'windows'``, ``'linux'``, ``'mac'``, or
            ``'auto'``.  When ``'auto'``, the running OS is queried via
            :func:`platform.system`.

    Returns:
        ``'windows'``, ``'linux'``, or ``'mac'``.
    """
    if os_override != "auto":
        return os_override

    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "mac"
    return "linux"


# ---------------------------------------------------------------------------
# Module / marker selection
# ---------------------------------------------------------------------------


def _select_modules(args: argparse.Namespace) -> list[str]:
    """Return the list of test module paths to pass to pytest.

    Storage tests are silently skipped when ``TEST_DATABASE_URL`` is not set.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Relative paths (from repo root) to the fuzz test modules to run.
    """
    modules: list[str] = []

    if not args.storage_only:
        modules.append("tests/fuzz/test_security_invariants_fuzz.py")

    if not args.security_only:
        db_url = os.environ.get("TEST_DATABASE_URL", "")
        if db_url:
            modules.append("tests/fuzz/test_storage_invariants_fuzz.py")
        elif args.storage_only:
            # User explicitly requested storage but DB URL is absent — warn.
            print(
                "WARNING: --storage-only requested but TEST_DATABASE_URL is not set; "
                "storage tests will not run.",
                file=sys.stderr,
            )

    return modules


def _select_marker(args: argparse.Namespace) -> str:
    """Return the pytest ``-m`` marker expression for the selected suites.

    Args:
        args: Parsed CLI arguments.

    Returns:
        A pytest marker expression string.
    """
    if args.smoke:
        return "fuzz"
    if args.security_only:
        return "fuzz and security"
    if args.storage_only:
        return "fuzz and storage"
    return "fuzz"


# ---------------------------------------------------------------------------
# pytest command builder
# ---------------------------------------------------------------------------


def _build_pytest_cmd(
    modules: list[str],
    marker: str,
    seed: int,
    platform_name: str,
) -> list[str]:
    """Build the ``pytest`` command-line list.

    Args:
        modules: Test module paths relative to repo root.
        marker:  pytest ``-m`` expression.
        seed:    ``--hypothesis-seed`` value.
        platform_name: Detected/overridden platform name.

    Returns:
        A list of strings suitable for :func:`subprocess.run`.
    """
    cmd = (
        [sys.executable, "-m", "pytest"]
        + modules
        + [
            "-v",
            "--tb=short",
            "-m",
            marker,
            f"--hypothesis-seed={seed}",
        ]
    )

    # Windows: disable cache plugin to prevent WinError 183 race condition
    # when pytest-cache tries to (re-)create .pytest_cache concurrently across
    # xdist workers or rapid sequential re-runs.
    if platform_name == "windows":
        cmd.append("-p")
        cmd.append("no:cacheprovider")

    return cmd


def _build_env(platform_name: str) -> dict[str, str]:
    """Return an environment dict for the subprocess.

    Inherits the current process environment and applies platform-specific
    additions.

    Args:
        platform_name: Detected/overridden platform name.

    Returns:
        Environment dictionary for :func:`subprocess.run`.
    """
    env = os.environ.copy()

    if platform_name == "windows":
        # Suppress ANSI escape codes for terminals that do not support them
        env.setdefault("NO_COLOR", "1")
        # Ensure UTF-8 is used for stdout/stderr even in legacy Windows consoles
        env.setdefault("PYTHONIOENCODING", "utf-8")

    return env


# ---------------------------------------------------------------------------
# Single-pass runner
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_pass(
    cmd: list[str],
    env: dict[str, str],
    pass_num: int,
    seed: int,
) -> tuple[bool, float]:
    """Run a single pytest pass and return (passed, elapsed_seconds).

    Pytest output streams directly to the calling terminal (no capture).

    Args:
        cmd:      Full pytest command list.
        env:      Environment dictionary.
        pass_num: 1-based pass number (used only for display).
        seed:     Hypothesis seed used for this pass (used only for display).

    Returns:
        ``(True, elapsed)`` when the pass exits 0; ``(False, elapsed)``
        otherwise.
    """
    print(f"\n=== Pass {pass_num} ({_now_iso()}) seed={seed} ===", flush=True)

    t0 = time.monotonic()
    result = subprocess.run(cmd, cwd=_REPO_ROOT, env=env)
    elapsed = time.monotonic() - t0

    status = "PASSED" if result.returncode == 0 else "FAILED"
    detail = f" [seed={seed}]" if result.returncode != 0 else ""
    print(
        f"Pass {pass_num}: {status} in {elapsed:.1f}s{detail}",
        flush=True,
    )

    return result.returncode == 0, elapsed


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def _run_loop(args: argparse.Namespace) -> int:
    """Execute the fuzz loop according to *args* and return an exit code.

    Args:
        args: Parsed CLI arguments from :func:`_parse_args`.

    Returns:
        0 if all passes succeeded; 1 if any pass failed (and
        ``--stop-on-fail`` was set or at least one failure occurred).
    """
    platform_name = _detect_platform(args.os_override)

    # --- Resolve profile and max_examples -----------------------------------
    if args.smoke:
        profile = args.profile or "fuzz_smoke"
        max_examples = args.max_examples or 30
        seed = args.seed if args.seed is not None else 0
    else:
        profile = args.profile or "fuzz_24h"
        max_examples = args.max_examples or 10_000
        seed = args.seed  # None = random per pass

    # --- Propagate to environment (tests read these) ------------------------
    os.environ["HYPOTHESIS_PROFILE"] = profile
    os.environ["FUZZ_MAX_EXAMPLES"] = str(max_examples)

    # --- Module / marker selection ------------------------------------------
    modules = _select_modules(args)
    if not modules:
        print(
            "ERROR: No fuzz modules to run.  Set TEST_DATABASE_URL to enable storage tests.",
            file=sys.stderr,
        )
        return 1

    marker = _select_marker(args)
    env = _build_env(platform_name)

    # --- Duration -----------------------------------------------------------
    if args.smoke:
        total_passes: int | None = 1
        end_time: float | None = None
    elif args.count is not None:
        total_passes = args.count if args.count > 0 else None
        end_time = None
    else:
        hours = args.hours if args.hours is not None else 24.0
        total_passes = None
        end_time = time.monotonic() + hours * 3600

    artifact_dir = _REPO_ROOT / ".hypothesis" / "fuzz-artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # --- Summary header -----------------------------------------------------
    print("=== Olympus Fuzz Loop ===")
    print(f"  Platform:        {platform_name}")
    print(f"  Profile:         {profile}")
    print(f"  Max examples:    {max_examples}")
    print(f"  Marker:          {marker}")
    if total_passes is not None:
        print(f"  Passes:          {total_passes}")
    elif end_time is not None:
        hrs = (end_time - time.monotonic()) / 3600
        print(f"  Duration:        {hrs:.1f}h")
    db_url = os.environ.get("TEST_DATABASE_URL", "")
    print(f"  TEST_DATABASE_URL: {db_url if db_url else '(not set, storage tests skipped)'}")
    if platform_name == "windows":
        print("  Windows flags:   -p no:cacheprovider  NO_COLOR=1  PYTHONIOENCODING=utf-8")
    print()

    # --- Loop ---------------------------------------------------------------
    pass_num = 0
    passed_total = 0
    failed_total = 0
    any_failure = False

    def _should_continue() -> bool:
        if total_passes is not None:
            return pass_num < total_passes
        if end_time is not None:
            return time.monotonic() < end_time
        return True  # unlimited (--count 0)

    while _should_continue():
        pass_num += 1

        # Per-pass seed: deterministic for smoke, randomised for marathon
        pass_seed: int
        if args.smoke or seed is not None:
            pass_seed = seed if seed is not None else 0
        else:
            pass_seed = random.randint(1, 2_147_483_647)

        cmd = _build_pytest_cmd(modules, marker, pass_seed, platform_name)
        ok, _ = _run_pass(cmd, env, pass_num, pass_seed)

        if ok:
            passed_total += 1
        else:
            failed_total += 1
            any_failure = True

        print(
            f"Cumulative: {passed_total} passed, {failed_total} failed",
            flush=True,
        )

        if not ok and args.stop_on_fail:
            print(
                f"\nStopping after pass {pass_num} due to --stop-on-fail.",
                flush=True,
            )
            break

    # --- Final summary ------------------------------------------------------
    print(f"\n=== Fuzz loop complete after {pass_num} pass(es) ===")
    print(f"Passed: {passed_total}  Failed: {failed_total}")
    artifacts = list(artifact_dir.glob("*.json"))
    if artifacts:
        print(f"Artifacts saved to: {artifact_dir}")
        for a in sorted(artifacts)[-5:]:
            print(f"  {a.name}")
    else:
        print("(no failure artifacts)")

    return 1 if any_failure else 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the fuzz loop.

    Args:
        argv: Argument list (defaults to :data:`sys.argv` when ``None``).

    Returns:
        Process exit code: 0 for all-pass, 1 for any failure.
    """
    args = _parse_args(argv)
    return _run_loop(args)


if __name__ == "__main__":
    sys.exit(main())
