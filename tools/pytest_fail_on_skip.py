"""Pytest plugin that converts unexpected skips into failures.

Used by strict CI lanes (``full``) to prevent silent drift where a test stops
running because a dependency, service, or env var was removed but the test
keeps emitting ``SKIPPED`` instead of ``FAILED``.

Activation
----------

Enable explicitly per invocation::

    pytest tests/ -p tools.pytest_fail_on_skip --fail-on-skip

By default the plugin is a no-op; only ``--fail-on-skip`` flips it on.

Allowlist
---------

Some skips are legitimate (e.g. platform-specific filesystem behaviour). They
can be allowlisted by substring against the skip ``reason`` via repeated
``--allow-skip`` flags::

    pytest -p tools.pytest_fail_on_skip --fail-on-skip \
        --allow-skip="filesystem is case-insensitive" \
        --allow-skip="filesystem does not support this Unicode filename"

Anything not allowlisted will be reported as a failure at session end with the
list of offending nodeids and reasons, and the process will exit non-zero.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from _pytest.config import Config
    from _pytest.config.argparsing import Parser
    from _pytest.reports import TestReport
    from _pytest.terminal import TerminalReporter


_UNEXPECTED_SKIPS_KEY = pytest.StashKey[list[tuple[str, str]]]()


def pytest_addoption(parser: Parser) -> None:
    group = parser.getgroup("fail-on-skip", "Convert unexpected skips into failures")
    group.addoption(
        "--fail-on-skip",
        action="store_true",
        default=False,
        help="Fail the test session if any test reports SKIPPED (except --allow-skip matches).",
    )
    group.addoption(
        "--allow-skip",
        action="append",
        default=[],
        metavar="SUBSTRING",
        help=(
            "Substring to match against skip reasons. Skips matching at least "
            "one --allow-skip value are tolerated. May be supplied multiple times."
        ),
    )


def pytest_configure(config: Config) -> None:
    if config.getoption("--fail-on-skip"):
        config.stash[_UNEXPECTED_SKIPS_KEY] = []


def _extract_reason(report: TestReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) >= 3:
        # Standard skip representation: (path, lineno, reason)
        return str(longrepr[2])
    return str(longrepr) if longrepr is not None else ""


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    outcome = yield
    report: TestReport = outcome.get_result()
    if not item.config.getoption("--fail-on-skip"):
        return
    if report.when != "setup" and report.when != "call":
        return
    if not report.skipped:
        return

    reason = _extract_reason(report)
    allowlist = item.config.getoption("--allow-skip") or []
    if any(allowed and allowed in reason for allowed in allowlist):
        return

    bucket = item.config.stash.get(_UNEXPECTED_SKIPS_KEY, None)
    if bucket is not None:
        bucket.append((report.nodeid, reason))


def pytest_terminal_summary(terminalreporter: TerminalReporter) -> None:
    config = terminalreporter.config
    if not config.getoption("--fail-on-skip"):
        return
    bucket = config.stash.get(_UNEXPECTED_SKIPS_KEY, None)
    if not bucket:
        return

    terminalreporter.write_sep("=", "UNEXPECTED SKIPS (--fail-on-skip)", red=True)
    for nodeid, reason in bucket:
        terminalreporter.write_line(f"SKIPPED  {nodeid}  -- {reason}")
    terminalreporter.write_line(
        f"\n{len(bucket)} unexpected skip(s) recorded; failing the session."
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not session.config.getoption("--fail-on-skip"):
        return
    bucket = session.config.stash.get(_UNEXPECTED_SKIPS_KEY, None)
    if bucket:
        # Use TESTSFAILED so the exit status reflects a real failure, but only
        # when the run would otherwise have been considered successful.
        if exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
