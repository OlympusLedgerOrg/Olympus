"""Shared fixtures for the adversarial break-harness test suite.

Each test in this suite was written as an ``xfail`` probe *before* the
corresponding fix landed.  Now that the fixes are in place every ``xfail``
must flip to a clean pass — ``strict=True`` ensures that a regression
(an unexpectedly passing xfail) causes a loud failure rather than a
silent skip.
"""

from __future__ import annotations

import pytest

from protocol.ledger import Ledger


@pytest.fixture()
def fresh_ledger() -> Ledger:
    """Return a new empty Ledger instance for each test."""
    return Ledger()
