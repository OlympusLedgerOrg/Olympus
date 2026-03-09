"""Shared fixtures and helpers for the Olympus chaos engineering test suite."""

from __future__ import annotations

import pytest

from protocol.ledger import Ledger


@pytest.fixture()
def fresh_ledger() -> Ledger:
    """Return a new empty Ledger instance for each test."""
    return Ledger()
