"""Shared fixtures and helpers for the Olympus chaos engineering test suite."""

from __future__ import annotations

import pytest


@pytest.fixture()
def fresh_ledger():  # type: ignore[no-untyped-def]
    """Return a new empty Ledger instance for each test."""
    from protocol.ledger import Ledger

    return Ledger()
