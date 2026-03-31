"""
Pytest configuration for Olympus test suite.

Auto-detects PostgreSQL availability and sets TEST_DATABASE_URL
so that database-dependent tests run automatically when PostgreSQL
is accessible (e.g., via docker-compose or CI service containers).
"""

import os

import psycopg
import pytest


def pytest_configure(config):
    """Set TEST_DATABASE_URL if PostgreSQL is reachable and not already set.

    Also ensures OLYMPUS_ENV=development for tests so that ZK proof stubs
    are available (they are disabled in production).
    """
    env = os.environ.get("OLYMPUS_ENV")
    if not env:
        os.environ["OLYMPUS_ENV"] = "development"
        os.environ["OLYMPUS_ALLOW_DEV_AUTH"] = "1"
    elif env == "development":
        os.environ.setdefault("OLYMPUS_ALLOW_DEV_AUTH", "1")
    else:
        os.environ.pop("OLYMPUS_ALLOW_DEV_AUTH", None)

    if os.environ.get("TEST_DATABASE_URL"):
        return

    candidate = "postgresql://A.Smith:Mm4E@localhost:5432/olympus"
    try:
        with psycopg.connect(candidate, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        os.environ["TEST_DATABASE_URL"] = candidate
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Reset the auth module rate-limit backend between tests.

    Prevents rate-limit bucket state from leaking across test functions,
    which can cause spurious HTTP 429 failures when many tests share the
    same TestClient peer IP.
    """
    yield
    try:
        from api.auth import _reset_rate_limit_backend_for_tests

        _reset_rate_limit_backend_for_tests()
    except ImportError:
        pass


@pytest.fixture(autouse=True)
def _reset_auth_state():
    """Reset the auth module API key store between tests.

    Prevents API key state from leaking across test functions, which can
    cause tests to fail when previous tests registered API keys that
    subsequent tests don't expect.
    """
    yield
    try:
        from api.auth import _reset_auth_state_for_tests

        _reset_auth_state_for_tests()
    except ImportError:
        pass
