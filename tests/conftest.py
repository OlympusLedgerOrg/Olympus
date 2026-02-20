"""
Pytest configuration for Olympus test suite.

Auto-detects PostgreSQL availability and sets TEST_DATABASE_URL
so that database-dependent tests run automatically when PostgreSQL
is accessible (e.g., via docker-compose or CI service containers).
"""

import os

import psycopg


def pytest_configure(config):
    """Set TEST_DATABASE_URL if PostgreSQL is reachable and not already set."""
    if os.environ.get("TEST_DATABASE_URL"):
        return

    candidate = "postgresql://olympus:olympus@localhost:5432/olympus"
    try:
        with psycopg.connect(candidate, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        os.environ["TEST_DATABASE_URL"] = candidate
    except Exception:
        pass
