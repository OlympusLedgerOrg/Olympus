"""
CORS preflight tests for custom authentication headers.

Verifies that an OPTIONS preflight request with
Access-Control-Request-Headers: x-api-key (or x-admin-key) receives a 200
response and the header is echoed back in Access-Control-Allow-Headers, so
that browser clients can use these headers without silent CORS failures.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from api.main import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def cors_client():
    """Create a test client with CORS enabled for a specific origin."""
    with patch.dict(
        os.environ,
        {
            "OLYMPUS_ENV": "development",
            "CORS_ORIGINS": "http://localhost:3000",
        },
    ):
        app = create_app()
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as ac:
            yield ac


# ---------------------------------------------------------------------------
# Preflight tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cors_preflight_x_api_key(cors_client):
    """OPTIONS preflight with x-api-key should be allowed."""
    resp = await cors_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-api-key",
        },
    )
    assert resp.status_code == 200
    allowed = resp.headers.get("access-control-allow-headers", "").lower()
    assert "x-api-key" in allowed


@pytest.mark.asyncio
async def test_cors_preflight_x_admin_key(cors_client):
    """OPTIONS preflight with x-admin-key should be allowed."""
    resp = await cors_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-admin-key",
        },
    )
    assert resp.status_code == 200
    allowed = resp.headers.get("access-control-allow-headers", "").lower()
    assert "x-admin-key" in allowed
