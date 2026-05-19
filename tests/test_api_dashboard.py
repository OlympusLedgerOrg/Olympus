"""Tests for shard history and state-diff API endpoints."""

from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import api.services.storage_layer as storage_layer_module
from api.main import create_app


@pytest.fixture(scope="module")
def anyio_backend():
    """Use asyncio as the anyio backend for module-scoped fixtures."""
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def client():
    with patch.dict(
        os.environ,
        {"OLYMPUS_ENV": "development", "OLYMPUS_ALLOW_DEV_AUTH": "1"},
    ):
        app = create_app()
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as ac:
            yield ac


@contextmanager
def _fake_storage(storage_obj):
    original = storage_layer_module._storage
    storage_layer_module._storage = storage_obj
    try:
        yield
    finally:
        storage_layer_module._storage = original


class FakeDashboardStorage:
    """Minimal storage stub for dashboard endpoints."""

    def get_header_history(self, shard_id: str, n: int = 10):
        return [
            {
                "seq": 2,
                "root_hash": "bb" * 32,
                "header_hash": "22" * 32,
                "previous_header_hash": "11" * 32,
                "timestamp": "2026-01-02T00:00:00Z",
            },
            {
                "seq": 1,
                "root_hash": "aa" * 32,
                "header_hash": "11" * 32,
                "previous_header_hash": "",
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ]

    def get_root_diff(self, shard_id: str, from_seq: int, to_seq: int):
        return {
            "from_root_hash": "aa" * 32,
            "to_root_hash": "bb" * 32,
            "added": [
                {
                    "key": "10" * 32,
                    "before_value_hash": None,
                    "after_value_hash": "20" * 32,
                }
            ],
            "changed": [],
            "removed": [],
        }


class MissingDiffStorage(FakeDashboardStorage):
    def get_root_diff(self, shard_id: str, from_seq: int, to_seq: int):
        raise ValueError("Shard header not found: shard-a@99")


@pytest.mark.asyncio
async def test_shard_history_endpoint(client):
    """The shard history endpoint should return recent signed header snapshots."""
    with _fake_storage(FakeDashboardStorage()):
        response = await client.get("/shards/shard-a/history?n=2")

    assert response.status_code == 200
    data = response.json()
    assert data["shard_id"] == "shard-a"
    assert [entry["seq"] for entry in data["headers"]] == [2, 1]
    assert data["headers"][0]["root_hash"] == "bb" * 32


@pytest.mark.asyncio
async def test_shard_state_diff_endpoint(client):
    """The shard state diff endpoint should expose root hashes and summary counts."""
    with _fake_storage(FakeDashboardStorage()):
        response = await client.get("/shards/shard-a/diff?from_seq=1&to_seq=2")

    assert response.status_code == 200
    data = response.json()
    assert data["from_root_hash"] == "aa" * 32
    assert data["to_root_hash"] == "bb" * 32
    assert data["summary"] == {"added": 1, "changed": 0, "removed": 0}
    assert data["added"][0]["after_value_hash"] == "20" * 32


@pytest.mark.asyncio
async def test_shard_state_diff_missing_sequence_returns_404(client):
    """Missing historical sequences should map to a 404 response."""
    with _fake_storage(MissingDiffStorage()):
        response = await client.get("/shards/shard-a/diff?from_seq=99&to_seq=100")

    assert response.status_code == 404
    assert "Shard header not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_root_and_health_expose_new_dashboard_endpoints(client):
    """Root and health metadata should confirm the API is operational."""
    root_response = await client.get("/")
    health_response = await client.get("/health")

    assert root_response.status_code == 200
    assert "service" in root_response.json()
    assert "version" in root_response.json()
    assert health_response.status_code == 200
    assert "status" in health_response.json()
    assert "version" in health_response.json()
