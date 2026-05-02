"""Tests for shard history and state-diff API endpoints."""

import importlib

from fastapi.testclient import TestClient

import api.routers.shards as shards_mod


api_app = importlib.import_module("api.app")
client = TestClient(api_app.app)


class FakeDashboardStorage:
    """Minimal storage stub for dashboard endpoints."""

    def get_header_history(self, shard_id: str, n: int = 10):
        assert shard_id == "shard-a"
        assert n == 2
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
        assert shard_id == "shard-a"
        assert from_seq == 1
        assert to_seq == 2
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


def _fake_dashboard_storage() -> FakeDashboardStorage:
    return FakeDashboardStorage()


def test_shard_history_endpoint(monkeypatch):
    """The shard history endpoint should return recent signed header snapshots."""
    monkeypatch.setattr(shards_mod, "_require_storage", _fake_dashboard_storage)

    response = client.get("/shards/shard-a/history?n=2")

    assert response.status_code == 200
    data = response.json()
    assert data["shard_id"] == "shard-a"
    assert [entry["seq"] for entry in data["headers"]] == [2, 1]
    assert data["headers"][0]["root_hash"] == "bb" * 32


def test_shard_state_diff_endpoint(monkeypatch):
    """The shard state diff endpoint should expose root hashes and summary counts."""
    monkeypatch.setattr(shards_mod, "_require_storage", _fake_dashboard_storage)

    response = client.get("/shards/shard-a/diff?from_seq=1&to_seq=2")

    assert response.status_code == 200
    data = response.json()
    assert data["from_root_hash"] == "aa" * 32
    assert data["to_root_hash"] == "bb" * 32
    assert data["summary"] == {"added": 1, "changed": 0, "removed": 0}
    assert data["added"][0]["after_value_hash"] == "20" * 32


def test_shard_state_diff_missing_sequence_returns_404(monkeypatch):
    """Missing historical sequences should map to a 404 response."""

    class MissingDiffStorage(FakeDashboardStorage):
        def get_root_diff(self, shard_id: str, from_seq: int, to_seq: int):
            raise ValueError("Shard header not found: shard-a@99")

    monkeypatch.setattr(shards_mod, "_require_storage", lambda: MissingDiffStorage())

    response = client.get("/shards/shard-a/diff?from_seq=99&to_seq=100")

    assert response.status_code == 404
    assert "Shard header not found" in response.json()["detail"]


def test_root_and_health_expose_new_dashboard_endpoints():
    """Root and health metadata should confirm the API is operational."""
    root_response = client.get("/")
    health_response = client.get("/health")

    assert root_response.status_code == 200
    assert "service" in root_response.json()
    assert "version" in root_response.json()
    assert health_response.status_code == 200
    assert "status" in health_response.json()
    assert "version" in health_response.json()
