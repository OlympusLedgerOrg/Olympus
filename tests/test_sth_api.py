"""Tests for STH gossip endpoints."""

import pytest
from fastapi.testclient import TestClient

from api import sth as sth_api
from api.app import app


class _FakeStorage:
    """Minimal storage stub used to exercise STH endpoints."""

    def __init__(self) -> None:
        self.shard_id = "demo-shard"
        self.latest_header = {
            "header": {
                "shard_id": self.shard_id,
                "root_hash": "aa" * 32,
                "tree_size": 5,
                "timestamp": "2026-03-14T00:00:00Z",
                "previous_header_hash": "",
                "header_hash": "bb" * 32,
            },
            "signature": "cc" * 32,
            "pubkey": "dd" * 16,
            "seq": 2,
        }
        self.history = [
            {
                "seq": 2,
                "root_hash": "aa" * 32,
                "tree_size": 5,
                "header_hash": "bb" * 32,
                "previous_header_hash": "",
                "timestamp": "2026-03-14T00:00:00Z",
                "signature": "cc" * 32,
                "pubkey": "dd" * 16,
            },
            {
                "seq": 1,
                "root_hash": "ee" * 32,
                "tree_size": 3,
                "header_hash": "ff" * 32,
                "previous_header_hash": "",
                "timestamp": "2026-03-13T00:00:00Z",
                "signature": "cc" * 32,
                "pubkey": "dd" * 16,
            },
        ]
        self.counts = {
            "2026-03-14T00:00:00Z": -1,
            "2026-03-13T00:00:00Z": -1,
        }

    def get_latest_header(self, shard_id: str) -> dict[str, object]:
        assert shard_id == self.shard_id
        return self.latest_header

    def get_header_history(self, shard_id: str, n: int = 10) -> list[dict[str, object]]:
        assert shard_id == self.shard_id
        return self.history[:n]

    def get_leaf_count(self, shard_id: str, up_to_ts: str | None = None) -> int:
        assert shard_id == self.shard_id
        return self.counts.get(str(up_to_ts), 0)


@pytest.fixture()
def sth_client() -> tuple[TestClient, _FakeStorage]:
    """Inject fake storage into STH router for isolated testing."""
    previous_storage = getattr(sth_api, "_storage", None)
    fake_storage = _FakeStorage()
    sth_api.set_storage(fake_storage)
    client = TestClient(app)
    yield client, fake_storage
    sth_api.set_storage(previous_storage)


def test_latest_sth_returns_leaf_count(sth_client: tuple[TestClient, _FakeStorage]) -> None:
    client, fake_storage = sth_client

    resp = client.get("/protocol/sth/latest", params={"shard_id": fake_storage.shard_id})
    assert resp.status_code == 200
    payload = resp.json()

    assert payload["tree_size"] == fake_storage.latest_header["header"]["tree_size"]
    assert payload["merkle_root"] == fake_storage.latest_header["header"]["root_hash"]


def test_history_includes_leaf_counts(sth_client: tuple[TestClient, _FakeStorage]) -> None:
    client, fake_storage = sth_client

    resp = client.get(
        "/protocol/sth/history",
        params={"shard_id": fake_storage.shard_id, "n": 2},
    )
    assert resp.status_code == 200
    payload = resp.json()

    assert payload["sths"][0]["tree_size"] == fake_storage.history[0]["tree_size"]
    assert payload["sths"][1]["tree_size"] == fake_storage.history[1]["tree_size"]


@pytest.mark.parametrize("path", ["/protocol/sth/latest", "/protocol/sth/history"])
def test_sth_routes_reject_invalid_shard_id(
    sth_client: tuple[TestClient, _FakeStorage], path: str
) -> None:
    """STH routes reject malformed shard identifiers at validation time."""
    client, _ = sth_client
    resp = client.get(path, params={"shard_id": "bad shard!"})
    assert resp.status_code == 422
