from __future__ import annotations

from contextlib import contextmanager

import pytest

import api.services.storage_layer as storage_layer


class _DummyCursor:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, _query: str) -> None:
        return None

    def fetchone(self):
        return (1,)


class _DummyConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _DummyCursor()


class _FakeStorageLayer:
    def __init__(self, _connection_string: str):
        pass

    def init_schema(self) -> None:
        return None

    @contextmanager
    def _get_connection(self):
        yield _DummyConnection()


def _reset_storage_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage_layer, "_storage", None)
    monkeypatch.setattr(storage_layer, "_db_error", None)
    monkeypatch.setattr(storage_layer, "_logged_dev_tls_warning", False)


def test_startup_rejects_sslmode_require_in_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/olympus?sslmode=require")
    _reset_storage_state(monkeypatch)
    with pytest.raises(SystemExit, match="sslmode=verify-full"):
        storage_layer._get_storage()


def test_startup_accepts_sslmode_verify_full(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OLYMPUS_ENV", "production")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://user:pass@localhost:5432/olympus?sslmode=verify-full"
    )
    _reset_storage_state(monkeypatch)
    monkeypatch.setattr("storage.postgres.StorageLayer", _FakeStorageLayer)

    assert storage_layer._get_storage() is not None


def test_startup_allows_sslmode_disable_in_development_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setenv("OLYMPUS_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/olympus?sslmode=disable")
    _reset_storage_state(monkeypatch)
    monkeypatch.setattr("storage.postgres.StorageLayer", _FakeStorageLayer)

    with caplog.at_level("WARNING"):
        assert storage_layer._get_storage() is not None
    assert "Non-verifying Postgres sslmode" in caplog.text
