"""Tests for production API database configuration guardrails."""

import importlib
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import api.services.storage_layer as storage_layer_mod


api_app = importlib.import_module("api.app")


def test_get_storage_rejects_missing_database_url(monkeypatch):
    """DB-backed endpoints must reject requests when DATABASE_URL is unset."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(storage_layer_mod, "_storage", None)
    monkeypatch.setattr(storage_layer_mod, "_db_error", None)

    with pytest.raises(HTTPException, match="Database temporarily unavailable"):
        api_app._get_storage()


def test_run_api_requires_database_url():
    """run_api.py should fail fast when DATABASE_URL is unset."""
    run_api_path = Path(__file__).resolve().parent.parent / "run_api.py"
    env = dict(os.environ)
    env.pop("DATABASE_URL", None)

    result = subprocess.run(
        [sys.executable, str(run_api_path)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "DATABASE_URL is required" in (result.stderr + result.stdout)


def test_get_storage_normalizes_asyncpg_url_for_psycopg(monkeypatch):
    """Storage init should strip +asyncpg driver suffix before psycopg use."""
    captured: dict[str, str] = {}

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
        def __init__(self, connection_string: str):
            captured["connection_string"] = connection_string

        def init_schema(self) -> None:
            return None

        @contextmanager
        def _get_connection(self):
            yield _DummyConnection()

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+asyncpg://user:pass@localhost:5432/olympus",
    )
    monkeypatch.setattr(storage_layer_mod, "_storage", None)
    monkeypatch.setattr(storage_layer_mod, "_db_error", None)
    monkeypatch.setattr("storage.postgres.StorageLayer", _FakeStorageLayer)

    storage = api_app._get_storage()

    assert storage is not None
    assert captured["connection_string"] == "postgresql://user:pass@localhost:5432/olympus"


def test_require_storage_runs_rust_smt_smoke_test_once(monkeypatch):
    """_require_storage() should run the Rust SMT smoke test once per process."""
    calls: list[tuple[bytes, bytes, list[bytes]]] = []
    sentinel_storage = object()

    class _FakeRustSparseMerkleTree:
        @staticmethod
        def incremental_update(key: bytes, value_hash: bytes, siblings: list[bytes]):
            calls.append((key, value_hash, siblings))
            return (b"\x00" * 32, list(siblings), [(0, b"", b"\x00" * 32)] * 256)

    monkeypatch.setattr(storage_layer_mod, "_rust_smt_smoke_test_complete", False)
    monkeypatch.setattr(storage_layer_mod, "_get_storage", lambda: sentinel_storage)
    monkeypatch.setitem(
        sys.modules,
        "olympus_core",
        SimpleNamespace(RustSparseMerkleTree=_FakeRustSparseMerkleTree),
    )

    assert storage_layer_mod._require_storage() is sentinel_storage
    assert storage_layer_mod._require_storage() is sentinel_storage
    assert len(calls) == 1


def test_require_storage_hard_fails_when_rust_smt_smoke_test_raises(monkeypatch):
    """_require_storage() should fail hard if Rust incremental_update raises."""
    sentinel_storage = object()

    class _FakeRustSparseMerkleTree:
        @staticmethod
        def incremental_update(_key: bytes, _value_hash: bytes, _siblings: list[bytes]):
            raise ValueError("boom")

    monkeypatch.setattr(storage_layer_mod, "_rust_smt_smoke_test_complete", False)
    monkeypatch.setattr(storage_layer_mod, "_get_storage", lambda: sentinel_storage)
    monkeypatch.setitem(
        sys.modules,
        "olympus_core",
        SimpleNamespace(RustSparseMerkleTree=_FakeRustSparseMerkleTree),
    )

    with pytest.raises(RuntimeError, match="Rust SMT startup smoke test failed"):
        storage_layer_mod._require_storage()
