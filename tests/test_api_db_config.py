"""Tests for production API database configuration guardrails."""

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


api_app = importlib.import_module("api.app")


def test_get_storage_rejects_missing_database_url(monkeypatch):
    """DB-backed endpoints must reject requests when DATABASE_URL is unset."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(api_app, "_storage", None)
    monkeypatch.setattr(api_app, "_db_error", None)

    with pytest.raises(HTTPException, match="DATABASE_URL is required"):
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
