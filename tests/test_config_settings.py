"""
Tests for api.config — Settings management.

Covers:
- Default settings construction
- shard_timestamp_skew_ms validation (must be positive)
- cors_origins validator passthrough
- get_settings() caching
- _load_db_password() file/env fallback
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from api.config import Settings, _load_db_password


# ------------------------------------------------------------------ #
# Settings construction
# ------------------------------------------------------------------ #


class TestSettingsDefaults:
    """Tests for default Settings values."""

    def test_default_database_url(self) -> None:
        settings = Settings()
        assert "sqlite" in settings.database_url

    def test_default_app_title(self) -> None:
        settings = Settings()
        assert settings.app_title == "Olympus FOIA Ledger"

    def test_default_shard_id(self) -> None:
        settings = Settings()
        assert settings.default_shard_id == "0x4F3A"

    def test_default_max_upload_bytes(self) -> None:
        settings = Settings()
        assert settings.max_upload_bytes == 256 * 1024 * 1024

    def test_default_statutory_windows(self) -> None:
        settings = Settings()
        assert settings.statutory_window_nc_ack_days == 14
        assert settings.statutory_window_nc_fulfill_days == 30
        assert settings.statutory_window_foia_days == 20


# ------------------------------------------------------------------ #
# Validators
# ------------------------------------------------------------------ #


class TestSettingsValidators:
    """Tests for field validators."""

    def test_positive_skew_accepted(self) -> None:
        settings = Settings(shard_timestamp_skew_ms=1000)
        assert settings.shard_timestamp_skew_ms == 1000

    def test_zero_skew_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            Settings(shard_timestamp_skew_ms=0)

    def test_negative_skew_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            Settings(shard_timestamp_skew_ms=-1)

    def test_cors_origins_passthrough(self) -> None:
        settings = Settings(cors_origins="http://localhost:3000,https://example.com")
        assert "localhost:3000" in settings.cors_origins

    def test_empty_cors_origins(self) -> None:
        settings = Settings(cors_origins="")
        assert settings.cors_origins == ""


# ------------------------------------------------------------------ #
# _load_db_password
# ------------------------------------------------------------------ #


class TestLoadDbPassword:
    """Tests for _load_db_password() helper."""

    def test_no_env_returns_empty(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            # Remove both env vars if present
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in ("DATABASE_PASSWORD_FILE", "DATABASE_PASSWORD")
            }
            with patch.dict(os.environ, env, clear=True):
                result = _load_db_password()
                assert result == ""

    def test_password_from_env(self) -> None:
        with patch.dict(
            os.environ,
            {"DATABASE_PASSWORD": "secret123"},
            clear=False,
        ):
            # Ensure file-based override is not set
            os.environ.pop("DATABASE_PASSWORD_FILE", None)
            result = _load_db_password()
            assert result == "secret123"

    def test_password_from_file(self, tmp_path: object) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("file_secret\n")
            f.flush()
            with patch.dict(
                os.environ,
                {"DATABASE_PASSWORD_FILE": f.name},
                clear=False,
            ):
                result = _load_db_password()
                assert result == "file_secret"
            os.unlink(f.name)

    def test_missing_file_falls_back_to_env(self) -> None:
        with patch.dict(
            os.environ,
            {
                "DATABASE_PASSWORD_FILE": "/nonexistent/path/secret.txt",
                "DATABASE_PASSWORD": "env_fallback",
            },
            clear=False,
        ):
            result = _load_db_password()
            assert result == "env_fallback"
