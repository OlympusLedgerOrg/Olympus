"""Tests for remaining audit fixes (M1, M2, L1, L3, L4).

Covers:
- M2: RFC 3161 bare exception replacement with specific types + logging
- M1: Debug console minimum password length enforcement
- L1: ZIP symlink detection in upload validation
- L3: shard_timestamp_skew_ms positive-value validation
- L4: Debug console HTTPS enforcement via X-Forwarded-Proto
"""

from __future__ import annotations

import io
import logging
import stat
import unittest.mock
import zipfile

import pytest


# ── M2: RFC 3161 specific exception handling with logging ────────────────────


class TestRfc3161SpecificExceptions:
    """Verify that invalid TST bytes log warnings instead of silently failing."""

    def test_extract_tsa_cert_fingerprint_logs_on_invalid_input(self, caplog):
        from protocol.rfc3161 import _extract_tsa_cert_fingerprint

        with caplog.at_level(logging.WARNING, logger="protocol.rfc3161"):
            result = _extract_tsa_cert_fingerprint(b"\xff\xff")
        assert result is None
        assert "Failed to extract TSA certificate fingerprint" in caplog.text

    def test_extract_message_imprint_logs_on_invalid_input(self, caplog):
        from protocol.rfc3161 import _extract_message_imprint

        with caplog.at_level(logging.WARNING, logger="protocol.rfc3161"):
            result = _extract_message_imprint(b"\xff\xff")
        assert result is None
        assert "Failed to extract message imprint from TST" in caplog.text

    def test_extract_tsa_certificate_logs_on_invalid_input(self, caplog):
        from protocol.rfc3161 import extract_tsa_certificate

        with caplog.at_level(logging.WARNING, logger="protocol.rfc3161"):
            result = extract_tsa_certificate(b"\xff\xff")
        assert result is None
        assert "Failed to extract TSA certificate" in caplog.text

    def test_extract_tsa_cert_fingerprint_returns_none_for_empty(self, caplog):
        from protocol.rfc3161 import _extract_tsa_cert_fingerprint

        with caplog.at_level(logging.WARNING, logger="protocol.rfc3161"):
            assert _extract_tsa_cert_fingerprint(b"") is None

    def test_extract_message_imprint_returns_none_for_empty(self, caplog):
        from protocol.rfc3161 import _extract_message_imprint

        with caplog.at_level(logging.WARNING, logger="protocol.rfc3161"):
            assert _extract_message_imprint(b"") is None


# ── L1: ZIP symlink detection ────────────────────────────────────────────────


def _make_zip_with_symlink(name: str = "link.txt") -> bytes:
    """Create a ZIP archive containing a symlink entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(name)
        # Set Unix symlink mode in external_attr (upper 16 bits)
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


def _make_normal_zip(name: str = "hello.txt", content: str = "hello") -> bytes:
    """Create a normal ZIP archive for comparison."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, content)
    return buf.getvalue()


class TestZipSymlinkGuard:
    """Validate that ZIP archives containing symlinks are rejected."""

    def test_symlink_entry_rejected(self):
        from fastapi import HTTPException

        from api.services.upload_validation import validate_zip_safety

        content = _make_zip_with_symlink("link.txt")
        with pytest.raises(HTTPException) as exc_info:
            validate_zip_safety(content)
        assert exc_info.value.status_code == 400
        assert "symlink" in exc_info.value.detail.lower()

    def test_normal_zip_passes(self):
        from api.services.upload_validation import validate_zip_safety

        content = _make_normal_zip("hello.txt", "hello world")
        # Should not raise
        validate_zip_safety(content)


# ── L3: shard_timestamp_skew_ms validation ───────────────────────────────────


class TestShardTimestampSkewValidation:
    """Verify that shard_timestamp_skew_ms rejects non-positive values."""

    def test_zero_skew_rejected(self):
        from pydantic import ValidationError

        from api.config import Settings

        with pytest.raises(ValidationError, match="shard_timestamp_skew_ms must be positive"):
            Settings(shard_timestamp_skew_ms=0)

    def test_negative_skew_rejected(self):
        from pydantic import ValidationError

        from api.config import Settings

        with pytest.raises(ValidationError, match="shard_timestamp_skew_ms must be positive"):
            Settings(shard_timestamp_skew_ms=-1)

    def test_positive_skew_accepted(self):
        from api.config import Settings

        s = Settings(shard_timestamp_skew_ms=5000)
        assert s.shard_timestamp_skew_ms == 5000

    def test_default_skew_accepted(self):
        from api.config import Settings

        s = Settings()
        assert s.shard_timestamp_skew_ms == 30_000


# ── M1: Debug console minimum password length ───────────────────────────────


class TestDebugConsolePasswordMinLength:
    """Validate that short passwords are rejected in production."""

    def test_short_password_rejected_in_production(self):
        """Production mode with a password shorter than 16 chars should fail."""
        env = {
            "OLYMPUS_ENV": "production",
            "OLYMPUS_DEBUG_CONSOLE_PASSWORD": "short",
        }
        with unittest.mock.patch.dict("os.environ", env, clear=False):
            with pytest.raises(RuntimeError, match="at least 16 characters"):
                import importlib

                import ui.app

                importlib.reload(ui.app)

    def test_adequate_password_accepted_in_production(self):
        """Production mode with a 16+ character password should succeed."""
        env = {
            "OLYMPUS_ENV": "production",
            "OLYMPUS_DEBUG_CONSOLE_PASSWORD": "a_very_strong_password_here!!",
        }
        with unittest.mock.patch.dict("os.environ", env, clear=False):
            import importlib

            import ui.app

            importlib.reload(ui.app)
            assert ui.app._MIN_DEBUG_PASSWORD_LENGTH == 16


# ── L4: Debug console HTTPS enforcement ──────────────────────────────────────


class TestDebugConsoleHttpsEnforcement:
    """Validate that non-HTTPS requests are rejected in production debug console."""

    def test_http_forwarded_proto_rejected_in_production(self):
        """Request with X-Forwarded-Proto: http should be rejected in non-dev mode."""
        import importlib

        env = {
            "OLYMPUS_ENV": "production",
            "OLYMPUS_DEBUG_CONSOLE_PASSWORD": "a_very_strong_password_here!!",
        }
        with unittest.mock.patch.dict("os.environ", env, clear=False):
            import ui.app

            importlib.reload(ui.app)
            from fastapi.testclient import TestClient

            client = TestClient(ui.app.app)
            response = client.get("/", headers={"X-Forwarded-Proto": "http"})
            assert response.status_code == 421
            assert "HTTPS" in response.json()["detail"]

    def test_https_forwarded_proto_allowed_in_production(self):
        """Request with X-Forwarded-Proto: https should pass the proto check."""
        import importlib

        env = {
            "OLYMPUS_ENV": "production",
            "OLYMPUS_DEBUG_CONSOLE_PASSWORD": "a_very_strong_password_here!!",
        }
        with unittest.mock.patch.dict("os.environ", env, clear=False):
            import ui.app

            importlib.reload(ui.app)
            from fastapi.testclient import TestClient

            client = TestClient(ui.app.app)
            # Should reach auth (401) not proto check (421)
            response = client.get("/", headers={"X-Forwarded-Proto": "https"})
            assert response.status_code == 401

    def test_no_forwarded_proto_allowed_in_development(self):
        """Development mode should not enforce HTTPS check."""
        import importlib

        env = {
            "OLYMPUS_ENV": "development",
            "OLYMPUS_DEBUG_CONSOLE_PASSWORD": "",
        }
        with unittest.mock.patch.dict("os.environ", env, clear=False):
            import ui.app

            importlib.reload(ui.app)
            from fastapi.testclient import TestClient

            client = TestClient(ui.app.app)
            response = client.get("/manifest.json", headers={"X-Forwarded-Proto": "http"})
            # Should pass proto check in dev mode (200 for static, not 421)
            assert response.status_code != 421
