"""Tests for sequencer token environment variable aliases (H-5).

Asserts that:
- OLYMPUS_SEQUENCER_TOKEN is the canonical environment variable for the Python client.
- SEQUENCER_API_TOKEN in api/ingest.py is accepted as a fallback when
  OLYMPUS_SEQUENCER_TOKEN is absent, and a deprecation warning is logged.
- GoSequencerClient reads OLYMPUS_SEQUENCER_TOKEN (not SEQUENCER_API_TOKEN).
"""

from __future__ import annotations

import logging


# ---------------------------------------------------------------------------
# GoSequencerClient token resolution
# ---------------------------------------------------------------------------


class TestGoSequencerClientTokenResolution:
    """GoSequencerClient reads OLYMPUS_SEQUENCER_TOKEN."""

    def test_reads_olympus_sequencer_token(self, monkeypatch):
        """Client picks up the canonical env var."""
        monkeypatch.setenv("OLYMPUS_SEQUENCER_TOKEN", "canonical-token-abc123")
        monkeypatch.delenv("SEQUENCER_API_TOKEN", raising=False)

        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient()
        assert client._token == "canonical-token-abc123"

    def test_does_not_fall_back_to_sequencer_api_token(self, monkeypatch):
        """GoSequencerClient does NOT read the Go-server-side SEQUENCER_API_TOKEN.

        The Python client is always configured via OLYMPUS_SEQUENCER_TOKEN.
        SEQUENCER_API_TOKEN is a Go-server env var, not a Python client var.
        """
        monkeypatch.delenv("OLYMPUS_SEQUENCER_TOKEN", raising=False)
        monkeypatch.setenv("SEQUENCER_API_TOKEN", "old-server-token")

        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient()
        # The Python client should NOT pick up SEQUENCER_API_TOKEN
        assert client._token != "old-server-token"

    def test_explicit_token_overrides_env(self, monkeypatch):
        """Constructor token parameter takes precedence over env vars."""
        monkeypatch.setenv("OLYMPUS_SEQUENCER_TOKEN", "env-token")

        from api.services.sequencer_client import GoSequencerClient

        client = GoSequencerClient(token="explicit-token")
        assert client._token == "explicit-token"

    def test_missing_token_logs_error(self, monkeypatch, caplog):
        """Missing token emits an error-level log (detected at client init)."""
        monkeypatch.delenv("OLYMPUS_SEQUENCER_TOKEN", raising=False)
        monkeypatch.delenv("SEQUENCER_API_TOKEN", raising=False)

        from api.services.sequencer_client import GoSequencerClient

        with caplog.at_level(logging.ERROR, logger="api.services.sequencer_client"):
            client = GoSequencerClient()

        assert client._token == ""
        assert any("OLYMPUS_SEQUENCER_TOKEN" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# api/ingest.py — deprecated alias support
# ---------------------------------------------------------------------------


class TestIngestTokenAlias:
    """api/ingest.py accepts SEQUENCER_API_TOKEN as a deprecated fallback."""

    def test_olympus_sequencer_token_is_preferred(self, monkeypatch):
        """OLYMPUS_SEQUENCER_TOKEN takes priority over SEQUENCER_API_TOKEN."""
        monkeypatch.setenv("OLYMPUS_SEQUENCER_TOKEN", "canonical")
        monkeypatch.setenv("SEQUENCER_API_TOKEN", "legacy")

        # Reload the module so the module-level token resolution re-runs
        import importlib

        import api.ingest as ingest_mod

        importlib.reload(ingest_mod)

        assert ingest_mod._sequencer_token == "canonical"

    def test_sequencer_api_token_fallback(self, monkeypatch):
        """When OLYMPUS_SEQUENCER_TOKEN is absent, SEQUENCER_API_TOKEN is used."""
        monkeypatch.delenv("OLYMPUS_SEQUENCER_TOKEN", raising=False)
        monkeypatch.setenv("SEQUENCER_API_TOKEN", "legacy-token-value")

        import importlib

        import api.ingest as ingest_mod

        importlib.reload(ingest_mod)

        assert ingest_mod._sequencer_token == "legacy-token-value"

    def test_sequencer_api_token_fallback_emits_warning(self, monkeypatch, caplog):
        """Using SEQUENCER_API_TOKEN alone emits a deprecation warning."""
        monkeypatch.delenv("OLYMPUS_SEQUENCER_TOKEN", raising=False)
        monkeypatch.setenv("SEQUENCER_API_TOKEN", "legacy-only")

        import importlib

        import api.ingest as ingest_mod

        with caplog.at_level(logging.WARNING, logger="api.ingest"):
            importlib.reload(ingest_mod)

        deprecation_msgs = [
            r.message
            for r in caplog.records
            if "SEQUENCER_API_TOKEN" in r.message and "deprecated" in r.message.lower()
        ]
        assert deprecation_msgs, (
            "Expected a deprecation warning about SEQUENCER_API_TOKEN, got none. "
            f"All log messages: {[r.message for r in caplog.records]}"
        )

    def test_missing_both_tokens_emits_warning(self, monkeypatch, caplog):
        """Missing both env vars emits a warning about OLYMPUS_SEQUENCER_TOKEN."""
        monkeypatch.delenv("OLYMPUS_SEQUENCER_TOKEN", raising=False)
        monkeypatch.delenv("SEQUENCER_API_TOKEN", raising=False)

        import importlib

        import api.ingest as ingest_mod

        with caplog.at_level(logging.WARNING, logger="api.ingest"):
            importlib.reload(ingest_mod)

        assert ingest_mod._sequencer_token == ""
        assert any("OLYMPUS_SEQUENCER_TOKEN" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# storage_layer._use_go_sequencer — CRITICAL warning on startup
# ---------------------------------------------------------------------------


class TestGoSequencerExperimentalWarning:
    """_use_go_sequencer logs CRITICAL when Path B is enabled."""

    def test_critical_warning_logged_when_enabled(self, monkeypatch, caplog):
        """First call with OLYMPUS_USE_GO_SEQUENCER=true emits CRITICAL."""
        monkeypatch.setenv("OLYMPUS_USE_GO_SEQUENCER", "true")

        # Reset the once-warning guard so this test sees a fresh state
        from api.services import storage_layer

        storage_layer._use_go_sequencer._warned = False  # type: ignore[attr-defined]

        with caplog.at_level(logging.CRITICAL, logger="api.services.storage_layer"):
            result = storage_layer._use_go_sequencer()

        assert result is True
        critical_msgs = [r for r in caplog.records if r.levelno == logging.CRITICAL]
        assert critical_msgs, "Expected a CRITICAL warning, got none"
        assert any("EXPERIMENTAL" in r.message for r in critical_msgs)

    def test_critical_warning_emitted_only_once(self, monkeypatch, caplog):
        """The CRITICAL warning is only emitted on the first call."""
        monkeypatch.setenv("OLYMPUS_USE_GO_SEQUENCER", "true")

        from api.services import storage_layer

        storage_layer._use_go_sequencer._warned = False  # type: ignore[attr-defined]

        with caplog.at_level(logging.CRITICAL, logger="api.services.storage_layer"):
            storage_layer._use_go_sequencer()
            storage_layer._use_go_sequencer()
            storage_layer._use_go_sequencer()

        critical_msgs = [r for r in caplog.records if r.levelno == logging.CRITICAL]
        assert len(critical_msgs) == 1, f"Expected exactly 1 CRITICAL log, got {len(critical_msgs)}"

    def test_no_warning_when_disabled(self, monkeypatch, caplog):
        """No CRITICAL warning when OLYMPUS_USE_GO_SEQUENCER is false/unset."""
        monkeypatch.delenv("OLYMPUS_USE_GO_SEQUENCER", raising=False)

        from api.services import storage_layer

        storage_layer._use_go_sequencer._warned = False  # type: ignore[attr-defined]

        with caplog.at_level(logging.CRITICAL, logger="api.services.storage_layer"):
            result = storage_layer._use_go_sequencer()

        assert result is False
        critical_msgs = [r for r in caplog.records if r.levelno == logging.CRITICAL]
        assert not critical_msgs
