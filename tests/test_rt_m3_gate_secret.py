"""
Tests for RT-M3: Trigger gate secret enforcement in production.

The mitigation in storage/gates.py enforces that
OLYMPUS_NODE_REHASH_GATE_SECRET must be set in production mode. In
development/test mode, the deterministic fallback is allowed with a warning.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import patch

import pytest

from storage.gates import derive_node_rehash_gate


class TestRTM3ProductionEnforcement:
    """Test that production mode requires the gate secret."""

    def test_raises_when_production_and_no_secret(self):
        """derive_node_rehash_gate raises RuntimeError in production without secret."""
        with patch.dict(os.environ, {"OLYMPUS_ENV": "production"}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            with pytest.raises(RuntimeError, match="OLYMPUS_NODE_REHASH_GATE_SECRET must be set"):
                derive_node_rehash_gate()

    def test_raises_when_env_unset_and_no_secret(self):
        """Default env (unset) is treated as production — must raise."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OLYMPUS_ENV", None)
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            with pytest.raises(RuntimeError, match="OLYMPUS_NODE_REHASH_GATE_SECRET must be set"):
                derive_node_rehash_gate()

    def test_raises_when_secret_is_empty_string(self):
        """An empty string secret is treated as unset in production."""
        with patch.dict(
            os.environ,
            {"OLYMPUS_ENV": "production", "OLYMPUS_NODE_REHASH_GATE_SECRET": ""},
            clear=False,
        ):
            with pytest.raises(RuntimeError, match="OLYMPUS_NODE_REHASH_GATE_SECRET must be set"):
                derive_node_rehash_gate()

    def test_succeeds_when_secret_is_set(self):
        """derive_node_rehash_gate succeeds in production when secret is set."""
        with patch.dict(
            os.environ,
            {
                "OLYMPUS_ENV": "production",
                "OLYMPUS_NODE_REHASH_GATE_SECRET": "a" * 64,
            },
            clear=False,
        ):
            gate = derive_node_rehash_gate()
        assert len(gate) == 64
        int(gate, 16)  # valid hex


class TestRTM3DevelopmentFallback:
    """Test that dev/test mode allows deterministic fallback with warning."""

    def test_warns_in_development_without_secret(self, caplog):
        """Development mode without secret logs a warning but succeeds."""
        with patch.dict(os.environ, {"OLYMPUS_ENV": "development"}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            with caplog.at_level(logging.WARNING, logger="storage.gates"):
                gate = derive_node_rehash_gate()
        assert len(gate) == 64
        assert "OLYMPUS_NODE_REHASH_GATE_SECRET is not set" in caplog.text

    def test_warns_in_test_mode_without_secret(self, caplog):
        """Test mode without secret logs a warning but succeeds."""
        with patch.dict(os.environ, {"OLYMPUS_ENV": "test"}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            with caplog.at_level(logging.WARNING, logger="storage.gates"):
                gate = derive_node_rehash_gate()
        assert len(gate) == 64
        assert "OLYMPUS_NODE_REHASH_GATE_SECRET is not set" in caplog.text

    def test_no_warning_when_secret_set_in_development(self, caplog):
        """No warning is logged when secret is set in dev mode."""
        with patch.dict(
            os.environ,
            {
                "OLYMPUS_ENV": "development",
                "OLYMPUS_NODE_REHASH_GATE_SECRET": "dev-secret",
            },
            clear=False,
        ):
            with caplog.at_level(logging.WARNING, logger="storage.gates"):
                gate = derive_node_rehash_gate()
        assert len(gate) == 64
        assert "OLYMPUS_NODE_REHASH_GATE_SECRET is not set" not in caplog.text


class TestRTM3SecretDifferentiation:
    """Test that different secrets produce different gate values."""

    def test_two_different_secrets_produce_different_gates(self):
        """Two distinct secrets must yield distinct gate values."""
        with patch.dict(
            os.environ,
            {"OLYMPUS_ENV": "production", "OLYMPUS_NODE_REHASH_GATE_SECRET": "alpha"},
            clear=False,
        ):
            g1 = derive_node_rehash_gate()
        with patch.dict(
            os.environ,
            {"OLYMPUS_ENV": "production", "OLYMPUS_NODE_REHASH_GATE_SECRET": "beta"},
            clear=False,
        ):
            g2 = derive_node_rehash_gate()
        assert g1 != g2

    def test_secret_vs_no_secret_differ(self):
        """Gate with secret differs from gate without secret."""
        with patch.dict(os.environ, {"OLYMPUS_ENV": "test"}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            gate_no_secret = derive_node_rehash_gate()

        with patch.dict(
            os.environ,
            {"OLYMPUS_ENV": "test", "OLYMPUS_NODE_REHASH_GATE_SECRET": "my-secret"},
            clear=False,
        ):
            gate_with_secret = derive_node_rehash_gate()

        assert gate_no_secret != gate_with_secret

    def test_error_message_includes_generation_command(self):
        """The error message includes the generation command for convenience."""
        with patch.dict(os.environ, {"OLYMPUS_ENV": "production"}, clear=False):
            os.environ.pop("OLYMPUS_NODE_REHASH_GATE_SECRET", None)
            with pytest.raises(RuntimeError, match="secrets.token_hex"):
                derive_node_rehash_gate()
