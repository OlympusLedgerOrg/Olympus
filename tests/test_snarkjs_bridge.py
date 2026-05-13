"""Tests for proofs.snarkjs_bridge module."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from proofs import snarkjs_bridge


# ---------------------------------------------------------------------------
# Prerequisites / availability
# ---------------------------------------------------------------------------


class TestBridgeAvailability:
    def test_bridge_available_with_node(self):
        """bridge_available reflects Node.js + helper + node_modules presence."""
        available = snarkjs_bridge.bridge_available()
        has_node = shutil.which("node") is not None
        if has_node:
            # Also needs script and node_modules
            assert available == (
                snarkjs_bridge._SCRIPT.exists() and snarkjs_bridge._NODE_MODULES.is_dir()
            )
        else:
            assert available is False

    def test_bridge_available_without_node(self, monkeypatch):
        monkeypatch.setattr("proofs.snarkjs_bridge._node_available", lambda: False)
        assert snarkjs_bridge.bridge_available() is False

    def test_prove_available_with_rapidsnark(self, monkeypatch):
        monkeypatch.setenv("OLYMPUS_ENABLE_RAPIDSNARK", "1")
        monkeypatch.setattr("proofs.snarkjs_bridge._rapidsnark_platform_supported", lambda: True)
        monkeypatch.setattr(
            "proofs.snarkjs_bridge._resolve_rapidsnark_path",
            lambda: "/bin/rapidsnark",
        )
        monkeypatch.setattr("proofs.snarkjs_bridge.bridge_available", lambda: False)
        assert snarkjs_bridge.prove_available() is True

    def test_rapidsnark_disabled_by_default_even_if_binary_exists(self, monkeypatch):
        monkeypatch.delenv("OLYMPUS_ENABLE_RAPIDSNARK", raising=False)
        monkeypatch.setattr("proofs.snarkjs_bridge._rapidsnark_platform_supported", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")

        assert snarkjs_bridge._resolve_rapidsnark_path() is None
        assert snarkjs_bridge.rapidsnark_unavailable_reason() == (
            "OLYMPUS_ENABLE_RAPIDSNARK is not set to 1"
        )

    def test_rapidsnark_reports_unsupported_platform(self, monkeypatch):
        monkeypatch.setenv("OLYMPUS_ENABLE_RAPIDSNARK", "1")
        monkeypatch.setattr("proofs.snarkjs_bridge._rapidsnark_platform_supported", lambda: False)
        monkeypatch.setattr("proofs.snarkjs_bridge.platform.system", lambda: "Windows")
        monkeypatch.setattr("proofs.snarkjs_bridge.platform.machine", lambda: "AMD64")

        assert snarkjs_bridge._resolve_rapidsnark_path() is None
        assert (
            snarkjs_bridge.rapidsnark_unavailable_reason() == "unsupported platform Windows AMD64"
        )

    def test_requested_rapidsnark_fallback_logs_warning(self, tmp_path, monkeypatch, caplog):
        witness = tmp_path / "test.wtns"
        witness.touch()
        zkey = tmp_path / "test.zkey"
        zkey.touch()

        monkeypatch.setenv("OLYMPUS_ENABLE_RAPIDSNARK", "1")
        monkeypatch.setattr("proofs.snarkjs_bridge._rapidsnark_platform_supported", lambda: False)
        monkeypatch.setattr("proofs.snarkjs_bridge.platform.system", lambda: "Windows")
        monkeypatch.setattr("proofs.snarkjs_bridge.platform.machine", lambda: "AMD64")

        class FakeProcess:
            def call(self, payload):
                return {"proof": {"pi_a": [], "pi_b": [], "pi_c": []}, "publicSignals": ["1"]}

        monkeypatch.setattr("proofs.snarkjs_bridge._get_process", lambda: FakeProcess())

        proof, public_signals = snarkjs_bridge.prove(witness_file=witness, zkey_file=zkey)

        assert proof == {"pi_a": [], "pi_b": [], "pi_c": []}
        assert public_signals == ["1"]
        assert (
            "RapidSNARK requested but unavailable: unsupported platform Windows AMD64"
            in caplog.text
        )


# ---------------------------------------------------------------------------
# _SnarkjsNodeProcess basic lifecycle
# ---------------------------------------------------------------------------


class TestSnarkjsNodeProcess:
    def test_process_starts_and_shuts_down(self):
        """The Node.js helper process starts, stays alive, and shuts down."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        proc = snarkjs_bridge._SnarkjsNodeProcess(snarkjs_bridge._SCRIPT)
        try:
            # Send an invalid op to exercise the round-trip without needing files
            with pytest.raises(RuntimeError, match="Unknown op"):
                proc.call({"op": "ping"})
            assert proc.alive
        finally:
            proc._shutdown()

    def test_process_raises_on_missing_script(self, tmp_path):
        """RuntimeError raised when helper script is missing."""
        fake_script = tmp_path / "does_not_exist.js"
        proc = snarkjs_bridge._SnarkjsNodeProcess(fake_script)
        with patch.object(snarkjs_bridge, "_SCRIPT", fake_script):
            with pytest.raises(RuntimeError, match="snarkjs helper script not found"):
                proc.call({"op": "verify"})


# ---------------------------------------------------------------------------
# prove / verify API — file validation
# ---------------------------------------------------------------------------


class TestProveFileValidation:
    def test_prove_missing_witness(self, tmp_path):
        """prove() raises FileNotFoundError for missing witness file."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        with pytest.raises(FileNotFoundError, match="Witness file"):
            snarkjs_bridge.prove(
                witness_file=tmp_path / "missing.wtns",
                zkey_file=tmp_path / "missing.zkey",
            )

    def test_prove_missing_zkey(self, tmp_path):
        """prove() raises FileNotFoundError for missing zkey file."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        witness = tmp_path / "test.wtns"
        witness.touch()
        with pytest.raises(FileNotFoundError, match="ZKey file"):
            snarkjs_bridge.prove(
                witness_file=witness,
                zkey_file=tmp_path / "missing.zkey",
            )

    def test_full_prove_missing_wasm(self, tmp_path):
        """full_prove() raises FileNotFoundError for missing WASM file."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        with pytest.raises(FileNotFoundError, match="WASM file"):
            snarkjs_bridge.full_prove(
                input_signals={"root": "0"},
                wasm_file=tmp_path / "missing.wasm",
                zkey_file=tmp_path / "missing.zkey",
            )

    def test_prove_uses_rapidsnark_when_available(self, tmp_path):
        witness = tmp_path / "test.wtns"
        witness.touch()
        zkey = tmp_path / "test.zkey"
        zkey.touch()

        def mock_run(cmd, **kwargs):
            Path(cmd[3]).write_text('{"pi_a":[],"pi_b":[],"pi_c":[]}', encoding="utf-8")
            Path(cmd[4]).write_text('["1"]', encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch.dict(os.environ, {"OLYMPUS_ENABLE_RAPIDSNARK": "1"}),
            patch("proofs.snarkjs_bridge._rapidsnark_platform_supported", return_value=True),
            patch(
                "proofs.snarkjs_bridge._resolve_rapidsnark_path",
                return_value="/usr/bin/rapidsnark",
            ),
            patch("proofs.snarkjs_bridge.subprocess.run", side_effect=mock_run) as run_mock,
            patch("proofs.snarkjs_bridge._get_process") as get_process_mock,
        ):
            proof, public_signals = snarkjs_bridge.prove(witness_file=witness, zkey_file=zkey)

        run_mock.assert_called_once()
        get_process_mock.assert_not_called()
        assert proof == {"pi_a": [], "pi_b": [], "pi_c": []}
        assert public_signals == ["1"]


class TestVerifyFileValidation:
    def test_verify_missing_vkey(self, tmp_path):
        """verify() raises FileNotFoundError for missing verification key."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        with pytest.raises(FileNotFoundError, match="Verification key"):
            snarkjs_bridge.verify(
                vkey_file=tmp_path / "missing_vkey.json",
                proof={"pi_a": [], "pi_b": [], "pi_c": []},
                public_signals=["0"],
            )


# ---------------------------------------------------------------------------
# Integration: verify with real vkey (no circuits/zkey needed)
# ---------------------------------------------------------------------------


class TestVerifyIntegration:
    """Verify that the bridge correctly calls snarkjs verify with a real vkey."""

    @staticmethod
    def _get_vkey_path() -> Path:
        repo_root = Path(__file__).resolve().parent.parent
        vkey = repo_root / "proofs" / "keys" / "verification_keys" / "document_existence_vkey.json"
        if not vkey.exists():
            pytest.skip("document_existence_vkey.json not available")
        return vkey

    def test_verify_rejects_invalid_proof(self):
        """A deliberately invalid proof should be rejected (ok=False)."""
        if not snarkjs_bridge.bridge_available():
            pytest.skip("Node.js bridge not available")
        vkey = self._get_vkey_path()
        result = snarkjs_bridge.verify(
            vkey_file=vkey,
            proof={
                "pi_a": ["0", "0", "1"],
                "pi_b": [["0", "0"], ["0", "0"], ["1", "0"]],
                "pi_c": ["0", "0", "1"],
                "protocol": "groth16",
                "curve": "bn128",
            },
            public_signals=["0", "0", "0"],
        )
        assert result is False
