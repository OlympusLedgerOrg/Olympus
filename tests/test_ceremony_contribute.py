"""Tests for tools/ceremony_contribute.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# tools/ is not on sys.path by default — add it so we can import the CLI module.
TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_fake_files(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Write minimal fake ceremony input files to *tmp_path*.

    Returns (ptau, circuit, r1cs, output_zkey).
    """
    ptau = tmp_path / "phase1.ptau"
    ptau.write_bytes(b"fake ptau")
    circuit = tmp_path / "circuit.circom"
    circuit.write_text("pragma circom 2.0.0;")
    r1cs = tmp_path / "circuit.r1cs"
    r1cs.write_bytes(b"fake r1cs")
    output = tmp_path / "out.zkey"
    return ptau, circuit, r1cs, output


# ---------------------------------------------------------------------------
# _hash_file
# ---------------------------------------------------------------------------


class TestHashFile:
    def test_contribution_hash_is_deterministic(self, tmp_path: Path) -> None:
        """Same file → same BLAKE3 hash. Proves our hashing is stable."""
        from ceremony_contribute import _hash_file

        f = tmp_path / "test.zkey"
        f.write_bytes(b"deterministic content")

        h1 = _hash_file(f)
        h2 = _hash_file(f)
        assert h1 == h2
        assert len(h1) == 64  # BLAKE3 hex digest is 64 chars

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        from ceremony_contribute import _hash_file

        a = tmp_path / "a.zkey"
        b = tmp_path / "b.zkey"
        a.write_bytes(b"content-a")
        b.write_bytes(b"content-b")

        assert _hash_file(a) != _hash_file(b)


# ---------------------------------------------------------------------------
# _check_snarkjs
# ---------------------------------------------------------------------------


class TestCheckSnarkjs:
    def test_returns_true_when_snarkjs_available(self) -> None:
        from ceremony_contribute import _check_snarkjs

        mock = MagicMock()
        mock.returncode = 0
        with patch("ceremony_contribute.subprocess.run", return_value=mock):
            assert _check_snarkjs() is True

    def test_returns_false_when_snarkjs_missing(self) -> None:
        from ceremony_contribute import _check_snarkjs

        with patch(
            "ceremony_contribute.subprocess.run",
            side_effect=FileNotFoundError("npx not found"),
        ):
            assert _check_snarkjs() is False

    def test_check_snarkjs_returns_false_on_timeout(self) -> None:
        """_check_snarkjs returns False if snarkjs version check times out."""
        from ceremony_contribute import _check_snarkjs

        with patch(
            "ceremony_contribute.subprocess.run",
            side_effect=subprocess.TimeoutExpired("npx", 10),
        ):
            assert _check_snarkjs() is False


# ---------------------------------------------------------------------------
# contribute — prerequisite failures
# ---------------------------------------------------------------------------


class TestCeremonyPrerequisiteChecks:
    def test_missing_ptau_raises_file_not_found(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        with pytest.raises(FileNotFoundError, match="[Pp][Tt][Aa][Uu]"):
            contribute(
                ptau_path=tmp_path / "nonexistent.ptau",
                circuit_path=tmp_path / "circuit.circom",
                participant_name="test",
                output_path=tmp_path / "out.zkey",
            )

    def test_missing_circuit_raises_file_not_found(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        ptau = tmp_path / "phase1.ptau"
        ptau.write_bytes(b"fake ptau")

        with pytest.raises(FileNotFoundError, match="[Cc]ircuit"):
            contribute(
                ptau_path=ptau,
                circuit_path=tmp_path / "nonexistent.circom",
                participant_name="test",
                output_path=tmp_path / "out.zkey",
            )

    def test_missing_snarkjs_raises_runtime_error(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        ptau = tmp_path / "phase1.ptau"
        ptau.write_bytes(b"fake ptau")
        circuit = tmp_path / "circuit.circom"
        circuit.write_text("pragma circom 2.0.0;")

        with patch("ceremony_contribute._check_snarkjs", return_value=False):
            with pytest.raises(RuntimeError, match="snarkjs"):
                contribute(
                    ptau_path=ptau,
                    circuit_path=circuit,
                    participant_name="test",
                    output_path=tmp_path / "out.zkey",
                )

    def test_missing_r1cs_raises_file_not_found(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        ptau = tmp_path / "phase1.ptau"
        ptau.write_bytes(b"fake ptau")
        circuit = tmp_path / "circuit.circom"
        circuit.write_text("pragma circom 2.0.0;")

        with patch("ceremony_contribute._check_snarkjs", return_value=True):
            with pytest.raises(FileNotFoundError, match="R1CS"):
                contribute(
                    ptau_path=ptau,
                    circuit_path=circuit,
                    participant_name="test",
                    output_path=tmp_path / "out.zkey",
                )


# ---------------------------------------------------------------------------
# contribute — success path
# ---------------------------------------------------------------------------


class TestCeremonyContributeSuccess:
    def test_contribute_returns_metadata(self, tmp_path: Path) -> None:
        """contribute() returns a metadata dict with the expected keys."""
        from ceremony_contribute import contribute

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)
        seen_timeouts: list[int] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            seen_timeouts.append(kwargs["timeout"])
            mock = MagicMock()
            mock.returncode = 0
            if "setup" in cmd:
                Path(cmd[-1]).write_bytes(b"initial key material")
            elif "contribute" in cmd:
                assert any(arg.startswith("-e=") for arg in cmd)
                Path(cmd[5]).write_bytes(b"final key material")
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            meta = contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Test Participant",
                output_path=output,
            )

        assert seen_timeouts == [1800, 3600]
        assert meta["participant"] == "Test Participant"
        assert "zkey_blake3_hex" in meta
        assert "circuit_blake3_hex" in meta
        assert "contribution_hash" not in meta
        assert len(meta["zkey_blake3_hex"]) == 64
        assert len(meta["circuit_blake3_hex"]) == 64
        assert meta["timestamp"].endswith("Z")

    def test_contribute_writes_sidecar_json(self, tmp_path: Path) -> None:
        """A .metadata.json sidecar is written alongside the .zkey."""
        from ceremony_contribute import contribute

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            mock.returncode = 0
            if "setup" in cmd:
                Path(cmd[-1]).write_bytes(b"init")
            elif "contribute" in cmd:
                Path(cmd[5]).write_bytes(b"final")
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Alice",
                output_path=output,
            )

        sidecar = output.with_suffix(".metadata.json")
        assert sidecar.exists()
        data = json.loads(sidecar.read_text())
        assert data["participant"] == "Alice"
        assert "zkey_blake3_hex" in data
        assert "circuit_blake3_hex" in data

    def test_intermediate_zkey_removed_on_success(self, tmp_path: Path) -> None:
        """The intermediate .zkey is deleted after a successful contribution."""
        from ceremony_contribute import INITIAL_ZKEY_PREFIX, contribute

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            mock.returncode = 0
            if "setup" in cmd:
                Path(cmd[-1]).write_bytes(b"init key")
            elif "contribute" in cmd:
                Path(cmd[5]).write_bytes(b"final key")
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Bob",
                output_path=output,
            )

        assert not list(tmp_path.glob(f"{INITIAL_ZKEY_PREFIX}*.zkey"))

    def test_output_named_like_old_temp_file_is_not_deleted(self, tmp_path: Path) -> None:
        """The final output is never the same path as the intermediate .zkey."""
        from ceremony_contribute import contribute

        ptau, circuit, _r1cs, _output = _write_fake_files(tmp_path)
        output = tmp_path / "initial_DONOTCOMMIT.zkey"

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            mock.returncode = 0
            if "setup" in cmd:
                assert Path(cmd[-1]) != output
                Path(cmd[-1]).write_bytes(b"init key")
            elif "contribute" in cmd:
                Path(cmd[5]).write_bytes(b"final key")
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Carol",
                output_path=output,
            )

        assert output.exists()
        assert output.read_bytes() == b"final key"


# ---------------------------------------------------------------------------
# contribute — failure branches
# ---------------------------------------------------------------------------


class TestCeremonyContributeFailures:
    def test_groth16_setup_failure_raises_runtime_error(self, tmp_path: Path) -> None:
        """If snarkjs groth16 setup exits non-zero, RuntimeError is raised."""
        from ceremony_contribute import contribute

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)

        def fake_run_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            mock.returncode = 1
            mock.stderr = "snarkjs error: something went wrong"
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run_fail
        ):
            with pytest.raises(RuntimeError, match="groth16 setup failed"):
                contribute(
                    ptau_path=ptau,
                    circuit_path=circuit,
                    participant_name="test",
                    output_path=output,
                )

    def test_zkey_contribute_failure_raises_runtime_error(self, tmp_path: Path) -> None:
        """If snarkjs zkey contribute exits non-zero, RuntimeError is raised."""
        from ceremony_contribute import contribute

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)
        intermediate_paths: list[Path] = []

        def fake_run_second_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            if "setup" in cmd:
                intermediate = Path(cmd[-1])
                intermediate_paths.append(intermediate)
                intermediate.write_bytes(b"initial zkey")
                mock.returncode = 0
            else:
                mock.returncode = 1
                mock.stderr = "contribute failed"
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run_second_fail
        ):
            with pytest.raises(RuntimeError, match="zkey contribute failed"):
                contribute(
                    ptau_path=ptau,
                    circuit_path=circuit,
                    participant_name="test",
                    output_path=output,
                )

        assert intermediate_paths
        assert all(not path.exists() for path in intermediate_paths)


# ---------------------------------------------------------------------------
# main() — CLI smoke tests
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_returns_1_when_snarkjs_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns 1 when snarkjs is not available."""
        from ceremony_contribute import main

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "ceremony_contribute",
                "--ptau",
                str(ptau),
                "--circuit",
                str(circuit),
                "--participant",
                "test",
                "--output",
                str(output),
            ],
        )
        with patch("ceremony_contribute._check_snarkjs", return_value=False):
            assert main() == 1

    def test_main_returns_1_on_contribute_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns 1 when contribute raises an exception."""
        from ceremony_contribute import main

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "ceremony_contribute",
                "--ptau",
                str(ptau),
                "--circuit",
                str(circuit),
                "--participant-name",
                "test",
                "--output",
                str(output),
            ],
        )

        def fake_run_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            mock = MagicMock()
            mock.returncode = 1
            mock.stderr = "setup failed"
            return mock

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run_fail
        ):
            assert main() == 1

    def test_main_returns_1_on_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns 1 instead of a traceback when snarkjs times out."""
        from ceremony_contribute import main

        ptau, circuit, _r1cs, output = _write_fake_files(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "ceremony_contribute",
                "--ptau",
                str(ptau),
                "--circuit",
                str(circuit),
                "--participant",
                "test",
                "--output",
                str(output),
            ],
        )

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run",
            side_effect=subprocess.TimeoutExpired("snarkjs", 1800),
        ):
            assert main() == 1
