"""Tests for tools/ceremony_contribute.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# tools/ is not on sys.path by default — add the repo root so we can import it.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))


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
# contribute — success path
# ---------------------------------------------------------------------------


class TestCeremonyContributeSuccess:
    def test_contribute_returns_metadata(self, tmp_path: Path) -> None:
        """contribute() returns a metadata dict with the expected keys."""
        from ceremony_contribute import contribute

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)

        call_count = 0

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            m.returncode = 0
            if call_count == 1:
                # groth16 setup — write intermediate zkey
                initial_zkey = tmp_path / "initial_DONOTCOMMIT.zkey"
                initial_zkey.write_bytes(b"initial key material")
            else:
                # zkey contribute — write final output
                output.write_bytes(b"final key material")
            return m

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            meta = contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Test Participant",
                output_path=output,
            )

        assert meta["participant"] == "Test Participant"
        assert "zkey_blake3_hex" in meta
        assert "circuit_blake3_hex" in meta
        assert len(meta["zkey_blake3_hex"]) == 64
        assert len(meta["circuit_blake3_hex"]) == 64
        # Timestamp must end with Z (not +00:00)
        assert meta["timestamp"].endswith("Z")

    def test_contribute_writes_sidecar_json(self, tmp_path: Path) -> None:
        """A .metadata.json sidecar is written alongside the .zkey."""
        from ceremony_contribute import contribute

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)

        call_count = 0

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            m.returncode = 0
            if call_count == 1:
                (tmp_path / "initial_DONOTCOMMIT.zkey").write_bytes(b"init")
            else:
                output.write_bytes(b"final")
            return m

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
        import json

        data = json.loads(sidecar.read_text())
        assert data["participant"] == "Alice"
        assert "zkey_blake3_hex" in data
        assert "circuit_blake3_hex" in data

    def test_intermediate_zkey_removed_on_success(self, tmp_path: Path) -> None:
        """The intermediate .zkey is deleted after a successful contribution."""
        from ceremony_contribute import contribute

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)
        initial_zkey = tmp_path / "initial_DONOTCOMMIT.zkey"

        call_count = 0

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            m.returncode = 0
            if call_count == 1:
                initial_zkey.write_bytes(b"init key")
            else:
                output.write_bytes(b"final key")
            return m

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run
        ):
            contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="Bob",
                output_path=output,
            )

        assert not initial_zkey.exists(), "intermediate zkey must be deleted on success"


# ---------------------------------------------------------------------------
# contribute — failure branches
# ---------------------------------------------------------------------------


class TestCeremonyContributeFailures:
    def test_missing_ptau_raises_file_not_found(self, tmp_path: Path) -> None:
        """FileNotFoundError raised when PTAU file is missing."""
        from ceremony_contribute import contribute

        with pytest.raises(FileNotFoundError, match="[Pp][Tt][Aa][Uu]"):
            contribute(
                ptau_path=tmp_path / "missing.ptau",
                circuit_path=tmp_path / "circuit.circom",
                participant_name="test",
                output_path=tmp_path / "out.zkey",
            )

    def test_missing_circuit_raises_file_not_found(self, tmp_path: Path) -> None:
        """FileNotFoundError raised when circuit file is missing."""
        from ceremony_contribute import contribute

        ptau = tmp_path / "phase1.ptau"
        ptau.write_bytes(b"fake ptau")

        with pytest.raises(FileNotFoundError, match="[Cc]ircuit"):
            contribute(
                ptau_path=ptau,
                circuit_path=tmp_path / "circuit.circom",
                participant_name="test",
                output_path=tmp_path / "out.zkey",
            )

    def test_groth16_setup_failure_raises_runtime_error(self, tmp_path: Path) -> None:
        """If snarkjs groth16 setup exits non-zero, RuntimeError is raised."""
        from ceremony_contribute import contribute

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)

        def fake_run_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            m = MagicMock()
            m.returncode = 1
            m.stderr = "snarkjs error: something went wrong"
            return m

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

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)
        initial_zkey = tmp_path / "initial_DONOTCOMMIT.zkey"

        call_count = 0

        def fake_run_second_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            if call_count == 1:
                # setup succeeds, writes initial zkey
                initial_zkey.write_bytes(b"initial zkey")
                m.returncode = 0
            else:
                # contribute fails
                m.returncode = 1
                m.stderr = "contribute failed"
            return m

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

        # The intermediate zkey must be cleaned up even on failure
        assert not initial_zkey.exists(), "intermediate zkey must be deleted on failure"


# ---------------------------------------------------------------------------
# main() — CLI smoke tests
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_returns_1_when_snarkjs_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns 1 when snarkjs is not available."""
        from ceremony_contribute import main

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "ceremony_contribute",
                "--ptau", str(ptau),
                "--circuit", str(circuit),
                "--participant", "test",
                "--output", str(output),
            ],
        )
        with patch("ceremony_contribute._check_snarkjs", return_value=False):
            assert main() == 1

    def test_main_returns_1_on_contribute_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns 1 when contribute raises an exception."""
        from ceremony_contribute import main

        ptau, circuit, r1cs, output = _write_fake_files(tmp_path)

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

        def fake_run_fail(cmd: list[str], **kwargs: Any) -> MagicMock:
            m = MagicMock()
            m.returncode = 1
            m.stderr = "setup failed"
            return m

        with patch("ceremony_contribute._check_snarkjs", return_value=True), patch(
            "ceremony_contribute.subprocess.run", side_effect=fake_run_fail
        ):
            assert main() == 1
