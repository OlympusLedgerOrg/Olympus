"""Tests for tools/ceremony_contribute.py.

These are unit tests — they mock snarkjs and file I/O so the ceremony
can be verified without actually running the ZK ceremony (which requires
gigabytes of ptau files and external participants).

What we test:
- Error handling when prerequisites are missing
- Metadata is written correctly
- The contribution hash is deterministic given the same output file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# Add tools/ to path so we can import ceremony_contribute
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))


class TestCeremonyPrerequisiteChecks:
    def test_missing_ptau_raises_file_not_found(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        with pytest.raises(FileNotFoundError, match="ptau"):
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

        with pytest.raises(FileNotFoundError, match="circuit"):
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
        # No .r1cs file exists

        with patch("ceremony_contribute._check_snarkjs", return_value=True):
            with pytest.raises(FileNotFoundError, match="R1CS"):
                contribute(
                    ptau_path=ptau,
                    circuit_path=circuit,
                    participant_name="test",
                    output_path=tmp_path / "out.zkey",
                )


class TestCeremonyContributeSuccess:
    def test_metadata_written_on_success(self, tmp_path: Path) -> None:
        from ceremony_contribute import contribute

        ptau = tmp_path / "phase1.ptau"
        ptau.write_bytes(b"fake ptau")
        circuit = tmp_path / "circuit.circom"
        circuit.write_text("pragma circom 2.0.0;")
        r1cs = tmp_path / "circuit.r1cs"
        r1cs.write_bytes(b"fake r1cs")
        output = tmp_path / "contributions" / "test.zkey"

        def fake_run(cmd, **kwargs):
            # Simulate snarkjs writing output files
            if "setup" in cmd:
                (tmp_path / "initial_0000.zkey").write_bytes(b"initial zkey")
            elif "contribute" in cmd:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"contributed zkey data")
            m = MagicMock()
            m.returncode = 0
            return m

        with (
            patch("ceremony_contribute._check_snarkjs", return_value=True),
            patch("ceremony_contribute.subprocess.run", side_effect=fake_run),
        ):
            metadata = contribute(
                ptau_path=ptau,
                circuit_path=circuit,
                participant_name="FPF Test",
                output_path=output,
            )

        assert metadata["participant"] == "FPF Test"
        assert len(metadata["contribution_hash"]) == 64  # SHA-256 hex
        assert "timestamp" in metadata

        # Verify metadata file was written
        meta_file = output.with_suffix(".json")
        assert meta_file.exists()
        written = json.loads(meta_file.read_text())
        assert written["participant"] == "FPF Test"

    def test_contribution_hash_is_deterministic(self, tmp_path: Path) -> None:
        """Same output file → same hash. Proves our hashing is stable."""
        from ceremony_contribute import _sha256_file

        f = tmp_path / "test.zkey"
        f.write_bytes(b"deterministic content")

        h1 = _sha256_file(f)
        h2 = _sha256_file(f)
        assert h1 == h2
        assert len(h1) == 64


class TestCheckSnarkjs:
    def test_returns_true_when_available(self) -> None:
        from ceremony_contribute import _check_snarkjs

        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("ceremony_contribute.subprocess.run", return_value=mock_result):
            assert _check_snarkjs() is True

    def test_returns_false_when_not_found(self) -> None:
        from ceremony_contribute import _check_snarkjs

        with patch("ceremony_contribute.subprocess.run", side_effect=FileNotFoundError):
            assert _check_snarkjs() is False
