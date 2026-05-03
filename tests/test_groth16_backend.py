"""
Tests for the Groth16 proof backend implementation.

This module tests the Groth16Backend class which wraps snarkjs CLI
for proof generation and verification.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from protocol.groth16_backend import Groth16Backend
from protocol.proof_interface import (
    BackendNotAvailableError,
    Proof,
    ProofGenerationError,
    ProofSystemType,
    ProofVerificationError,
    Statement,
    Witness,
)


class TestIsAvailable:
    """Tests for the is_available() method."""

    def test_is_available_returns_true_when_snarkjs_found(self) -> None:
        """Test that is_available() returns True when snarkjs binary is in PATH."""
        backend = Groth16Backend()
        with patch("shutil.which", return_value="/usr/bin/npx"):
            assert backend.is_available() is True

    def test_is_available_returns_false_when_snarkjs_not_found(self) -> None:
        """Test that is_available() returns False when snarkjs binary is not in PATH."""
        backend = Groth16Backend()
        with patch("shutil.which", return_value=None):
            assert backend.is_available() is False


class TestResolveNodeBin:
    """Tests for the _resolve_node_bin() static method."""

    def test_resolve_node_bin_returns_path_when_found(self) -> None:
        """Test that _resolve_node_bin() returns the node path when found."""
        with patch("shutil.which", return_value="/usr/bin/node"):
            result = Groth16Backend._resolve_node_bin()
            assert result == "/usr/bin/node"

    def test_resolve_node_bin_raises_when_node_not_found(self) -> None:
        """Test that _resolve_node_bin() raises BackendNotAvailableError when node is not in PATH."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(BackendNotAvailableError) as exc_info:
                Groth16Backend._resolve_node_bin()
            assert "Node.js binary 'node' not found" in str(exc_info.value)


class TestResolveSnarkjsBin:
    """Tests for the _resolve_snarkjs_bin() method."""

    def test_resolve_snarkjs_bin_returns_path_when_found(self) -> None:
        """Test that _resolve_snarkjs_bin() returns the snarkjs path when found."""
        backend = Groth16Backend(snarkjs_bin="npx")
        with patch("shutil.which", return_value="/usr/bin/npx"):
            result = backend._resolve_snarkjs_bin()
            assert result == "/usr/bin/npx"

    def test_resolve_snarkjs_bin_raises_when_snarkjs_not_found(self) -> None:
        """Test that _resolve_snarkjs_bin() raises BackendNotAvailableError when snarkjs is not found."""
        backend = Groth16Backend(snarkjs_bin="snarkjs")
        with patch("shutil.which", return_value=None):
            with pytest.raises(BackendNotAvailableError) as exc_info:
                backend._resolve_snarkjs_bin()
            assert "snarkjs binary 'snarkjs' not found" in str(exc_info.value)


class TestValidateArtifactPath:
    """Tests for the _validate_artifact_path() method."""

    def test_validate_artifact_path_raises_for_path_outside_circuits_directory(
        self, tmp_path: Path
    ) -> None:
        """Test that _validate_artifact_path() raises for paths outside the circuits directory."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir)

        outside_path = tmp_path / "outside" / "file.zkey"
        outside_path.parent.mkdir(parents=True, exist_ok=True)
        outside_path.touch()

        with pytest.raises(ProofGenerationError) as exc_info:
            backend._validate_artifact_path(outside_path, kind="ZKey file")
        assert "outside expected circuits directories" in str(exc_info.value)

    def test_validate_artifact_path_raises_for_nonexistent_file(self, tmp_path: Path) -> None:
        """Test that _validate_artifact_path() raises when the artifact file does not exist."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir)

        nonexistent_path = build_dir / "nonexistent.zkey"

        with pytest.raises(ProofGenerationError) as exc_info:
            backend._validate_artifact_path(nonexistent_path, kind="ZKey file")
        assert "not found" in str(exc_info.value)

    def test_validate_artifact_path_succeeds_for_valid_path(self, tmp_path: Path) -> None:
        """Test that _validate_artifact_path() returns resolved path for valid artifacts."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir)

        valid_path = build_dir / "valid.zkey"
        valid_path.touch()

        result = backend._validate_artifact_path(valid_path, kind="ZKey file")
        assert result == valid_path.resolve()


class TestValidateCircuitName:
    """Tests for the _validate_circuit_name() static method."""

    def test_validate_circuit_name_raises_for_invalid_names(self) -> None:
        """Test that _validate_circuit_name() raises ValueError for invalid circuit names."""
        invalid_names = [
            "../traversal",
            "path/to/circuit",
            "circuit.json",
            "circuit name",
            "circuit;injection",
            "",
        ]
        for name in invalid_names:
            with pytest.raises(ValueError) as exc_info:
                Groth16Backend._validate_circuit_name(name)
            assert "Invalid circuit identifier" in str(exc_info.value)

    def test_validate_circuit_name_accepts_valid_names(self) -> None:
        """Test that _validate_circuit_name() accepts valid alphanumeric circuit names."""
        valid_names = [
            "document_existence",
            "test-circuit",
            "Circuit123",
            "my_circuit_v2",
        ]
        for name in valid_names:
            # Should not raise
            Groth16Backend._validate_circuit_name(name)


class TestGenerate:
    """Tests for the generate() method."""

    def test_generate_raises_when_snarkjs_not_available(self) -> None:
        """Test that generate() raises BackendNotAvailableError when snarkjs is not found."""
        backend = Groth16Backend()
        statement = Statement(circuit="test", public_inputs={"a": "1"})
        witness = Witness(private_inputs={"b": "2"})

        with patch("shutil.which", return_value=None):
            with pytest.raises(BackendNotAvailableError) as exc_info:
                backend.generate(statement, witness)
            assert "snarkjs binary" in str(exc_info.value)

    def test_generate_happy_path_mocked(self, tmp_path: Path) -> None:
        """Test that generate() returns a Proof when snarkjs succeeds."""
        # Set up directory structure
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        # Create required artifacts
        zkey_path = build_dir / "test_final.zkey"
        zkey_path.touch()

        wasm_dir = build_dir / "test_js"
        wasm_dir.mkdir()
        wasm_file = wasm_dir / "test.wasm"
        wasm_file.touch()
        generate_witness_js = wasm_dir / "generate_witness.js"
        generate_witness_js.touch()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir)

        statement = Statement(circuit="test", public_inputs={"root": "123"})
        witness = Witness(private_inputs={"path": "456"})

        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = ""
        mock_completed.stderr = ""

        def mock_run(cmd: list[str], *, cwd: Path | None = None, timeout: int, check: bool = True):
            """Mock _run_subprocess to simulate snarkjs behavior."""
            # Check if this is the proof generation call (snarkjs groth16 prove)
            if "prove" in cmd:
                # Write mock proof and public files
                proof_path = Path(cmd[-2])
                public_path = Path(cmd[-1])
                proof_path.write_text('{"pi_a": [], "pi_b": [], "pi_c": []}')
                public_path.write_text('["123"]')
            return mock_completed

        with (
            patch("shutil.which", return_value="/usr/bin/node"),
            patch("protocol.groth16_backend._run_subprocess", side_effect=mock_run),
        ):
            proof = backend.generate(statement, witness)

        assert isinstance(proof, Proof)
        assert proof.proof_system == ProofSystemType.GROTH16
        assert proof.circuit == "test"
        assert proof.public_signals == ["123"]

    def test_generate_raises_when_witness_generation_fails(self, tmp_path: Path) -> None:
        """Test that generate() raises ProofGenerationError when witness generation fails."""
        # Set up directory structure
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()

        # Create required artifacts
        zkey_path = build_dir / "test_final.zkey"
        zkey_path.touch()

        wasm_dir = build_dir / "test_js"
        wasm_dir.mkdir()
        wasm_file = wasm_dir / "test.wasm"
        wasm_file.touch()
        generate_witness_js = wasm_dir / "generate_witness.js"
        generate_witness_js.touch()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir)

        statement = Statement(circuit="test", public_inputs={"root": "123"})
        witness = Witness(private_inputs={"path": "456"})

        def mock_run_fail(
            cmd: list[str], *, cwd: Path | None = None, timeout: int, check: bool = True
        ):
            """Mock _run_subprocess to simulate witness generation failure."""
            raise subprocess.CalledProcessError(1, cmd, stderr="Witness generation error")

        with (
            patch("shutil.which", return_value="/usr/bin/node"),
            patch("protocol.groth16_backend._run_subprocess", side_effect=mock_run_fail),
        ):
            with pytest.raises(ProofGenerationError) as exc_info:
                backend.generate(statement, witness)
            assert "Witness generation failed" in str(exc_info.value)


class TestVerify:
    """Tests for the verify() method."""

    def test_verify_raises_when_snarkjs_not_available(self) -> None:
        """Test that verify() raises BackendNotAvailableError when snarkjs is not found."""
        backend = Groth16Backend()
        statement = Statement(circuit="test", public_inputs={"a": "1"})
        proof = Proof(
            proof_data={"pi_a": [], "pi_b": [], "pi_c": []},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
            public_signals=["1"],
        )

        with patch("shutil.which", return_value=None):
            with pytest.raises(BackendNotAvailableError) as exc_info:
                backend.verify(statement, proof)
            assert "snarkjs binary" in str(exc_info.value)

    def test_verify_returns_true_on_success(self, tmp_path: Path) -> None:
        """Test that verify() returns True when snarkjs verification succeeds."""
        # Set up directory structure
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        keys_dir = tmp_path / "keys"
        vkey_dir = keys_dir / "verification_keys"
        vkey_dir.mkdir(parents=True)

        # Create verification key
        vkey_path = vkey_dir / "test_vkey.json"
        vkey_path.write_text('{"protocol": "groth16"}')

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir, keys_dir=keys_dir)

        statement = Statement(circuit="test", public_inputs={"root": "123"})
        proof = Proof(
            proof_data={"pi_a": [], "pi_b": [], "pi_c": []},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
            public_signals=["123"],
        )

        mock_completed = MagicMock()
        mock_completed.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/npx"),
            patch("protocol.groth16_backend._run_subprocess", return_value=mock_completed),
        ):
            result = backend.verify(statement, proof)

        assert result is True

    def test_verify_returns_false_on_failure(self, tmp_path: Path) -> None:
        """Test that verify() returns False when snarkjs verification fails."""
        # Set up directory structure
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        keys_dir = tmp_path / "keys"
        vkey_dir = keys_dir / "verification_keys"
        vkey_dir.mkdir(parents=True)

        # Create verification key
        vkey_path = vkey_dir / "test_vkey.json"
        vkey_path.write_text('{"protocol": "groth16"}')

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir, keys_dir=keys_dir)

        statement = Statement(circuit="test", public_inputs={"root": "123"})
        proof = Proof(
            proof_data={"pi_a": [], "pi_b": [], "pi_c": []},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
            public_signals=["123"],
        )

        def mock_run_fail(
            cmd: list[str], *, cwd: Path | None = None, timeout: int, check: bool = True
        ):
            """Mock _run_subprocess to simulate verification failure."""
            raise subprocess.CalledProcessError(1, cmd, stderr="Verification failed")

        with (
            patch("shutil.which", return_value="/usr/bin/npx"),
            patch("protocol.groth16_backend._run_subprocess", side_effect=mock_run_fail),
        ):
            result = backend.verify(statement, proof)

        assert result is False

    def test_verify_raises_for_missing_verification_key(self, tmp_path: Path) -> None:
        """Test that verify() raises ProofVerificationError when verification key is not found."""
        # Set up directory structure without verification key
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir, keys_dir=keys_dir)

        statement = Statement(circuit="test", public_inputs={"root": "123"})
        proof = Proof(
            proof_data={"pi_a": [], "pi_b": [], "pi_c": []},
            proof_system=ProofSystemType.GROTH16,
            circuit="test",
            public_signals=["123"],
        )

        with patch("shutil.which", return_value="/usr/bin/npx"):
            with pytest.raises(ProofVerificationError) as exc_info:
                backend.verify(statement, proof)
            assert "Verification key not found" in str(exc_info.value)

    def test_verify_raises_for_wrong_proof_system(self) -> None:
        """Test that verify() raises ProofVerificationError for non-Groth16 proofs."""
        backend = Groth16Backend()
        statement = Statement(circuit="test", public_inputs={"a": "1"})
        proof = Proof(
            proof_data={},
            proof_system=ProofSystemType.HALO2,
            circuit="test",
            public_signals=["1"],
        )

        with patch("shutil.which", return_value="/usr/bin/npx"):
            with pytest.raises(ProofVerificationError) as exc_info:
                backend.verify(statement, proof)
            assert "Expected Groth16 proof" in str(exc_info.value)


class TestFindVerificationKey:
    """Tests for the _find_verification_key() method."""

    def test_find_verification_key_in_keys_dir(self, tmp_path: Path) -> None:
        """Test that _find_verification_key() finds key in keys/verification_keys directory."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        keys_dir = tmp_path / "keys"
        vkey_dir = keys_dir / "verification_keys"
        vkey_dir.mkdir(parents=True)

        vkey_path = vkey_dir / "test_vkey.json"
        vkey_path.write_text("{}")

        backend = Groth16Backend(circuits_dir=circuits_dir, keys_dir=keys_dir)
        result = backend._find_verification_key("test")

        assert result == vkey_path

    def test_find_verification_key_in_build_dir(self, tmp_path: Path) -> None:
        """Test that _find_verification_key() finds key in build directory as fallback."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        vkey_path = build_dir / "test_vkey.json"
        vkey_path.write_text("{}")

        backend = Groth16Backend(circuits_dir=circuits_dir, build_dir=build_dir, keys_dir=keys_dir)
        result = backend._find_verification_key("test")

        assert result == vkey_path

    def test_find_verification_key_in_circuits_keys_dir(self, tmp_path: Path) -> None:
        """Test that _find_verification_key() finds key in circuits/keys/verification_keys."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        vkey_dir = circuits_dir / "keys" / "verification_keys"
        vkey_dir.mkdir(parents=True)
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        vkey_path = vkey_dir / "test_vkey.json"
        vkey_path.write_text("{}")

        backend = Groth16Backend(circuits_dir=circuits_dir, keys_dir=keys_dir)
        result = backend._find_verification_key("test")

        assert result == vkey_path

    def test_find_verification_key_returns_none_when_not_found(self, tmp_path: Path) -> None:
        """Test that _find_verification_key() returns None when key is not found anywhere."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, keys_dir=keys_dir)
        result = backend._find_verification_key("nonexistent")

        assert result is None


class TestRunSnarkjs:
    """Tests for the _run_snarkjs() method."""

    def test_run_snarkjs_with_npx(self, tmp_path: Path) -> None:
        """Test that _run_snarkjs() uses npx snarkjs prefix when snarkjs_bin is npx."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, snarkjs_bin="npx")

        mock_completed = MagicMock()
        mock_completed.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/npx"),
            patch(
                "protocol.groth16_backend._run_subprocess", return_value=mock_completed
            ) as mock_run,
        ):
            backend._run_snarkjs(["groth16", "verify", "vkey.json", "public.json", "proof.json"])

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "/usr/bin/npx"
        assert cmd[1] == "snarkjs"
        assert "groth16" in cmd
        # Default timeout for _run_snarkjs is _PROOF_TIMEOUT_SECS
        from protocol.groth16_backend import _PROOF_TIMEOUT_SECS

        assert call_args.kwargs["timeout"] == _PROOF_TIMEOUT_SECS

    def test_run_snarkjs_with_direct_binary(self, tmp_path: Path) -> None:
        """Test that _run_snarkjs() uses direct binary when snarkjs_bin is not npx."""
        circuits_dir = tmp_path / "circuits"
        circuits_dir.mkdir()

        backend = Groth16Backend(circuits_dir=circuits_dir, snarkjs_bin="snarkjs")

        mock_completed = MagicMock()
        mock_completed.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/local/bin/snarkjs"),
            patch(
                "protocol.groth16_backend._run_subprocess", return_value=mock_completed
            ) as mock_run,
        ):
            backend._run_snarkjs(["groth16", "verify", "vkey.json", "public.json", "proof.json"])

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "/usr/local/bin/snarkjs"
        assert cmd[1] == "groth16"  # No "snarkjs" prefix
        from protocol.groth16_backend import _PROOF_TIMEOUT_SECS

        assert call_args.kwargs["timeout"] == _PROOF_TIMEOUT_SECS

    def test_run_snarkjs_timeout_raises_timeout_expired(self) -> None:
        """_run_snarkjs raises TimeoutExpired and kills process group on timeout."""
        backend = Groth16Backend()
        with patch("shutil.which", return_value="/bin/sleep"):
            backend.snarkjs_bin = "sleep"
            with pytest.raises(subprocess.TimeoutExpired):
                backend._run_snarkjs(["60"], timeout=1)


class TestProofSystemType:
    """Tests for the proof_system_type property."""

    def test_proof_system_type_returns_groth16(self) -> None:
        """Test that proof_system_type property returns GROTH16."""
        backend = Groth16Backend()
        assert backend.proof_system_type == ProofSystemType.GROTH16
