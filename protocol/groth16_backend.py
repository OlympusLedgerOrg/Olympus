"""
Groth16 Proof Backend Implementation

This module implements the ProofBackendProtocol for Groth16 proofs using snarkjs.
It provides the primary proof system for Olympus, optimized for throughput.

Groth16 characteristics:
- Requires trusted setup (mitigated via multi-party ceremony)
- Small proof size (~200 bytes)
- Fast verification (milliseconds)
- High throughput suitable for production workloads

This backend is used when maximum performance is required. For high-assurance
contexts where trusted setup elimination is critical, use the Halo2 backend.

Usage::

    from protocol.groth16_backend import Groth16Backend
    from protocol.proof_interface import Statement, Witness

    backend = Groth16Backend(circuits_dir=Path("proofs/circuits"))

    statement = Statement(
        circuit="document_existence",
        public_inputs={"root": "123", "leaf": "456"},
    )
    witness = Witness(private_inputs={"pathElements": [...], "pathIndices": [...]})

    proof = backend.generate(statement, witness)
    is_valid = backend.verify(statement, proof)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

from .proof_interface import (
    BackendNotAvailableError,
    Proof,
    ProofBackendProtocol,
    ProofGenerationError,
    ProofSystemType,
    ProofVerificationError,
    Statement,
    Witness,
)


class Groth16Backend(ProofBackendProtocol):
    """
    Groth16 proof backend using snarkjs CLI.

    This class implements the ProofBackendProtocol for Groth16 proofs.
    It wraps the snarkjs CLI to provide proof generation and verification.

    Attributes:
        circuits_dir: Path to the circuits directory
        build_dir: Path to the build directory for witnesses and proofs
        keys_dir: Path to the keys directory (zkeys, verification keys)
        snarkjs_bin: snarkjs launcher command (default: "npx")
    """

    def __init__(
        self,
        circuits_dir: Path | None = None,
        *,
        build_dir: Path | None = None,
        keys_dir: Path | None = None,
        snarkjs_bin: str = "npx",
    ) -> None:
        """
        Initialize Groth16 backend.

        Args:
            circuits_dir: Path to circuits directory. If None, uses default.
            build_dir: Path to build directory. If None, uses circuits_dir/build.
            keys_dir: Path to keys directory. If None, uses circuits_dir/../keys.
            snarkjs_bin: snarkjs launcher command (default: "npx")
        """
        default_circuits_dir = Path(__file__).parent.parent / "proofs" / "circuits"
        self.circuits_dir = circuits_dir or default_circuits_dir
        self.build_dir = build_dir or (self.circuits_dir.parent / "build")
        self.keys_dir = keys_dir or (self.circuits_dir.parent / "keys")
        self.snarkjs_bin = snarkjs_bin

    @staticmethod
    def _resolve_node_bin() -> str:
        """Return absolute path to the Node.js binary or raise."""
        node_path = shutil.which("node")
        if node_path is None:
            raise BackendNotAvailableError(
                "Node.js binary 'node' not found in PATH. "
                "Install Node >= 18 to run circom witness generators."
            )
        return node_path

    def _resolve_snarkjs_bin(self) -> str:
        """Return absolute path to the snarkjs launcher (snarkjs or npx)."""
        snarkjs_path = shutil.which(self.snarkjs_bin)
        if snarkjs_path is None:
            raise BackendNotAvailableError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
                "Install Node.js/npm (for npx) or install snarkjs globally."
            )
        return snarkjs_path

    def _validate_artifact_path(self, path: Path, *, kind: str) -> Path:
        """Resolve and validate circuit artifacts to avoid traversal."""
        resolved = path.resolve()
        base_dirs = {self.build_dir.resolve(), self.circuits_dir.resolve()}
        if not any(base in resolved.parents or resolved == base for base in base_dirs):
            raise ProofGenerationError(
                f"{kind} path {resolved} is outside expected circuits directories"
            )
        if not resolved.exists():
            raise ProofGenerationError(f"{kind} not found: {resolved}")
        return resolved

    @staticmethod
    def _validate_circuit_name(circuit: str) -> None:
        """Restrict circuit identifiers to simple file-stem tokens."""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", circuit):
            raise ValueError(f"Invalid circuit identifier: {circuit!r}")

    @property
    def proof_system_type(self) -> ProofSystemType:
        """Return Groth16 proof system type."""
        return ProofSystemType.GROTH16

    def is_available(self) -> bool:
        """
        Check if snarkjs is available.

        Returns:
            bool: True if snarkjs binary is found in PATH
        """
        return shutil.which(self.snarkjs_bin) is not None

    def generate(self, statement: Statement, witness: Witness) -> Proof:
        """
        Generate a Groth16 proof.

        This method:
        1. Writes witness inputs to a temp file
        2. Generates witness using circom WASM
        3. Generates Groth16 proof using snarkjs
        4. Returns the proof artifact

        Args:
            statement: The public statement (circuit + public inputs)
            witness: The private witness (private inputs + auxiliary data)

        Returns:
            Proof: A Groth16 proof that can be verified

        Raises:
            BackendNotAvailableError: If snarkjs is not available
            ProofGenerationError: If proof generation fails
        """
        if not self.is_available():
            raise BackendNotAvailableError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
                "Install Node.js/npm (for npx) or install snarkjs globally."
            )

        circuit = statement.circuit
        self._validate_circuit_name(circuit)
        node_bin = self._resolve_node_bin()

        # Determine paths
        zkey_path = self._validate_artifact_path(
            self.build_dir / f"{circuit}_final.zkey", kind="ZKey file"
        )

        wasm_dir = (self.build_dir / f"{circuit}_js").resolve()
        wasm_file = self._validate_artifact_path(wasm_dir / f"{circuit}.wasm", kind="WASM circuit")
        generate_witness_js = self._validate_artifact_path(
            wasm_dir / "generate_witness.js", kind="Witness generator"
        )

        # Merge public inputs and private inputs for witness generation
        if not isinstance(statement.public_inputs, dict) or not isinstance(
            witness.private_inputs, dict
        ):
            raise ProofGenerationError("public_inputs and private_inputs must be dictionaries")
        all_inputs: dict[str, Any] = {}
        all_inputs.update(statement.public_inputs)
        all_inputs.update(witness.private_inputs)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Write input JSON
            input_path = tmp_path / "input.json"
            with input_path.open("w", encoding="utf-8") as f:
                json.dump(all_inputs, f, allow_nan=False)

            # Generate witness
            witness_path = tmp_path / "witness.wtns"
            try:
                subprocess.run(  # nosec B603
                    [
                        node_bin,
                        str(generate_witness_js),
                        str(wasm_file),
                        str(input_path),
                        str(witness_path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                raise ProofGenerationError(f"Witness generation failed: {e.stderr}") from e

            # Generate proof
            proof_path = tmp_path / "proof.json"
            public_path = tmp_path / "public.json"

            try:
                self._run_snarkjs(
                    [
                        "groth16",
                        "prove",
                        str(zkey_path),
                        str(witness_path),
                        str(proof_path),
                        str(public_path),
                    ]
                )
            except subprocess.CalledProcessError as e:
                raise ProofGenerationError(f"Proof generation failed: {e.stderr}") from e

            # Read proof and public signals
            with proof_path.open("r", encoding="utf-8") as f:
                proof_data = json.load(f)
            with public_path.open("r", encoding="utf-8") as f:
                public_signals = json.load(f)

        return Proof(
            proof_data=proof_data,
            proof_system=ProofSystemType.GROTH16,
            circuit=circuit,
            public_signals=[str(s) for s in public_signals],
        )

    def verify(self, statement: Statement, proof: Proof) -> bool:
        """
        Verify a Groth16 proof.

        Args:
            statement: The public statement that was proven
            proof: The Groth16 proof to verify

        Returns:
            bool: True if the proof is valid, False otherwise

        Raises:
            BackendNotAvailableError: If snarkjs is not available
            ProofVerificationError: If verification fails unexpectedly
        """
        if not self.is_available():
            raise BackendNotAvailableError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
                "Install Node.js/npm (for npx) or install snarkjs globally."
            )

        if proof.proof_system != ProofSystemType.GROTH16:
            raise ProofVerificationError(f"Expected Groth16 proof, got {proof.proof_system.value}")

        circuit = proof.circuit
        self._validate_circuit_name(circuit)

        # Find verification key
        vkey_path = self._find_verification_key(circuit)
        if vkey_path is None:
            raise ProofVerificationError(f"Verification key not found for circuit: {circuit}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Write proof and public signals
            proof_path = tmp_path / "proof.json"
            public_path = tmp_path / "public.json"

            with proof_path.open("w", encoding="utf-8") as f:
                json.dump(proof.proof_data, f)
            with public_path.open("w", encoding="utf-8") as f:
                json.dump(proof.public_signals, f)

            try:
                self._run_snarkjs(
                    ["groth16", "verify", str(vkey_path), str(public_path), str(proof_path)]
                )
                return True
            except subprocess.CalledProcessError:
                return False

    def _run_snarkjs(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """
        Execute a snarkjs command.

        Args:
            args: Arguments to pass to snarkjs

        Returns:
            CompletedProcess with stdout/stderr

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        launcher = self._resolve_snarkjs_bin()
        if self.snarkjs_bin == "npx":
            cmd = [launcher, "snarkjs", *args]
        else:
            cmd = [launcher, *args]

        return subprocess.run(  # nosec B603
            cmd,
            cwd=self.circuits_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def _find_verification_key(self, circuit: str) -> Path | None:
        """
        Find the verification key for a circuit.

        Searches in multiple locations for the verification key.

        Args:
            circuit: Circuit identifier

        Returns:
            Path to verification key, or None if not found
        """
        vkey_filename = f"{circuit}_vkey.json"

        # Check keys directory first
        vkey_path = self.keys_dir / "verification_keys" / vkey_filename
        if vkey_path.exists():
            return vkey_path

        # Check build directory
        vkey_path = self.build_dir / vkey_filename
        if vkey_path.exists():
            return vkey_path

        # Check circuits directory
        vkey_path = self.circuits_dir / "keys" / "verification_keys" / vkey_filename
        if vkey_path.exists():
            return vkey_path

        return None
