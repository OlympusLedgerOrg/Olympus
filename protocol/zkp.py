"""
Groth16 proof bridge for Olympus.

This module provides a minimal Python interface around snarkjs while keeping
Poseidon hashing confined to circuit scope and BLAKE3 hashing in Python.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ZKProof:
    """Container for zkSNARK proof artifacts."""

    proof: dict[str, Any]
    public_signals: list[Any]
    circuit: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize proof to a dictionary."""
        return {
            "proof": self.proof,
            "public_signals": self.public_signals,
            "circuit": self.circuit,
        }


class Groth16Prover:
    """
    Thin wrapper around snarkjs groth16 CLI.

    This keeps snarkjs as a subprocess dependency and documents the hashing
    boundary: Poseidon is used inside circuits; BLAKE3 remains at the Python
    layer for ledger hashing.
    """

    def __init__(self, circuits_dir: Path, snarkjs_bin: str = "snarkjs") -> None:
        self.circuits_dir = circuits_dir
        self.snarkjs_bin = snarkjs_bin

    def _check_snarkjs(self) -> None:
        """Ensure snarkjs binary is available."""
        if shutil.which(self.snarkjs_bin) is None:
            raise FileNotFoundError(
                f"snarkjs binary '{self.snarkjs_bin}' not found in PATH. "
                "Install snarkjs or provide an explicit path."
            )

    def _run(self, args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        """Execute a snarkjs command and return the completed process."""
        self._check_snarkjs()
        return subprocess.run(
            [self.snarkjs_bin, *args],
            cwd=cwd or self.circuits_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def prove_existence(
        self,
        leaf: str,
        root: str,
        path_elements: list[str],
        path_indices: list[int],
        *,
        witness_path: Path | None = None,
        zkey_path: Path | None = None,
        proof_path: Path | None = None,
        public_path: Path | None = None,
    ) -> ZKProof:
        """
        Generate a Groth16 proof for document existence.

        Expects the witness to be generated already (e.g., via circom/wasm).
        """
        witness = witness_path or self.circuits_dir / "build" / "document_existence.wtns"
        zkey = zkey_path or self.circuits_dir / "build" / "document_existence_final.zkey"
        proof_file = proof_path or self.circuits_dir / "build" / "document_existence_proof.json"
        public_file = public_path or self.circuits_dir / "build" / "document_existence_public.json"

        if not witness.exists():
            raise FileNotFoundError(f"Witness file not found: {witness}")
        if not zkey.exists():
            raise FileNotFoundError(f"ZKey file not found: {zkey}")

        self._run(
            ["groth16", "prove", str(zkey), str(witness), str(proof_file), str(public_file)],
            cwd=self.circuits_dir,
        )

        with proof_file.open("r", encoding="utf-8") as f:
            proof = json.load(f)
        with public_file.open("r", encoding="utf-8") as f:
            public_signals = json.load(f)

        return ZKProof(proof=proof, public_signals=public_signals, circuit="document_existence")

    def verify(
        self,
        proof: ZKProof,
        verification_key_path: Path | None = None,
    ) -> bool:
        """Verify a Groth16 proof with snarkjs."""
        vkey = verification_key_path or self.circuits_dir / "keys" / "verification_keys" / "existence_vkey.json"
        if not vkey.exists():
            raise FileNotFoundError(f"Verification key not found: {vkey}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            proof_path = tmp_path / "proof.json"
            public_path = tmp_path / "public.json"

            with proof_path.open("w", encoding="utf-8") as f:
                json.dump(proof.proof, f)
            with public_path.open("w", encoding="utf-8") as f:
                json.dump(proof.public_signals, f)

            try:
                self._run(
                    ["groth16", "verify", str(vkey), str(public_path), str(proof_path)],
                    cwd=self.circuits_dir,
                )
            except subprocess.CalledProcessError:
                return False

        return True
