"""
Groth16 proof bridge for Olympus.

This module provides a minimal Python interface around snarkjs while keeping
Poseidon hashing confined to circuit scope and BLAKE3 hashing in Python.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
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

    Notes:
      - For local/dev, prefer snarkjs_bin="npx" so it uses the repo's node_modules.
      - For global installs, snarkjs_bin="snarkjs" is fine.
    """

    def __init__(self, circuits_dir: Path, snarkjs_bin: str = "npx") -> None:
        self.circuits_dir = circuits_dir
        self.snarkjs_bin = snarkjs_bin

    def _check_snarkjs(self) -> None:
        """Ensure snarkjs launcher is available (snarkjs or npx)."""
        if shutil.which(self.snarkjs_bin) is None:
            raise FileNotFoundError(
                f"snarkjs launcher '{self.snarkjs_bin}' not found in PATH. "
                "Install Node.js/npm (for npx) or install snarkjs globally, "
                "or provide an explicit path."
            )

    def _build_cmd(self, args: list[str]) -> list[str]:
        """
        Build the subprocess command.

        If snarkjs_bin == "npx", we run: npx snarkjs <args...>
        Else we run: <snarkjs_bin> <args...>
        """
        if self.snarkjs_bin == "npx":
            return ["npx", "snarkjs", *args]
        return [self.snarkjs_bin, *args]

    def _run(self, args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        """Execute a snarkjs command and return the completed process."""
        self._check_snarkjs()
        cmd = self._build_cmd(args)
        return subprocess.run(  # nosec B603
            cmd,
            cwd=cwd or self.circuits_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def prove(
        self,
        *,
        circuit: str,
        witness_path: Path,
        zkey_path: Path,
        proof_path: Path,
        public_path: Path,
    ) -> ZKProof:
        """
        Generate a Groth16 proof for any circuit.

        The witness must already be generated (e.g., via circom WASM witness generator).
        """
        self._check_snarkjs()

        if not witness_path.exists():
            raise FileNotFoundError(f"Witness file not found: {witness_path}")
        if not zkey_path.exists():
            raise FileNotFoundError(f"ZKey file not found: {zkey_path}")

        # Ensure output directories exist
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)

        self._run(
            ["groth16", "prove", str(zkey_path), str(witness_path), str(proof_path), str(public_path)],
            cwd=self.circuits_dir,
        )

        with proof_path.open("r", encoding="utf-8") as f:
            proof = json.load(f)
        with public_path.open("r", encoding="utf-8") as f:
            public_signals = json.load(f)

        return ZKProof(proof=proof, public_signals=public_signals, circuit=circuit)

    # Backwards-compatible wrapper (legacy callers)
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

        NOTE: leaf/root/path_* are not used by snarkjs prove once witness exists;
        they remain here for API compatibility with earlier code.
        """
        witness = witness_path or (self.circuits_dir / "build" / "document_existence.wtns")
        zkey = zkey_path or (self.circuits_dir / "build" / "document_existence_final.zkey")
        proof_file = proof_path or (self.circuits_dir / "build" / "document_existence_proof.json")
        public_file = public_path or (self.circuits_dir / "build" / "document_existence_public.json")

        return self.prove(
            circuit="document_existence",
            witness_path=witness,
            zkey_path=zkey,
            proof_path=proof_file,
            public_path=public_file,
        )

    def verify(
        self,
        proof: ZKProof,
        verification_key_path: Path | None = None,
    ) -> bool:
        """Verify a Groth16 proof with snarkjs."""
        self._check_snarkjs()

        if verification_key_path is not None:
            vkey = verification_key_path
        else:
            vkey_filename = f"{proof.circuit}_vkey.json"
            candidate = self.circuits_dir / "keys" / "verification_keys" / vkey_filename
            fallback = self.circuits_dir.parent / "keys" / "verification_keys" / vkey_filename
            vkey = candidate if candidate.exists() else fallback

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
