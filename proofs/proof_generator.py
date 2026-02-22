"""
High-level Python integration for ZK proof generation and verification.

This module provides a unified ``ProofGenerator`` interface that bridges
the gap between Olympus's Python protocol layer and the snarkjs/circom
ZK circuit infrastructure.

Usage::

    from proofs.proof_generator import ProofGenerator

    generator = ProofGenerator("document_existence")
    witness = generator.generate_witness(
        root="123",
        leafIndex="0",
        leaf="42",
        pathElements=["0"] * 20,
        pathIndices=[0] * 20,
    )
    proof = generator.prove(witness)
    verified = generator.verify(proof, public_inputs=proof.public_signals)

Hash boundary note:
    Circuits use **Poseidon** for in-circuit hashing while the Python/ledger
    layer may use **BLAKE3**. Witness generation must supply Poseidon-compatible
    field elements. See ``proofs/README.md`` for details.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from protocol.zkp import Groth16Prover, ZKProof


SUPPORTED_CIRCUITS = frozenset(
    {
        "document_existence",
        "non_existence",
        "redaction_validity",
    }
)

# Default paths relative to this file
_PROOFS_DIR = Path(__file__).resolve().parent
_CIRCUITS_DIR = _PROOFS_DIR / "circuits"
_KEYS_DIR = _PROOFS_DIR / "keys"
_BUILD_DIR = _PROOFS_DIR / "build"


@dataclass
class Witness:
    """Container for a circuit witness (input signals)."""

    circuit: str
    inputs: dict[str, Any]
    run_id: str
    input_path: Path | None = field(default=None, repr=False)
    witness_path: Path | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "circuit": self.circuit,
            "inputs": self.inputs,
            "run_id": self.run_id,
        }


class ProofGenerator:
    """
    High-level interface for generating and verifying ZK proofs.

    Wraps :class:`protocol.zkp.Groth16Prover` with ergonomic helpers for
    witness construction, proof generation, and verification.
    """

    def __init__(
        self,
        circuit: str,
        *,
        circuits_dir: Path | None = None,
        build_dir: Path | None = None,
        keys_dir: Path | None = None,
        snarkjs_bin: str = "npx",
    ) -> None:
        if circuit not in SUPPORTED_CIRCUITS:
            raise ValueError(
                f"Unsupported circuit '{circuit}'. Supported: {sorted(SUPPORTED_CIRCUITS)}"
            )

        self.circuit = circuit
        self.circuits_dir = circuits_dir or _CIRCUITS_DIR
        self.build_dir = build_dir or _BUILD_DIR
        self.keys_dir = keys_dir or _KEYS_DIR
        self.snarkjs_bin = snarkjs_bin

        # NOTE: Groth16Prover expects circuits_dir to be the proofs/circuits directory
        self._prover = Groth16Prover(self.circuits_dir, snarkjs_bin=snarkjs_bin)

    @property
    def snarkjs_available(self) -> bool:
        """Return True if the configured snarkjs launcher is on PATH."""
        return shutil.which(self.snarkjs_bin) is not None

    def generate_witness(self, **inputs: Any) -> Witness:
        """
        Build a witness for the configured circuit.
        Writes a unique input JSON and attempts to generate a unique witness .wtns via WASM.
        """
        self._validate_inputs(inputs)

        run_id = uuid.uuid4().hex
        witness = Witness(circuit=self.circuit, inputs=inputs, run_id=run_id)

        self.build_dir.mkdir(parents=True, exist_ok=True)

        # Write input JSON (unique)
        input_path = self.build_dir / f"{self.circuit}_input_{run_id}.json"
        with input_path.open("w", encoding="utf-8") as fh:
            json.dump(inputs, fh)
        witness.input_path = input_path

        # Attempt WASM witness generation
        wasm_dir = self.build_dir / f"{self.circuit}_js"
        wasm_file = wasm_dir / f"{self.circuit}.wasm"
        witness_out = self.build_dir / f"{self.circuit}_{run_id}.wtns"

        if not wasm_file.exists():
            # Circuit not compiled to WASM yet (setup_circuits.sh --compile-only or missing build)
            return witness

        generate_witness_js = wasm_dir / "generate_witness.js"
        if not generate_witness_js.exists():
            return witness

        # We can generate a witness without snarkjs; only node is required.
        subprocess.run(
            ["node", str(generate_witness_js), str(wasm_file), str(input_path), str(witness_out)],
            check=True,
            capture_output=True,
            text=True,
        )
        witness.witness_path = witness_out
        return witness

    def prove(self, witness: Witness) -> ZKProof:
        """
        Generate a Groth16 proof from a witness produced by generate_witness().
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs launcher '{self.snarkjs_bin}' not found. "
                "Install Node.js/npm (for npx) or install snarkjs globally."
            )

        if witness.witness_path is None or not witness.witness_path.exists():
            raise FileNotFoundError(
                "Witness file missing. Ensure circuits are compiled (setup_circuits.sh) "
                "and witness generation succeeded."
            )

        zkey_path = self.build_dir / f"{self.circuit}_final.zkey"
        if not zkey_path.exists():
            raise FileNotFoundError(
                f"ZKey file not found: {zkey_path}. Run 'bash setup_circuits.sh' first."
            )

        # Unique outputs per run to avoid collisions
        proof_path = self.build_dir / f"{self.circuit}_proof_{witness.run_id}.json"
        public_path = self.build_dir / f"{self.circuit}_public_{witness.run_id}.json"

        return self._prover.prove(
            circuit=self.circuit,
            witness_path=witness.witness_path,
            zkey_path=zkey_path,
            proof_path=proof_path,
            public_path=public_path,
        )

    def verify(
        self,
        proof: ZKProof,
        public_inputs: list[Any] | None = None,
        verification_key_path: Path | None = None,
    ) -> bool:
        """
        Verify a Groth16 proof.

        If public_inputs is provided, it overrides proof.public_signals for this call.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs launcher '{self.snarkjs_bin}' not found. "
                "Install Node.js/npm (for npx) or install snarkjs globally."
            )

        verify_proof = proof
        if public_inputs is not None:
            verify_proof = ZKProof(
                proof=proof.proof,
                public_signals=public_inputs,
                circuit=proof.circuit,
            )

        vkey = verification_key_path
        if vkey is None:
            vkey = self.keys_dir / "verification_keys" / f"{self.circuit}_vkey.json"

        return self._prover.verify(verify_proof, verification_key_path=vkey)

    def export_proof(self, proof: ZKProof, path: Path) -> None:
        """Write a proof and its public signals to a JSON file."""
        with path.open("w", encoding="utf-8") as fh:
            json.dump(proof.to_dict(), fh, indent=2)

    @staticmethod
    def load_proof(path: Path) -> ZKProof:
        """Load a proof from a JSON file previously written by export_proof()."""
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return ZKProof(
            proof=data["proof"],
            public_signals=data["public_signals"],
            circuit=data["circuit"],
        )

    _REQUIRED_INPUTS: dict[str, list[str]] = {
        "document_existence": ["root", "leaf", "leafIndex", "pathElements", "pathIndices"],
        "non_existence": ["root", "emptyLeaf", "pathElements", "pathIndices"],
        "redaction_validity": [
            "originalRoot",
            "redactedCommitment",
            "revealedCount",
            "originalLeaves",
            "revealMask",
            "pathElements",
            "pathIndices",
        ],
    }

    def _validate_inputs(self, inputs: dict[str, Any]) -> None:
        required = self._REQUIRED_INPUTS.get(self.circuit, [])
        missing = [k for k in required if k not in inputs]
        if missing:
            raise ValueError(f"Missing required inputs for circuit '{self.circuit}': {missing}")
