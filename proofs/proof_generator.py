"""
High-level Python integration for ZK proof generation and verification.

This module provides a unified ``ProofGenerator`` interface that bridges
the gap between Olympus's Python protocol layer and the snarkjs/circom
ZK circuit infrastructure.

Usage::

    from proofs.proof_generator import ProofGenerator

    generator = ProofGenerator("document_existence")
    witness = generator.generate_witness(
        merkle_root="123",
        leaf="42",
        path_elements=["0"] * 20,
        path_indices=[0] * 20,
    )
    proof = generator.prove(witness)
    verified = generator.verify(proof, public_inputs=proof.public_signals)

Hash boundary note:
    Circuits use **Poseidon** for in-circuit hashing while the Python/ledger
    layer uses **BLAKE3**.  Witness generation must supply Poseidon-compatible
    field elements.  See ``proofs/README.md`` for details.
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


# ---------------------------------------------------------------------------
# Supported circuits
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Witness container
# ---------------------------------------------------------------------------
@dataclass
class Witness:
    """Container for a circuit witness (input signals)."""

    circuit: str
    inputs: dict[str, Any]
    witness_path: Path | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize witness metadata to a dictionary."""
        return {
            "circuit": self.circuit,
            "inputs": self.inputs,
        }


# ---------------------------------------------------------------------------
# ProofGenerator
# ---------------------------------------------------------------------------
class ProofGenerator:
    """
    High-level interface for generating and verifying ZK proofs.

    Wraps :class:`protocol.zkp.Groth16Prover` with ergonomic helpers for
    witness construction, proof generation, and verification.

    Args:
        circuit: Name of the circuit (must be in ``SUPPORTED_CIRCUITS``).
        circuits_dir: Override the default circuits directory.
        build_dir: Override the default build artefacts directory.
        keys_dir: Override the default keys directory.
        snarkjs_bin: Path to or name of the ``snarkjs`` binary.
    """

    def __init__(
        self,
        circuit: str,
        *,
        circuits_dir: Path | None = None,
        build_dir: Path | None = None,
        keys_dir: Path | None = None,
        snarkjs_bin: str = "snarkjs",
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

        self._prover = Groth16Prover(self.circuits_dir, snarkjs_bin=snarkjs_bin)

    # ------------------------------------------------------------------
    # snarkjs availability check
    # ------------------------------------------------------------------
    @property
    def snarkjs_available(self) -> bool:
        """Return *True* if the configured snarkjs binary is on PATH."""
        return shutil.which(self.snarkjs_bin) is not None

    # ------------------------------------------------------------------
    # Witness generation
    # ------------------------------------------------------------------
    def generate_witness(self, **inputs: Any) -> Witness:
        """
        Build a witness for the configured circuit.
        """
        self._validate_inputs(inputs)
        witness = Witness(circuit=self.circuit, inputs=inputs)

        # FIX: Generate a unique run ID to prevent file collisions
        run_id = uuid.uuid4().hex

        # Write the JSON input file with a unique name
        self.build_dir.mkdir(parents=True, exist_ok=True)
        input_path = self.build_dir / f"{self.circuit}_input_{run_id}.json"

        with input_path.open("w", encoding="utf-8") as fh:
            json.dump(inputs, fh)

        # Attempt WASM witness generation if tooling is available
        wasm_dir = self.build_dir / f"{self.circuit}_js"
        wasm_file = wasm_dir / f"{self.circuit}.wasm"

        # FIX: Make the output witness file unique as well
        witness_out = self.build_dir / f"{self.circuit}_{run_id}.wtns"

        if wasm_file.exists() and self.snarkjs_available:
            generate_witness_js = wasm_dir / "generate_witness.js"
            if generate_witness_js.exists():
                subprocess.run(
                    [
                        "node",
                        str(generate_witness_js),
                        str(wasm_file),
                        str(input_path),
                        str(witness_out),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                witness.witness_path = witness_out

        return witness

    # ------------------------------------------------------------------
    # Proof generation
    # ------------------------------------------------------------------
    def prove(self, witness: Witness) -> ZKProof:
        """
        Generate a Groth16 proof from a witness.

        Args:
            witness: A :class:`Witness` previously created via
                :meth:`generate_witness`.

        Returns:
            :class:`ZKProof` containing the proof and public signals.

        Raises:
            FileNotFoundError: When required artefacts (witness file,
                zkey) are missing.
            RuntimeError: When snarkjs is not available.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
                "Install snarkjs globally or provide an explicit path."
            )

        witness_path = witness.witness_path or (self.build_dir / f"{self.circuit}.wtns")
        zkey_path = self.build_dir / f"{self.circuit}_final.zkey"
        proof_path = self.build_dir / f"{self.circuit}_proof.json"
        public_path = self.build_dir / f"{self.circuit}_public.json"

        return self._prover.prove_existence(
            leaf=witness.inputs.get("leaf", "0"),
            root=witness.inputs.get("root", "0"),
            path_elements=witness.inputs.get("pathElements", []),
            path_indices=witness.inputs.get("pathIndices", []),
            witness_path=witness_path,
            zkey_path=zkey_path,
            proof_path=proof_path,
            public_path=public_path,
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify(
        self,
        proof: ZKProof,
        public_inputs: list[Any] | None = None,
        verification_key_path: Path | None = None,
    ) -> bool:
        """
        Verify a Groth16 proof.

        Args:
            proof: The :class:`ZKProof` to verify.
            public_inputs: Optional override for public signals.  If
                provided they replace the signals inside *proof* for
                this verification call.
            verification_key_path: Explicit path to a verification key
                JSON file.  When *None* the generator searches the
                standard ``keys/verification_keys/`` directory.

        Returns:
            *True* if the proof verifies successfully, *False* otherwise.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
                "Install snarkjs globally or provide an explicit path."
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

    # ------------------------------------------------------------------
    # Offline helpers
    # ------------------------------------------------------------------
    def export_proof(self, proof: ZKProof, path: Path) -> None:
        """Write a proof and its public signals to a JSON file.

        Args:
            proof: The proof to export.
            path: Destination file path.
        """
        with path.open("w", encoding="utf-8") as fh:
            json.dump(proof.to_dict(), fh, indent=2)

    @staticmethod
    def load_proof(path: Path) -> ZKProof:
        """Load a proof from a JSON file previously written by :meth:`export_proof`.

        Args:
            path: Path to the proof JSON file.

        Returns:
            Reconstructed :class:`ZKProof`.
        """
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return ZKProof(
            proof=data["proof"],
            public_signals=data["public_signals"],
            circuit=data["circuit"],
        )

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------
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
        """Raise ``ValueError`` if required inputs are missing."""
        required = self._REQUIRED_INPUTS.get(self.circuit, [])
        missing = [k for k in required if k not in inputs]
        if missing:
            raise ValueError(f"Missing required inputs for circuit '{self.circuit}': {missing}")
