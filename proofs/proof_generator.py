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
        treeSize="1048576",
        leaf="42",
        pathElements=["0"] * 20,
        pathIndices=[0] * 20,
    )
    proof = generator.prove(witness)
    verified = generator.verify(proof, public_inputs=proof.public_signals)

    # Configure circuit parameters (writes proofs/circuits/parameters.circom)
    # python -m proofs.proof_generator configure --document-merkle-depth 32

Hash boundary note:
    Circuits use **Poseidon** for in-circuit hashing while the Python/ledger
    layer may use **BLAKE3**. Witness generation must supply Poseidon-compatible
    field elements. See ``proofs/README.md`` for details.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from protocol.zkp import Groth16Prover, ZKProof


SUPPORTED_CIRCUITS = frozenset(
    {
        "document_existence",
        "non_existence",
        "redaction_validity",
        "unified_canonicalization_inclusion_root_sign",
    }
)

# Default paths relative to this file
_PROOFS_DIR = Path(__file__).resolve().parent
_CIRCUITS_DIR = _PROOFS_DIR / "circuits"
_KEYS_DIR = _PROOFS_DIR / "keys"
_BUILD_DIR = _PROOFS_DIR / "build"


@dataclass(frozen=True)
class CircuitConfig:
    """Circuit configuration values for compile-time parameterization."""

    document_merkle_depth: int
    non_existence_merkle_depth: int
    redaction_max_leaves: int
    redaction_merkle_depth: int
    unified_max_sections: int
    unified_merkle_depth: int
    unified_smt_depth: int
    selective_disclosure_depth: int
    selective_disclosure_k: int
    selective_disclosure_preimage_len: int

    @classmethod
    def default(cls) -> "CircuitConfig":
        return cls(
            document_merkle_depth=20,
            non_existence_merkle_depth=20,
            redaction_max_leaves=16,
            redaction_merkle_depth=4,
            unified_max_sections=8,
            unified_merkle_depth=20,
            unified_smt_depth=256,
            selective_disclosure_depth=20,
            selective_disclosure_k=8,
            selective_disclosure_preimage_len=6,
        )

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "CircuitConfig":
        env = environ or os.environ
        defaults = cls.default()

        def env_int(name: str, fallback: int) -> int:
            raw = env.get(name)
            if raw is None or raw == "":
                return fallback
            try:
                value = int(raw, 10)
            except ValueError as exc:
                raise ValueError(f"Invalid {name} value {raw!r}") from exc
            if value <= 0:
                raise ValueError(f"{name} must be positive")
            return value

        return cls(
            document_merkle_depth=env_int(
                "OLYMPUS_DOCUMENT_MERKLE_DEPTH", defaults.document_merkle_depth
            ),
            non_existence_merkle_depth=env_int(
                "OLYMPUS_NON_EXISTENCE_MERKLE_DEPTH", defaults.non_existence_merkle_depth
            ),
            redaction_max_leaves=env_int(
                "OLYMPUS_REDACTION_MAX_LEAVES", defaults.redaction_max_leaves
            ),
            redaction_merkle_depth=env_int(
                "OLYMPUS_REDACTION_MERKLE_DEPTH", defaults.redaction_merkle_depth
            ),
            unified_max_sections=env_int(
                "OLYMPUS_UNIFIED_MAX_SECTIONS", defaults.unified_max_sections
            ),
            unified_merkle_depth=env_int(
                "OLYMPUS_UNIFIED_MERKLE_DEPTH", defaults.unified_merkle_depth
            ),
            unified_smt_depth=env_int(
                "OLYMPUS_UNIFIED_SMT_DEPTH", defaults.unified_smt_depth
            ),
            selective_disclosure_depth=env_int(
                "OLYMPUS_SELECTIVE_DISCLOSURE_DEPTH", defaults.selective_disclosure_depth
            ),
            selective_disclosure_k=env_int(
                "OLYMPUS_SELECTIVE_DISCLOSURE_K", defaults.selective_disclosure_k
            ),
            selective_disclosure_preimage_len=env_int(
                "OLYMPUS_SELECTIVE_DISCLOSURE_PREIMAGE_LEN",
                defaults.selective_disclosure_preimage_len,
            ),
        )

    def to_circom(self) -> str:
        """Render configuration as a Circom include file."""
        return (
            "pragma circom 2.0.0;\n\n"
            "// Configurable circuit parameters (updated via proofs/proof_generator.py).\n"
            "// Keep these defaults aligned with protocol docs and test inputs.\n\n"
            f"var DOCUMENT_MERKLE_DEPTH = {self.document_merkle_depth};\n"
            f"var NON_EXISTENCE_MERKLE_DEPTH = {self.non_existence_merkle_depth};\n"
            f"var REDACTION_MAX_LEAVES = {self.redaction_max_leaves};\n"
            f"var REDACTION_MERKLE_DEPTH = {self.redaction_merkle_depth};\n"
            f"var UNIFIED_MAX_SECTIONS = {self.unified_max_sections};\n"
            f"var UNIFIED_MERKLE_DEPTH = {self.unified_merkle_depth};\n"
            f"var UNIFIED_SMT_DEPTH = {self.unified_smt_depth};\n"
            f"var SELECTIVE_DISCLOSURE_DEPTH = {self.selective_disclosure_depth};\n"
            f"var SELECTIVE_DISCLOSURE_K = {self.selective_disclosure_k};\n"
            f"var SELECTIVE_DISCLOSURE_PREIMAGE_LEN = "
            f"{self.selective_disclosure_preimage_len};\n"
        )

    def validate(self) -> None:
        """Validate cross-parameter constraints."""
        max_leaves_capacity = 1 << self.redaction_merkle_depth
        if self.redaction_max_leaves != max_leaves_capacity:
            raise ValueError(
                "redaction_max_leaves must equal 2^redaction_merkle_depth "
                f"(expected {max_leaves_capacity})."
            )
        selective_capacity = 1 << self.selective_disclosure_depth
        if self.selective_disclosure_k > selective_capacity:
            raise ValueError(
                "selective_disclosure_k must be <= 2^selective_disclosure_depth "
                f"(max {selective_capacity})."
            )


def write_circuit_parameters(config: CircuitConfig, path: Path | None = None) -> Path:
    """Write Circom parameter include file for configurable circuits."""
    config.validate()
    output_path = path or (_CIRCUITS_DIR / "parameters.circom")
    output_path.write_text(config.to_circom(), encoding="utf-8")
    return output_path


@dataclass
class Witness:
    """Container for a circuit witness (input signals)."""

    circuit: str
    inputs: dict[str, Any]
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
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
        circuit_config: CircuitConfig | None = None,
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
        self.circuit_config = circuit_config or CircuitConfig.from_env()
        self.circuit_config.validate()
        self.snarkjs_bin = snarkjs_bin

        # Groth16Prover expects circuits_dir to be the proofs/circuits directory
        self._prover = Groth16Prover(self.circuits_dir, snarkjs_bin=snarkjs_bin)

    @property
    def snarkjs_available(self) -> bool:
        """Return True if the configured snarkjs launcher is on PATH."""
        return shutil.which(self.snarkjs_bin) is not None

    def generate_witness(self, **inputs: Any) -> Witness:
        """
        Build a witness for the configured circuit.

        Writes a unique input JSON and generates a unique witness .wtns via WASM.
        Only Node.js is required for witness generation.
        """
        self._validate_inputs(inputs)

        witness = Witness(circuit=self.circuit, inputs=inputs)
        run_id = witness.run_id

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
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
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

        Important: by default the verification key is selected based on proof.circuit,
        not the generator's configured circuit.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs binary '{self.snarkjs_bin}' not found. "
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
            vkey = self.keys_dir / "verification_keys" / f"{verify_proof.circuit}_vkey.json"

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
        return ZKProof.from_dict(data)

    # Keep this in sync with circuit signal names
    _REQUIRED_INPUTS: dict[str, list[str]] = {
        "document_existence": [
            "root",
            "leaf",
            "leafIndex",
            "treeSize",
            "pathElements",
            "pathIndices",
        ],
        # UPDATED: indexed non-existence now uses leafIndex (public) and does NOT take emptyLeaf.
        "non_existence": ["root", "leafIndex", "treeSize", "pathElements", "pathIndices"],
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

    @staticmethod
    def _require_length(name: str, value: Any, expected: int) -> None:
        if not isinstance(value, list) or len(value) != expected:
            raise ValueError(f"{name} must be a list of length {expected}")

    @classmethod
    def _require_nested_length(
        cls,
        name: str,
        value: Any,
        outer: int,
        inner: int,
    ) -> None:
        if not isinstance(value, list) or len(value) != outer:
            raise ValueError(f"{name} must be a list of length {outer}")
        for idx, item in enumerate(value):
            if not isinstance(item, list) or len(item) != inner:
                raise ValueError(f"{name}[{idx}] must be a list of length {inner}")

    def _validate_inputs(self, inputs: dict[str, Any]) -> None:
        required = self._REQUIRED_INPUTS.get(self.circuit, [])
        missing = [k for k in required if k not in inputs]
        if missing:
            raise ValueError(f"Missing required inputs for circuit '{self.circuit}': {missing}")

        config = self.circuit_config
        if self.circuit == "document_existence":
            self._require_length(
                "pathElements", inputs.get("pathElements"), config.document_merkle_depth
            )
            self._require_length(
                "pathIndices", inputs.get("pathIndices"), config.document_merkle_depth
            )
        elif self.circuit == "non_existence":
            self._require_length(
                "pathElements", inputs.get("pathElements"), config.non_existence_merkle_depth
            )
            self._require_length(
                "pathIndices", inputs.get("pathIndices"), config.non_existence_merkle_depth
            )
        elif self.circuit == "redaction_validity":
            self._require_length(
                "originalLeaves", inputs.get("originalLeaves"), config.redaction_max_leaves
            )
            self._require_length(
                "revealMask", inputs.get("revealMask"), config.redaction_max_leaves
            )
            self._require_nested_length(
                "pathElements",
                inputs.get("pathElements"),
                config.redaction_max_leaves,
                config.redaction_merkle_depth,
            )
            self._require_nested_length(
                "pathIndices",
                inputs.get("pathIndices"),
                config.redaction_max_leaves,
                config.redaction_merkle_depth,
            )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Configure Olympus Circom circuit parameter defaults."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    configure = subparsers.add_parser(
        "configure",
        help="Write proofs/circuits/parameters.circom with updated values.",
    )
    configure.add_argument(
        "--output",
        type=Path,
        default=_CIRCUITS_DIR / "parameters.circom",
        help="Path to write the Circom parameters include file.",
    )
    configure.add_argument(
        "--from-env",
        action="store_true",
        help="Seed defaults from OLYMPUS_* environment variables.",
    )
    configure.add_argument("--document-merkle-depth", type=int, dest="document_merkle_depth")
    configure.add_argument("--non-existence-merkle-depth", type=int, dest="non_existence_merkle_depth")
    configure.add_argument("--redaction-max-leaves", type=int, dest="redaction_max_leaves")
    configure.add_argument("--redaction-merkle-depth", type=int, dest="redaction_merkle_depth")
    configure.add_argument("--unified-max-sections", type=int, dest="unified_max_sections")
    configure.add_argument("--unified-merkle-depth", type=int, dest="unified_merkle_depth")
    configure.add_argument("--unified-smt-depth", type=int, dest="unified_smt_depth")
    configure.add_argument(
        "--selective-disclosure-depth", type=int, dest="selective_disclosure_depth"
    )
    configure.add_argument("--selective-disclosure-k", type=int, dest="selective_disclosure_k")
    configure.add_argument(
        "--selective-disclosure-preimage-len",
        type=int,
        dest="selective_disclosure_preimage_len",
    )

    return parser


def _resolve_config_from_args(args: argparse.Namespace) -> CircuitConfig:
    base = CircuitConfig.from_env() if args.from_env else CircuitConfig.default()
    overrides = {
        field: getattr(args, field)
        for field in (
            "document_merkle_depth",
            "non_existence_merkle_depth",
            "redaction_max_leaves",
            "redaction_merkle_depth",
            "unified_max_sections",
            "unified_merkle_depth",
            "unified_smt_depth",
            "selective_disclosure_depth",
            "selective_disclosure_k",
            "selective_disclosure_preimage_len",
        )
        if getattr(args, field) is not None
    }
    return replace(base, **overrides) if overrides else base


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "configure":
        config = _resolve_config_from_args(args)
        output_path = write_circuit_parameters(config, args.output)
        print(f"Wrote circuit parameters to {output_path}")
        return 0

    parser.error("Unsupported command")  # pragma: no cover
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
