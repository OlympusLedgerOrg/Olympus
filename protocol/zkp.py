"""
Groth16 proof bridge for Olympus.

This module provides a minimal Python interface around snarkjs while keeping
Poseidon hashing confined to circuit scope and BLAKE3 hashing in Python.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical_json import canonical_json_bytes
from .hashes import hash_bytes


OLYMPUS_DEFAULT_PROOF_TYPE = "groth16"
OLYMPUS_DEFAULT_PROTOCOL_VERSION = "1"
SUPPORTED_PROOF_PROTOCOL_VERSIONS = {OLYMPUS_DEFAULT_PROTOCOL_VERSION}


@dataclass
class ZKProof:
    """Container for zkSNARK proof artifacts."""

    proof: dict[str, Any]
    public_signals: list[Any]
    circuit: str
    proof_type: str = OLYMPUS_DEFAULT_PROOF_TYPE
    protocol_version: str = OLYMPUS_DEFAULT_PROTOCOL_VERSION

    @property
    def proof_bytes(self) -> bytes:
        """Return canonicalized proof bytes suitable for transport or hashing."""
        return canonical_json_bytes(self.proof)

    @property
    def public_inputs_hash(self) -> str:
        """Hash public signals using canonical JSON + BLAKE3 (hex encoded)."""
        return self._hash_public_inputs(self.public_signals)

    @staticmethod
    def _hash_public_inputs(public_signals: list[Any]) -> str:
        """Compute canonicalized BLAKE3 hash for public inputs list."""
        return hash_bytes(canonical_json_bytes(public_signals)).hex()

    @staticmethod
    def _load_proof_from_bytes(encoded_hex: str) -> dict[str, Any]:
        """Decode a hex-encoded canonical JSON proof."""
        try:
            decoded = bytes.fromhex(encoded_hex)
        except ValueError as exc:
            raise ValueError("proof_bytes must be valid hex-encoded string") from exc
        try:
            result = json.loads(decoded.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("proof_bytes did not decode to valid JSON proof object") from exc
        if not isinstance(result, dict):
            raise ValueError("proof_bytes did not decode to a JSON object")
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ZKProof:
        """
        Deserialize a proof from dictionary form (metadata wrapper or legacy dict).

        Accepts the new metadata wrapper keys (proof_type, circuit_id, proof_bytes,
        public_inputs_hash, protocol_version) while remaining backward compatible
        with the previous shape containing only proof/public_signals/circuit.
        """
        if "circuit_id" in data:
            circuit = data.get("circuit_id")
        else:
            circuit = data.get("circuit")
        if circuit is None:
            raise ValueError("Proof dictionary must include 'circuit_id' or 'circuit'")

        proof_bytes_hex = data.get("proof_bytes")
        proof_obj = data.get("proof")
        if proof_obj is None:
            if proof_bytes_hex is None:
                raise ValueError("Proof dictionary must include 'proof' or 'proof_bytes'")
            proof_obj = cls._load_proof_from_bytes(proof_bytes_hex)
        elif proof_bytes_hex is not None:
            provided_bytes = bytes.fromhex(proof_bytes_hex)
            canonical_bytes = canonical_json_bytes(proof_obj)
            if canonical_bytes != provided_bytes:
                expected_digest = hash_bytes(canonical_bytes).hex()
                provided_digest = hash_bytes(provided_bytes).hex()
                raise ValueError(
                    "Canonical proof bytes mismatch for "
                    f"circuit '{circuit}' (non-canonical encoding or tampering). "
                    f"expected_digest={expected_digest}, provided_digest={provided_digest}"
                )

        public_signals = data.get("public_signals", [])
        provided_hash = data.get("public_inputs_hash")
        computed_hash = cls._hash_public_inputs(public_signals)
        if provided_hash is not None and provided_hash != computed_hash:
            raise ValueError(
                "public_inputs_hash does not match provided public_signals "
                f"(expected {computed_hash}, got {provided_hash})"
            )

        raw_protocol_version = data.get("protocol_version")
        if raw_protocol_version is None:
            raw_protocol_version = OLYMPUS_DEFAULT_PROTOCOL_VERSION
        elif not isinstance(raw_protocol_version, str):
            raise ValueError(
                'protocol_version must be a string (e.g., "1"); '
                f"got {type(raw_protocol_version).__name__}"
            )
        elif not raw_protocol_version.strip():
            raise ValueError("protocol_version must be a non-empty string")
        elif raw_protocol_version not in SUPPORTED_PROOF_PROTOCOL_VERSIONS:
            raise ValueError(
                f"Unsupported protocol_version '{raw_protocol_version}'. "
                f"Supported versions: {sorted(SUPPORTED_PROOF_PROTOCOL_VERSIONS)}"
            )

        return cls(
            proof=proof_obj,
            public_signals=public_signals,
            circuit=circuit,
            proof_type=data.get("proof_type", OLYMPUS_DEFAULT_PROOF_TYPE),
            protocol_version=raw_protocol_version,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize proof to a self-describing metadata wrapper."""
        proof_hex = self.proof_bytes.hex()
        return {
            "proof_type": self.proof_type,
            "circuit_id": self.circuit,
            "public_inputs_hash": self.public_inputs_hash,
            "proof_bytes": proof_hex,
            "protocol_version": self.protocol_version,
            # Backward-compatibility fields
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
        self._snarkjs_path: str | None = None

    @staticmethod
    def _validate_circuit_name(circuit: str) -> None:
        """Restrict circuit identifiers to simple file-stem tokens (allowlist).

        Prevents path-traversal and shell-injection attacks where a caller
        supplies a circuit name that bleeds out of the expected build directory
        or injects shell metacharacters into filesystem paths.
        """
        if not re.fullmatch(r"[A-Za-z0-9_-]+", circuit):
            raise ValueError(f"Invalid circuit identifier: {circuit!r}")

    def _check_snarkjs(self) -> str:
        """Ensure snarkjs launcher is available (snarkjs or npx) and cache absolute path."""
        resolved = shutil.which(self.snarkjs_bin)
        if resolved is None:
            raise FileNotFoundError(
                f"snarkjs binary '{self.snarkjs_bin}' not found in PATH. "
                "Install Node.js/npm (for npx) or install snarkjs globally, "
                "or provide an explicit path."
            )
        self._snarkjs_path = resolved
        return resolved

    def _build_cmd(self, args: list[str]) -> list[str]:
        """
        Build the subprocess command.

        If snarkjs_bin == "npx", we run: npx snarkjs <args...>
        Else we run: <snarkjs_bin> <args...>
        """
        launcher = self._snarkjs_path or self._check_snarkjs()
        if self.snarkjs_bin == "npx":
            return [launcher, "snarkjs", *args]
        return [launcher, *args]

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
            [
                "groth16",
                "prove",
                str(zkey_path),
                str(witness_path),
                str(proof_path),
                str(public_path),
            ],
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

        .. deprecated:: 1.0
            This legacy method is deprecated and will be removed in a future release.
            Use :meth:`prove` with ``circuit="document_existence"`` instead.

        NOTE: leaf/root/path_* are not used by snarkjs prove once witness exists;
        they remain here for API compatibility with earlier code.

        Args:
            leaf: Not used (legacy parameter).
            root: Not used (legacy parameter).
            path_elements: Not used (legacy parameter).
            path_indices: Not used (legacy parameter).
            witness_path: Path to pre-computed witness file (required).
            zkey_path: Path to proving key.
            proof_path: Output path for proof.
            public_path: Output path for public signals.

        Returns:
            ZKProof containing the Groth16 proof.

        Raises:
            DeprecationWarning: This method is deprecated.
            FileNotFoundError: If the witness file does not exist.
        """
        import warnings

        # L5-C: Emit deprecation warning
        warnings.warn(
            "prove_existence is deprecated and will be removed in a future release. "
            "Use Groth16Prover.prove(circuit='document_existence', ...) instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        witness = witness_path or (self.circuits_dir / "build" / "document_existence.wtns")
        zkey = zkey_path or (self.circuits_dir / "build" / "document_existence_final.zkey")
        proof_file = proof_path or (self.circuits_dir / "build" / "document_existence_proof.json")
        public_file = public_path or (
            self.circuits_dir / "build" / "document_existence_public.json"
        )

        # L5-C: Enforce witness file existence before proceeding
        if not witness.exists():
            raise FileNotFoundError(
                f"Witness file not found: {witness}. "
                f"Generate the witness using the circuit's WASM witness generator first."
            )

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

        # Validate circuit name before using it in path construction to prevent
        # path-traversal attacks via a crafted circuit identifier.
        self._validate_circuit_name(proof.circuit)

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
