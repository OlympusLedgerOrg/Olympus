"""
High-level Python integration for ZK proof generation and verification.

This module provides a unified ``ProofGenerator`` interface that bridges
the gap between Olympus's Python protocol layer and the snarkjs/circom
ZK circuit infrastructure.

Usage::

    from protocol.poseidon_smt import PoseidonSMT
    from proofs.proof_generator import ProofGenerator

    key1 = bytes.fromhex("01" * 32)
    key2 = bytes.fromhex("02" * 32)
    value_hash1 = int.from_bytes(bytes.fromhex("10" * 32), byteorder="big")
    value_hash2 = int.from_bytes(bytes.fromhex("20" * 32), byteorder="big")
    key_to_prove_absent = bytes.fromhex("03" * 32)

    smt = PoseidonSMT()
    smt.update(key1, value_hash1)
    smt.update(key2, value_hash2)

    witness = ProofGenerator.witness_from_smt(smt, key_to_prove_absent)
    generator = ProofGenerator("non_existence")
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
import logging
import os
import shutil
import signal
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from proofs import snarkjs_bridge
from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.poseidon_bn128 import poseidon_hash_bn128
from protocol.poseidon_tree import POSEIDON_DOMAIN_COMMITMENT
from protocol.zkp import Groth16Prover, ZKProof


if TYPE_CHECKING:
    from protocol.poseidon_smt import PoseidonSMT

_log = logging.getLogger(__name__)

# Per-operation timeout constant (seconds)
_WITNESS_TIMEOUT_SECS = 120  # witness gen can be slow on large circuits


def _make_pdeathsig_preexec():
    """
    Return a preexec_fn that sets PR_SET_PDEATHSIG=SIGTERM on Linux so the
    child process is automatically killed when its parent process dies.
    Returns None on non-Linux platforms (Popen accepts None for preexec_fn).
    """
    import sys

    if sys.platform != "linux":
        return None
    import ctypes

    _PR_SET_PDEATHSIG = 1
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return None

    def _preexec() -> None:
        libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)

    return _preexec


def _try_limit_cgroup(pid: int, *, memory_bytes: int) -> None:
    """
    Best-effort: move *pid* into a dedicated cgroupv2 leaf and cap its memory.

    Silently no-ops if not on Linux, if /sys/fs/cgroup is not a cgroupv2
    unified hierarchy, if the process lacks write permission, or on any
    other OS/IO error. Never raises; failures are logged at DEBUG level so
    they don't obscure the real work.
    """
    import sys

    if sys.platform != "linux":
        return
    cgroup_root = Path("/sys/fs/cgroup")
    try:
        # Verify cgroupv2 unified hierarchy
        if not (cgroup_root / "cgroup.controllers").exists():
            return
        # Create a per-PID leaf under an olympus sub-tree
        leaf = cgroup_root / "olympus" / f"snarkjs-{pid}"
        leaf.mkdir(parents=True, exist_ok=True)
        # Cap memory before the process can allocate much
        (leaf / "memory.max").write_text(str(memory_bytes), encoding="ascii")
        # Move the process into the leaf
        (leaf / "cgroup.procs").write_text(str(pid), encoding="ascii")
    except Exception as exc:  # noqa: BLE001
        _log.debug("_try_limit_cgroup: could not limit pid %d: %s", pid, exc)


def _run_subprocess(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Run a subprocess with timeout and best-effort process group cleanup.

    Uses start_new_session=True so the entire npx + Node.js tree can be
    killed as a group on timeout. If the container security policy blocks
    setsid (OSError on Popen), falls back to plain Popen with
    PR_SET_PDEATHSIG set via preexec_fn (_make_pdeathsig_preexec) on Linux
    so children are still signalled when the parent dies — timeout still
    applies, but only the direct child is killed on expiry.

    After a successful Popen the child is moved into a memory-bounded
    cgroupv2 leaf (_try_limit_cgroup) to prevent a runaway snarkjs circuit
    from OOM-killing the whole runner.
    """
    use_new_session = True
    try:
        proc = subprocess.Popen(  # nosec B603
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError:
        # setsid(2) blocked by container security policy (seccomp/gVisor).
        # Fall back: set PR_SET_PDEATHSIG so children die with the parent,
        # but orphaned siblings may still survive if npx is killed.
        _log.warning(
            "start_new_session=True failed (seccomp restriction?); "
            "falling back to plain subprocess — orphaned children possible on timeout"
        )
        use_new_session = False
        proc = subprocess.Popen(  # nosec B603
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=_make_pdeathsig_preexec(),
        )

    # After Popen, move the child into a memory-bounded cgroup
    # Prevents a runaway snarkjs circuit from OOMing the whole runner
    _try_limit_cgroup(proc.pid, memory_bytes=2 * 1024**3)  # 2GB ceiling

    with proc:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if use_new_session:
                # Kill the whole process group
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass  # process already exited before we could signal it
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # process already exited during the grace period
                    proc.communicate()
            else:
                # Best effort: kill just the direct child
                proc.kill()
                proc.communicate()
            raise

        returncode = proc.wait()

    completed = subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
    if check and returncode != 0:
        raise subprocess.CalledProcessError(returncode, cmd, stdout, stderr)
    return completed


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
    def default(cls) -> CircuitConfig:
        return cls(
            document_merkle_depth=20,
            non_existence_merkle_depth=256,
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
    def from_env(cls, environ: Mapping[str, str] | None = None) -> CircuitConfig:
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
            unified_smt_depth=env_int("OLYMPUS_UNIFIED_SMT_DEPTH", defaults.unified_smt_depth),
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
        """Render configuration as a Circom include file.

        Uses zero-argument functions rather than top-level ``var`` declarations
        because circom 2.x does not allow global variable declarations.
        """

        def _fn(name: str, value: int) -> str:
            return f"function {name}() {{ return {value}; }}\n"

        return (
            "pragma circom 2.0.0;\n\n"
            "// Configurable circuit parameters (updated via proofs/proof_generator.py).\n"
            "// Keep these defaults aligned with protocol docs and test inputs.\n"
            "// Note: circom 2.x does not allow global var declarations; use functions instead.\n\n"
            + _fn("DOCUMENT_MERKLE_DEPTH", self.document_merkle_depth)
            + _fn("NON_EXISTENCE_MERKLE_DEPTH", self.non_existence_merkle_depth)
            + _fn("REDACTION_MAX_LEAVES", self.redaction_max_leaves)
            + _fn("REDACTION_MERKLE_DEPTH", self.redaction_merkle_depth)
            + _fn("UNIFIED_MAX_SECTIONS", self.unified_max_sections)
            + _fn("UNIFIED_MERKLE_DEPTH", self.unified_merkle_depth)
            + _fn("UNIFIED_SMT_DEPTH", self.unified_smt_depth)
            + _fn("SELECTIVE_DISCLOSURE_DEPTH", self.selective_disclosure_depth)
            + _fn("SELECTIVE_DISCLOSURE_K", self.selective_disclosure_k)
            + _fn("SELECTIVE_DISCLOSURE_PREIMAGE_LEN", self.selective_disclosure_preimage_len)
        )

    def validate(self) -> None:
        """Validate cross-parameter constraints."""
        max_leaves_capacity = 1 << self.redaction_merkle_depth
        if self.redaction_max_leaves > max_leaves_capacity:
            raise ValueError(
                "redaction_max_leaves must be <= 2^redaction_merkle_depth "
                f"(max {max_leaves_capacity})."
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
        """Return True if snarkjs is available (via bridge or CLI)."""
        return snarkjs_bridge.bridge_available() or shutil.which(self.snarkjs_bin) is not None

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

        _run_subprocess(
            ["node", str(generate_witness_js), str(wasm_file), str(input_path), str(witness_out)],
            cwd=self.build_dir,
            timeout=_WITNESS_TIMEOUT_SECS,
        )
        witness.witness_path = witness_out
        return witness

    def prove(self, witness: Witness) -> ZKProof:
        """
        Generate a Groth16 proof from a witness produced by generate_witness().

        Uses the persistent Node.js snarkjs bridge when available,
        falling back to the CLI subprocess (npx snarkjs) otherwise.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs binary '{self.snarkjs_bin}' not found and Node.js bridge "
                "unavailable. Install Node.js/npm or install snarkjs globally."
            )

        zkey_path = self.build_dir / f"{self.circuit}_final.zkey"
        if not zkey_path.exists():
            raise FileNotFoundError(
                f"ZKey file not found: {zkey_path}. Run 'bash setup_circuits.sh' first."
            )

        # --- Preferred path: Node.js bridge ---
        if snarkjs_bridge.bridge_available():
            # If we have a witness file, use prove(); otherwise use fullProve()
            # with the raw input signals + WASM.
            if witness.witness_path is not None and witness.witness_path.exists():
                proof_dict, public_signals = snarkjs_bridge.prove(
                    witness_file=witness.witness_path,
                    zkey_file=zkey_path,
                )
            else:
                # fullProve: witness generation + proving in one step
                wasm_file = self.build_dir / f"{self.circuit}_js" / f"{self.circuit}.wasm"
                if not wasm_file.exists():
                    raise FileNotFoundError(
                        f"WASM witness generator not found: {wasm_file}. "
                        "Run 'bash setup_circuits.sh --compile-only' first."
                    )
                proof_dict, public_signals = snarkjs_bridge.full_prove(
                    input_signals=witness.inputs,
                    wasm_file=wasm_file,
                    zkey_file=zkey_path,
                )
            return ZKProof(
                proof=proof_dict,
                public_signals=public_signals,
                circuit=self.circuit,
            )

        # --- Fallback: CLI subprocess via Groth16Prover ---
        if witness.witness_path is None or not witness.witness_path.exists():
            raise FileNotFoundError(
                "Witness file missing. Ensure circuits are compiled (setup_circuits.sh) "
                "and witness generation succeeded."
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

        Uses the persistent Node.js snarkjs bridge when available,
        falling back to the CLI subprocess (npx snarkjs) otherwise.

        If public_inputs is provided, it overrides proof.public_signals for this call.

        Important: by default the verification key is selected based on proof.circuit,
        not the generator's configured circuit.
        """
        if not self.snarkjs_available:
            raise RuntimeError(
                f"snarkjs binary '{self.snarkjs_bin}' not found and Node.js bridge "
                "unavailable. Install Node.js/npm or install snarkjs globally."
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

        # --- Preferred path: Node.js bridge ---
        if snarkjs_bridge.bridge_available():
            return snarkjs_bridge.verify(
                vkey_file=vkey,
                proof=verify_proof.proof,
                public_signals=verify_proof.public_signals,
            )

        # --- Fallback: CLI subprocess via Groth16Prover ---
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

    @classmethod
    def witness_from_smt(
        cls,
        smt: PoseidonSMT,
        key: bytes,
        *,
        circuit_config: CircuitConfig | None = None,
        snarkjs_bin: str = "npx",
    ) -> Witness:
        """
        Generate a non-existence witness directly from a PoseidonSMT.

        Args:
            smt: Poseidon sparse Merkle tree populated with the authoritative
                key/value pairs for the proof target.
            key: 32-byte key to prove absent.
            circuit_config: Optional circuit configuration override.
            snarkjs_bin: snarkjs launcher command.

        Returns:
            Witness ready for non_existence proof generation.

        Raises:
            ValueError: If the key is already present in the SMT.
        """
        config = replace(circuit_config or CircuitConfig.from_env(), non_existence_merkle_depth=256)
        generator = cls(
            "non_existence",
            circuit_config=config,
            snarkjs_bin=snarkjs_bin,
        )
        nonexistence_witness = smt.prove_nonexistence(key)
        return generator.generate_witness(
            root=nonexistence_witness.root,
            key=[int(byte) for byte in nonexistence_witness.key],
            pathElements=nonexistence_witness.path_elements,
        )

    @classmethod
    def witness_from_smt_existence(
        cls,
        smt: PoseidonSMT,
        key: bytes,
        *,
        circuit_config: CircuitConfig | None = None,
        snarkjs_bin: str = "npx",
    ) -> Witness:
        """
        Generate a document_existence witness directly from a PoseidonSMT.

        Args:
            smt: Poseidon sparse Merkle tree populated with the authoritative
                key/value pairs for the proof target.
            key: 32-byte key to prove present.
            circuit_config: Optional circuit configuration override.
            snarkjs_bin: snarkjs launcher command.

        Returns:
            Witness ready for document_existence proof generation.

        Raises:
            ValueError: If the key is absent from the SMT.
        """
        from protocol.hashes import SNARK_SCALAR_FIELD
        from protocol.poseidon_bn128 import poseidon_hash_bn128

        value = smt.get(key)
        if value is None:
            raise ValueError("Key is absent from the SMT; use witness_from_smt for absence")

        config = replace(circuit_config or CircuitConfig.from_env(), document_merkle_depth=256)

        path = smt._key_to_path(key)
        path_elements = [str(sibling) for sibling in smt._collect_siblings(path)]
        path_indices = list(reversed(path))
        key_int = int.from_bytes(key, byteorder="big") % SNARK_SCALAR_FIELD
        leaf = poseidon_hash_bn128(key_int, value % SNARK_SCALAR_FIELD) % SNARK_SCALAR_FIELD

        generator = cls(
            "document_existence",
            circuit_config=config,
            snarkjs_bin=snarkjs_bin,
        )
        return generator.generate_witness(
            root=str(smt.get_root()),
            leaf=str(leaf),
            leafIndex=str(int.from_bytes(key, byteorder="big") % SNARK_SCALAR_FIELD),
            treeSize=str((1 << len(path_indices)) % SNARK_SCALAR_FIELD),
            pathElements=path_elements,
            pathIndices=path_indices,
        )

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
        # L4-B: keyed non-existence uses key[32] (PRIVATE) and derives path internally.
        # Only root is public; key and pathElements are private inputs.
        "non_existence": ["root", "key", "pathElements"],
        "redaction_validity": [
            "originalRoot",
            "redactedCommitment",
            "revealedCount",
            "originalLeaves",
            "revealMask",
            "pathElements",
            "pathIndices",
        ],
        "unified_canonicalization_inclusion_root_sign": [
            "canonicalHash",
            "merkleRoot",
            "ledgerRoot",
            "treeSize",
            "documentSections",
            "sectionCount",
            "sectionLengths",
            "sectionHashes",
            "merklePath",
            "merkleIndices",
            "leafIndex",
            "ledgerPathElements",
            "ledgerPathIndices",
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
            # key must be a 32-element list of integers in [0, 255]
            if not isinstance(inputs.get("key"), list) or len(inputs["key"]) != 32:
                raise ValueError("non_existence 'key' must be a list of exactly 32 integers")
            for idx, byte_val in enumerate(inputs["key"]):
                if not isinstance(byte_val, int) or not (0 <= byte_val <= 255):
                    raise ValueError(
                        f"non_existence key[{idx}] = {byte_val!r} is not an integer in [0, 255]"
                    )
            self._require_length(
                "pathElements", inputs.get("pathElements"), config.non_existence_merkle_depth
            )
            # pathIndices is no longer a caller input — the circuit derives it from key.
            # Reject it explicitly if supplied to catch callers using the old API:
            if "pathIndices" in inputs:
                raise ValueError(
                    "non_existence no longer accepts pathIndices — the circuit derives "
                    "path bits from the key. Remove pathIndices from your call."
                )
            if "leafIndex" in inputs:
                raise ValueError(
                    "non_existence no longer accepts leafIndex — use key=[32 bytes] instead."
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
        elif self.circuit == "unified_canonicalization_inclusion_root_sign":
            # Validate structured canonicalization inputs
            self._require_length(
                "documentSections", inputs.get("documentSections"), config.unified_max_sections
            )
            self._require_length(
                "sectionLengths", inputs.get("sectionLengths"), config.unified_max_sections
            )
            self._require_length(
                "sectionHashes", inputs.get("sectionHashes"), config.unified_max_sections
            )
            # Validate Merkle inclusion proof inputs
            self._require_length(
                "merklePath", inputs.get("merklePath"), config.unified_merkle_depth
            )
            self._require_length(
                "merkleIndices", inputs.get("merkleIndices"), config.unified_merkle_depth
            )
            # Validate SMT ledger proof inputs
            self._require_length(
                "ledgerPathElements", inputs.get("ledgerPathElements"), config.unified_smt_depth
            )
            self._require_length(
                "ledgerPathIndices", inputs.get("ledgerPathIndices"), config.unified_smt_depth
            )

            # Finding #11/#12: Validate BLAKE3/Poseidon canonical-hash binding.
            # The circuit computes a Poseidon chain from sectionCount,
            # sectionLengths, and sectionHashes and asserts that the result
            # equals the public canonicalHash.  We replicate that computation
            # here so that a mismatched canonicalHash is rejected *before*
            # expensive witness/proof generation.
            self._validate_canonical_hash_binding(inputs, config.unified_max_sections)

    @staticmethod
    def recompute_canonical_hash(
        section_count: int | str,
        section_lengths: list[int | str],
        section_hashes: list[int | str],
        max_sections: int,
    ) -> str:
        """Recompute the Poseidon canonical hash from structured metadata.

        Mirrors the circuit's DomainPoseidon(3, ...) chain exactly:

        1. ``current = sectionCount``
        2. For each section ``i`` in ``[0, maxSections)``:
           ``current = DomainPoseidon(3, current, sectionLengths[i])``
           ``current = DomainPoseidon(3, current, sectionHashes[i])``
        3. Return ``current`` as a decimal string.

        Args:
            section_count: Number of real sections (field element).
            section_lengths: List of section byte-lengths (field elements).
            section_hashes: List of BLAKE3 section hashes as field elements.
            max_sections: Circuit-fixed max section count.

        Returns:
            Canonical hash as a decimal string matching the circuit's
            ``canonicalHash`` public signal.
        """
        F = SNARK_SCALAR_FIELD
        domain = POSEIDON_DOMAIN_COMMITMENT

        current = int(section_count) % F
        for i in range(max_sections):
            length_val = int(section_lengths[i]) % F
            hash_val = int(section_hashes[i]) % F

            # DomainPoseidon(3, current, length) = Poseidon(Poseidon(3, current), length)
            tagged = poseidon_hash_bn128(domain % F, current % F) % F
            current = poseidon_hash_bn128(tagged, length_val) % F

            # DomainPoseidon(3, current, sectionHash)
            tagged = poseidon_hash_bn128(domain % F, current % F) % F
            current = poseidon_hash_bn128(tagged, hash_val) % F

        return str(current)

    @classmethod
    def _validate_canonical_hash_binding(
        cls,
        inputs: dict[str, Any],
        max_sections: int,
    ) -> None:
        """Verify that canonicalHash matches the Poseidon chain of section metadata.

        Raises:
            ValueError: If the recomputed hash does not match ``canonicalHash``.
        """
        expected = cls.recompute_canonical_hash(
            section_count=inputs["sectionCount"],
            section_lengths=inputs["sectionLengths"],
            section_hashes=inputs["sectionHashes"],
            max_sections=max_sections,
        )
        supplied = str(inputs["canonicalHash"])
        if expected != supplied:
            raise ValueError(
                f"BLAKE3/Poseidon binding mismatch: recomputed canonicalHash "
                f"({expected}) does not match supplied value ({supplied}). "
                f"This means the witness inputs are inconsistent — the circuit "
                f"would reject the proof."
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
    configure.add_argument(
        "--non-existence-merkle-depth", type=int, dest="non_existence_merkle_depth"
    )
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
