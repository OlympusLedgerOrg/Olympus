"""Tests for proofs.proof_generator module."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from proofs.proof_generator import (
    SUPPORTED_CIRCUITS,
    CircuitConfig,
    ProofGenerator,
    Witness,
    write_circuit_parameters,
)
from protocol.redaction_ledger import VerificationResult, ZKPublicInputs, verify_zk_redaction
from protocol.zkp import ZKProof


# ---------------------------------------------------------------------------
# Witness tests
# ---------------------------------------------------------------------------


class TestWitness:
    def test_to_dict(self):
        w = Witness(circuit="document_existence", inputs={"root": "1", "leaf": "42"})
        d = w.to_dict()
        assert d["circuit"] == "document_existence"
        assert d["inputs"]["root"] == "1"

    def test_witness_path_default_none(self):
        w = Witness(circuit="document_existence", inputs={})
        assert w.witness_path is None


# ---------------------------------------------------------------------------
# ProofGenerator construction
# ---------------------------------------------------------------------------


class TestProofGeneratorInit:
    def test_supported_circuit(self):
        gen = ProofGenerator("document_existence")
        assert gen.circuit == "document_existence"

    def test_unsupported_circuit_raises(self):
        with pytest.raises(ValueError, match="Unsupported circuit"):
            ProofGenerator("invalid_circuit")

    def test_all_supported_circuits(self):
        for circuit in SUPPORTED_CIRCUITS:
            gen = ProofGenerator(circuit)
            assert gen.circuit == circuit

    def test_custom_paths(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            circuits_dir=tmp_path / "circuits",
            build_dir=tmp_path / "build",
            keys_dir=tmp_path / "keys",
        )
        assert gen.circuits_dir == tmp_path / "circuits"
        assert gen.build_dir == tmp_path / "build"
        assert gen.keys_dir == tmp_path / "keys"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_document_existence_missing_inputs(self, tmp_path: Path):
        gen = ProofGenerator("document_existence", build_dir=tmp_path)
        with pytest.raises(ValueError, match="Missing required inputs"):
            gen.generate_witness(root="1")  # missing leaf, leafIndex, etc.

    def test_document_existence_valid_inputs(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            build_dir=tmp_path,
            snarkjs_bin="nonexistent-snarkjs",
        )
        witness = gen.generate_witness(
            root="123",
            leaf="42",
            leafIndex="0",
            treeSize="1048576",
            pathElements=["0"] * 20,
            pathIndices=[0] * 20,
        )
        assert witness.circuit == "document_existence"
        assert witness.inputs["root"] == "123"
        assert witness.inputs["leaf"] == "42"

    def test_non_existence_missing_inputs(self, tmp_path: Path):
        gen = ProofGenerator("non_existence", build_dir=tmp_path)
        with pytest.raises(ValueError, match="Missing required inputs"):
            gen.generate_witness(root="1")

    def test_redaction_validity_missing_inputs(self, tmp_path: Path):
        gen = ProofGenerator("redaction_validity", build_dir=tmp_path)
        with pytest.raises(ValueError, match="Missing required inputs"):
            gen.generate_witness(originalRoot="1")

    def test_redaction_validity_rejects_mismatched_lengths(self, tmp_path: Path):
        gen = ProofGenerator("redaction_validity", build_dir=tmp_path)
        with pytest.raises(ValueError, match="originalLeaves must be a list"):
            gen.generate_witness(
                originalRoot="1",
                redactedCommitment="2",
                revealedCount="1",
                originalLeaves=["1"],
                revealMask=["1"],
                pathElements=[["0"] * 4],
                pathIndices=[["0"] * 4],
            )


# ---------------------------------------------------------------------------
# Witness generation
# ---------------------------------------------------------------------------


class TestWitnessGeneration:
    def test_generates_input_json(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            build_dir=tmp_path,
            snarkjs_bin="nonexistent-snarkjs",
        )
        witness = gen.generate_witness(
            root="123",
            leaf="42",
            leafIndex="0",
            treeSize="1048576",
            pathElements=["0"] * 20,
            pathIndices=[0] * 20,
        )
        input_files = list(tmp_path.glob("document_existence_input_*.json"))
        assert len(input_files) == 1
        data = json.loads(input_files[0].read_text())
        assert data["root"] == "123"
        assert data["leaf"] == "42"
        # No WASM generator available, so witness_path is None
        assert witness.witness_path is None


class TestCircuitConfig:
    def test_from_env_overrides(self, monkeypatch):
        monkeypatch.setenv("OLYMPUS_DOCUMENT_MERKLE_DEPTH", "32")
        monkeypatch.setenv("OLYMPUS_REDACTION_MAX_LEAVES", "32")
        monkeypatch.setenv("OLYMPUS_REDACTION_MERKLE_DEPTH", "5")
        config = CircuitConfig.from_env()
        assert config.document_merkle_depth == 32
        assert config.redaction_max_leaves == 32
        assert config.redaction_merkle_depth == 5

    def test_write_circuit_parameters(self, tmp_path: Path):
        config = CircuitConfig.default()
        output_path = write_circuit_parameters(config, tmp_path / "params.circom")
        text = output_path.read_text(encoding="utf-8")
        assert "DOCUMENT_MERKLE_DEPTH" in text
        assert str(config.document_merkle_depth) in text


# ---------------------------------------------------------------------------
# Prove / verify
# ---------------------------------------------------------------------------


class TestProveAndVerify:
    def test_prove_raises_without_snarkjs(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            build_dir=tmp_path,
            snarkjs_bin="nonexistent-snarkjs",
        )
        witness = Witness(circuit="document_existence", inputs={})
        with pytest.raises(RuntimeError, match="snarkjs binary"):
            gen.prove(witness)

    def test_verify_raises_without_snarkjs(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            build_dir=tmp_path,
            snarkjs_bin="nonexistent-snarkjs",
        )
        proof = ZKProof(proof={}, public_signals=[], circuit="document_existence")
        with pytest.raises(RuntimeError, match="snarkjs binary"):
            gen.verify(proof)

    def test_snarkjs_available_property(self, tmp_path: Path):
        gen = ProofGenerator(
            "document_existence",
            snarkjs_bin="nonexistent-snarkjs",
        )
        assert gen.snarkjs_available is False


def _require_redaction_artifacts() -> tuple[Path, Path]:
    repo_root = Path(__file__).resolve().parent.parent
    build_dir = repo_root / "proofs" / "build"
    vkey_path = repo_root / "proofs" / "keys" / "verification_keys" / "redaction_validity_vkey.json"
    wasm_dir = build_dir / "redaction_validity_js"
    wasm = wasm_dir / "redaction_validity.wasm"
    generator = wasm_dir / "generate_witness.js"
    zkey = build_dir / "redaction_validity_final.zkey"

    missing = [path for path in (wasm, generator, zkey, vkey_path) if not path.exists()]
    if missing:
        pytest.skip(
            f"redaction_validity artifacts missing ({', '.join(str(m) for m in missing)}); "
            "run proofs/setup_circuits.sh to generate them"
        )
    if shutil.which("node") is None or shutil.which("npx") is None:
        pytest.skip("Node.js and npx are required for redaction round-trip integration test")
    return repo_root, build_dir


def test_redaction_validity_round_trip_verification() -> None:
    """
    Generate witness → prove → verify for redaction_validity circuit.

    Ensures the public signal ordering expected by verify_zk_redaction aligns
    with the circuit declaration.
    """
    repo_root, build_dir = _require_redaction_artifacts()
    input_script = repo_root / "proofs" / "test_inputs" / "generate_inputs.js"
    subprocess.run(["node", str(input_script)], check=True, cwd=repo_root)

    input_path = build_dir / "redaction_validity_input.json"
    inputs = json.loads(input_path.read_text())

    gen = ProofGenerator("redaction_validity")
    witness = gen.generate_witness(**inputs)
    assert witness.witness_path is not None

    proof = gen.prove(witness)
    # verify() operates on the ZKProof container
    assert gen.verify(proof, public_inputs=proof.public_signals) is True

    # verify_zk_redaction expects the unpacked Groth16 proof blob + public inputs
    zk_inputs = ZKPublicInputs(
        original_root=inputs["originalRoot"],
        redacted_commitment=inputs["redactedCommitment"],
        revealed_count=int(inputs["revealedCount"]),
    )
    result = verify_zk_redaction(proof.proof, zk_inputs)
    assert result is VerificationResult.VALID
    assert proof.public_signals[:3] == [
        inputs["originalRoot"],
        inputs["redactedCommitment"],
        inputs["revealedCount"],
    ]


# ---------------------------------------------------------------------------
# Export / load proof
# ---------------------------------------------------------------------------


class TestExportLoadProof:
    def test_round_trip(self, tmp_path: Path):
        gen = ProofGenerator("document_existence")
        proof = ZKProof(
            proof={"pi_a": [1, 2], "pi_b": [[3, 4]], "pi_c": [5]},
            public_signals=["42", "0"],
            circuit="document_existence",
        )
        out_path = tmp_path / "proof.json"
        gen.export_proof(proof, out_path)

        loaded = ProofGenerator.load_proof(out_path)
        assert loaded.circuit == proof.circuit
        assert loaded.public_signals == proof.public_signals
        assert loaded.proof == proof.proof


# ---------------------------------------------------------------------------
# Non-existence input validation (new key-based API)
# ---------------------------------------------------------------------------


@pytest.mark.layer4
@pytest.mark.circuits
class TestNonExistenceInputValidation:
    def test_rejects_old_leaf_index_input(self):
        gen = ProofGenerator("non_existence")
        with pytest.raises(ValueError, match="leafIndex"):
            gen._validate_inputs(
                {"root": "1", "key": [0] * 32, "leafIndex": "5", "pathElements": ["0"] * 256}
            )

    def test_rejects_old_path_indices_input(self):
        gen = ProofGenerator("non_existence")
        with pytest.raises(ValueError, match="pathIndices"):
            gen._validate_inputs(
                {
                    "root": "1",
                    "key": [0] * 32,
                    "pathElements": ["0"] * 256,
                    "pathIndices": [0] * 256,
                }
            )

    def test_rejects_key_wrong_length(self):
        gen = ProofGenerator("non_existence")
        with pytest.raises(ValueError, match="32"):
            gen._validate_inputs({"root": "1", "key": [0] * 31, "pathElements": ["0"] * 256})

    def test_rejects_key_byte_out_of_range(self):
        gen = ProofGenerator("non_existence")
        bad_key = [0] * 32
        bad_key[5] = 256  # out of range
        with pytest.raises(ValueError, match=r"key\[5\]"):
            gen._validate_inputs({"root": "1", "key": bad_key, "pathElements": ["0"] * 256})

    def test_accepts_valid_non_existence_inputs(self):
        gen = ProofGenerator("non_existence")
        # Should not raise
        gen._validate_inputs(
            {
                "root": "12345",
                "key": list(range(32)),
                "pathElements": ["0"] * 256,
            }
        )


# ---------------------------------------------------------------------------
# BLAKE3/Poseidon canonical-hash binding (Finding #11/#12)
# ---------------------------------------------------------------------------


class TestCanonicalHashBinding:
    """Verify that recompute_canonical_hash matches the circuit's Poseidon chain."""

    @staticmethod
    def _build_unified_inputs(
        section_count: int,
        section_lengths: list[int],
        section_hashes: list[int],
        canonical_hash: str,
        max_sections: int = 8,
    ) -> dict:
        """Helper to build a minimal valid unified circuit input dict."""
        config = CircuitConfig.default()
        return {
            "canonicalHash": canonical_hash,
            "merkleRoot": "0",
            "ledgerRoot": "0",
            "treeSize": "0",
            "documentSections": ["0"] * config.unified_max_sections,
            "sectionCount": str(section_count),
            "sectionLengths": [str(v) for v in section_lengths]
                + ["0"] * (config.unified_max_sections - len(section_lengths)),
            "sectionHashes": [str(v) for v in section_hashes]
                + ["0"] * (config.unified_max_sections - len(section_hashes)),
            "merklePath": ["0"] * config.unified_merkle_depth,
            "merkleIndices": [0] * config.unified_merkle_depth,
            "leafIndex": "0",
            "ledgerPathElements": ["0"] * config.unified_smt_depth,
            "ledgerPathIndices": [0] * config.unified_smt_depth,
        }

    def test_recompute_canonical_hash_deterministic(self):
        """Same inputs always produce the same canonical hash."""
        config = CircuitConfig.default()
        h1 = ProofGenerator.recompute_canonical_hash(
            section_count=2,
            section_lengths=[100, 200] + [0] * (config.unified_max_sections - 2),
            section_hashes=[42, 99] + [0] * (config.unified_max_sections - 2),
            max_sections=config.unified_max_sections,
        )
        h2 = ProofGenerator.recompute_canonical_hash(
            section_count=2,
            section_lengths=[100, 200] + [0] * (config.unified_max_sections - 2),
            section_hashes=[42, 99] + [0] * (config.unified_max_sections - 2),
            max_sections=config.unified_max_sections,
        )
        assert h1 == h2

    def test_recompute_changes_with_different_section_count(self):
        """Different sectionCount → different canonical hash."""
        config = CircuitConfig.default()
        lengths = [100] + [0] * (config.unified_max_sections - 1)
        hashes = [42] + [0] * (config.unified_max_sections - 1)
        h1 = ProofGenerator.recompute_canonical_hash(1, lengths, hashes, config.unified_max_sections)
        h2 = ProofGenerator.recompute_canonical_hash(2, lengths, hashes, config.unified_max_sections)
        assert h1 != h2

    def test_recompute_changes_with_different_section_hashes(self):
        """Different sectionHashes → different canonical hash."""
        config = CircuitConfig.default()
        lengths = [100] + [0] * (config.unified_max_sections - 1)
        h1 = ProofGenerator.recompute_canonical_hash(
            1, lengths, [42] + [0] * (config.unified_max_sections - 1), config.unified_max_sections
        )
        h2 = ProofGenerator.recompute_canonical_hash(
            1, lengths, [99] + [0] * (config.unified_max_sections - 1), config.unified_max_sections
        )
        assert h1 != h2

    def test_validate_rejects_mismatched_canonical_hash(self):
        """Mismatched canonicalHash must raise ValueError."""
        config = CircuitConfig.default()
        inputs = self._build_unified_inputs(
            section_count=1,
            section_lengths=[100],
            section_hashes=[42],
            canonical_hash="9999999999999999",  # wrong value
        )
        gen = ProofGenerator("unified_canonicalization_inclusion_root_sign")
        with pytest.raises(ValueError, match="BLAKE3/Poseidon binding mismatch"):
            gen._validate_inputs(inputs)

    def test_validate_accepts_correct_canonical_hash(self):
        """Correctly computed canonicalHash must pass validation."""
        config = CircuitConfig.default()
        # Compute the correct hash first
        lengths = [100] + [0] * (config.unified_max_sections - 1)
        hashes = [42] + [0] * (config.unified_max_sections - 1)
        correct = ProofGenerator.recompute_canonical_hash(
            1, lengths, hashes, config.unified_max_sections
        )
        inputs = self._build_unified_inputs(
            section_count=1,
            section_lengths=[100],
            section_hashes=[42],
            canonical_hash=correct,
        )
        gen = ProofGenerator("unified_canonicalization_inclusion_root_sign")
        # Should not raise
        gen._validate_inputs(inputs)
