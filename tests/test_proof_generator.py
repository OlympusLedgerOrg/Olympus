"""Tests for proofs.proof_generator module."""

import json
from pathlib import Path

import pytest

from proofs.proof_generator import SUPPORTED_CIRCUITS, ProofGenerator, Witness
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
