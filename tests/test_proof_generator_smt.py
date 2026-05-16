"""Tests for ProofGenerator PoseidonSMT witness helpers."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from proofs import proof_generator as proof_generator_mod
from proofs.proof_generator import CircuitConfig, ProofGenerator
from protocol.hashes import SNARK_SCALAR_FIELD, blake3_hash
from protocol.poseidon_smt import PoseidonSMT, key_to_smt_bytes
from protocol.poseidon_tree import (
    POSEIDON_DOMAIN_COMMITMENT,
    PoseidonMerkleTree,
    poseidon_hash_with_domain,
)


def test_witness_from_smt_roundtrip() -> None:
    """witness_from_smt produces a valid snarkjs input dict."""
    smt = PoseidonSMT()
    key1 = key_to_smt_bytes(blake3_hash([b"key1"]))
    key2 = key_to_smt_bytes(blake3_hash([b"key2"]))
    val1 = int.from_bytes(blake3_hash([b"val1"]), byteorder="big")
    val2 = int.from_bytes(blake3_hash([b"val2"]), byteorder="big")
    smt.update(key1, val1)
    smt.update(key2, val2)

    key_absent = key_to_smt_bytes(blake3_hash([b"not_here"]))
    witness = ProofGenerator.witness_from_smt(smt, key_absent)
    inp = witness.inputs

    assert inp["root"] == str(smt.get_root())
    assert inp["key"] == list(key_absent)
    assert len(inp["pathElements"]) == 256


def test_witness_from_smt_raises_for_present_key() -> None:
    smt = PoseidonSMT()
    key1 = key_to_smt_bytes(blake3_hash([b"key1"]))
    smt.update(key1, int.from_bytes(blake3_hash([b"val1"]), byteorder="big"))

    with pytest.raises(ValueError):
        ProofGenerator.witness_from_smt(smt, key1)


def test_no_placeholder_string_in_proof_generator() -> None:
    """Regression: the literal placeholder must be removed from the module."""
    from proofs import proof_generator as pg_mod

    src = inspect.getsource(pg_mod)
    assert "<poseidon_smt_root_as_field_element>" not in src, (
        "Placeholder string still present in proof_generator.py"
    )


# ---------------------------------------------------------------------------
# witness_from_redaction tests
# ---------------------------------------------------------------------------


def _make_redaction_tree(leaves: list[int], depth: int) -> PoseidonMerkleTree:
    """Build a PoseidonMerkleTree padded to 2**depth leaves."""
    return PoseidonMerkleTree(leaves, depth=depth)


def _expected_commitment(raw_leaves: list[int], reveal_mask: list[int]) -> str:
    """Recompute the domain-separated Poseidon commitment chain from Python."""
    max_leaves = len(raw_leaves)
    revealed = [(raw_leaves[i] * reveal_mask[i]) % SNARK_SCALAR_FIELD for i in range(max_leaves)]
    revealed_count = sum(reveal_mask)
    acc = poseidon_hash_with_domain(revealed_count, revealed[0], POSEIDON_DOMAIN_COMMITMENT)
    for k in range(1, max_leaves):
        acc = poseidon_hash_with_domain(acc, revealed[k], POSEIDON_DOMAIN_COMMITMENT)
    return str(acc % SNARK_SCALAR_FIELD)


class TestWitnessFromRedaction:
    """Tests for ProofGenerator.witness_from_redaction."""

    @pytest.fixture(autouse=True)
    def _empty_build_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(proof_generator_mod, "_BUILD_DIR", tmp_path / "build")

    def _config(self) -> CircuitConfig:
        # Use a small 4-leaf config so tests don't need 64-element masks.
        # The default changed from 4 → 64 leaves; keep tests self-contained.
        import dataclasses

        return dataclasses.replace(
            CircuitConfig.default(),
            redaction_max_leaves=4,
            redaction_merkle_depth=2,
        )

    def test_roundtrip_all_revealed(self) -> None:
        """All-revealed mask produces correct circuit inputs."""
        cfg = self._config()
        leaves = [10, 20, 30, 40]
        tree = _make_redaction_tree(leaves, cfg.redaction_merkle_depth)
        mask = [1, 1, 1, 1]

        witness = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        inp = witness.inputs

        assert witness.circuit == "redaction_validity"
        assert inp["originalRoot"] == tree.get_root()
        assert inp["revealedCount"] == str(sum(mask))
        assert len(inp["originalLeaves"]) == cfg.redaction_max_leaves
        assert len(inp["revealMask"]) == cfg.redaction_max_leaves
        assert len(inp["pathElements"]) == cfg.redaction_max_leaves
        assert len(inp["pathIndices"]) == cfg.redaction_max_leaves

    def test_roundtrip_partial_redaction(self) -> None:
        """Partial mask produces correct commitment and input structure."""
        cfg = self._config()
        leaves = [111, 222, 333, 444]
        tree = _make_redaction_tree(leaves, cfg.redaction_merkle_depth)
        mask = [1, 0, 1, 0]  # reveal leaves 0 and 2

        witness = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        inp = witness.inputs

        raw = [v % SNARK_SCALAR_FIELD for v in tree.leaves]
        expected_commitment = _expected_commitment(raw, mask)

        assert inp["redactedCommitment"] == expected_commitment
        assert inp["revealedCount"] == "2"
        assert inp["revealMask"] == [1, 0, 1, 0]

    def test_roundtrip_all_redacted(self) -> None:
        """All-redacted mask produces commitment over all-zero revealed leaves."""
        cfg = self._config()
        leaves = [5, 6, 7, 8]
        tree = _make_redaction_tree(leaves, cfg.redaction_merkle_depth)
        mask = [0, 0, 0, 0]

        witness = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        inp = witness.inputs

        assert inp["revealedCount"] == "0"
        raw = [v % SNARK_SCALAR_FIELD for v in tree.leaves]
        assert inp["redactedCommitment"] == _expected_commitment(raw, mask)

    def test_path_elements_shape(self) -> None:
        """pathElements and pathIndices are correctly shaped [maxLeaves][depth]."""
        cfg = self._config()
        depth = cfg.redaction_merkle_depth
        leaves = [1, 2, 3, 4]
        tree = _make_redaction_tree(leaves, depth)
        mask = [1, 1, 0, 0]

        inp = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg).inputs

        for i in range(cfg.redaction_max_leaves):
            assert len(inp["pathElements"][i]) == depth, f"pathElements[{i}] has wrong length"
            assert len(inp["pathIndices"][i]) == depth, f"pathIndices[{i}] has wrong length"

    def test_path_indices_bind_to_position(self) -> None:
        """pathIndices[i] must reconstruct leaf index i (LSB-first)."""
        cfg = self._config()
        depth = cfg.redaction_merkle_depth
        tree = _make_redaction_tree([10, 20, 30, 40], depth)
        mask = [1, 1, 1, 1]

        inp = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg).inputs

        for i in range(cfg.redaction_max_leaves):
            reconstructed = sum(inp["pathIndices"][i][b] * (1 << b) for b in range(depth))
            assert reconstructed == i, (
                f"pathIndices[{i}] reconstructs {reconstructed}, expected {i}"
            )

    def test_wrong_mask_length_raises(self) -> None:
        cfg = self._config()
        tree = _make_redaction_tree([1, 2, 3, 4], cfg.redaction_merkle_depth)
        with pytest.raises(ValueError, match="reveal_mask length"):
            ProofGenerator.witness_from_redaction(tree, [1, 0], circuit_config=cfg)

    def test_invalid_mask_value_raises(self) -> None:
        cfg = self._config()
        tree = _make_redaction_tree([1, 2, 3, 4], cfg.redaction_merkle_depth)
        with pytest.raises(ValueError, match="must be 0 or 1"):
            ProofGenerator.witness_from_redaction(tree, [1, 2, 0, 0], circuit_config=cfg)

    def test_wrong_tree_size_raises(self) -> None:
        """A tree not padded to 2**depth raises ValueError."""
        cfg = self._config()
        # Build a 2-leaf tree (not 4 leaves); depth=2 tree should have 4 leaves
        tree = PoseidonMerkleTree([10, 20])
        mask = [1, 1, 0, 0]
        with pytest.raises(ValueError, match="tree has"):
            ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)

    def test_deterministic_output(self) -> None:
        """Same inputs always produce identical witness."""
        cfg = self._config()
        leaves = [9, 8, 7, 6]
        mask = [1, 0, 0, 1]
        tree = _make_redaction_tree(leaves, cfg.redaction_merkle_depth)

        w1 = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        w2 = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        assert w1.inputs == w2.inputs
