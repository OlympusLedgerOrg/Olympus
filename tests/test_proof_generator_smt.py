"""Tests for ProofGenerator PoseidonSMT witness helpers."""

from __future__ import annotations

import inspect

import pytest

from proofs.proof_generator import CircuitConfig, ProofGenerator
from protocol.hashes import SNARK_SCALAR_FIELD, blake3_hash
from protocol.poseidon_smt import PoseidonSMT, key_to_smt_bytes
from protocol.poseidon_tree import (
    POSEIDON_DOMAIN_COMMITMENT,
    PoseidonMerkleTree,
    compute_redaction_commitments,
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

    def _config(self) -> CircuitConfig:
        # Use a small 4-leaf config so tests don't need 64-element masks.
        # The default changed from 4 → 64 leaves; keep tests self-contained.
        import dataclasses

        return dataclasses.replace(
            CircuitConfig.default(),
            redaction_max_leaves=4,
            redaction_merkle_depth=2,  # 2**2 == 4 leaves; must be log2(redaction_max_leaves)
        )

    @pytest.mark.layer4
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

    @pytest.mark.layer4
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

    @pytest.mark.layer4
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

    @pytest.mark.layer4
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

    @pytest.mark.layer4
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

    @pytest.mark.layer4
    def test_deterministic_output(self) -> None:
        """Same inputs always produce identical witness."""
        cfg = self._config()
        leaves = [9, 8, 7, 6]
        mask = [1, 0, 0, 1]
        tree = _make_redaction_tree(leaves, cfg.redaction_merkle_depth)

        w1 = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        w2 = ProofGenerator.witness_from_redaction(tree, mask, circuit_config=cfg)
        assert w1.inputs == w2.inputs


# ---------------------------------------------------------------------------
# Pure-Python commitment tests (no WASM / Node.js required).
# These verify that compute_redaction_commitments agrees with the circuit
# definition and with witness_from_redaction — catching Bug #2 where spurious
# position binding was added to poseidon_tree.py but not to the circuit.
# ---------------------------------------------------------------------------


class TestComputeRedactionCommitments:
    """compute_redaction_commitments must mirror the circuit (no position binding)."""

    def _leaves(self, values: list[int]) -> list[int]:
        """Reduce raw ints into the scalar field."""
        return [v % SNARK_SCALAR_FIELD for v in values]

    def test_matches_expected_commitment_partial(self) -> None:
        """compute_redaction_commitments == _expected_commitment for partial mask."""
        leaves = self._leaves([111, 222, 333, 444])
        mask = [1, 0, 1, 0]
        redacted_commitment, _ = compute_redaction_commitments(leaves, mask, sum(mask))
        assert redacted_commitment == _expected_commitment(leaves, mask)

    def test_matches_expected_commitment_all_revealed(self) -> None:
        leaves = self._leaves([10, 20, 30, 40])
        mask = [1, 1, 1, 1]
        redacted_commitment, _ = compute_redaction_commitments(leaves, mask, sum(mask))
        assert redacted_commitment == _expected_commitment(leaves, mask)

    def test_matches_expected_commitment_all_redacted(self) -> None:
        leaves = self._leaves([5, 6, 7, 8])
        mask = [0, 0, 0, 0]
        redacted_commitment, _ = compute_redaction_commitments(leaves, mask, 0)
        assert redacted_commitment == _expected_commitment(leaves, mask)

    def test_matches_witness_commitment_formula(self) -> None:
        """compute_redaction_commitments must produce the same redactedCommitment
        as witness_from_redaction's internal formula so the stored API value and
        the ZK witness agree.

        Regression test for the position-binding bug where compute_redaction_commitments
        applied poseidon_hash_bn128(i, masked[i]) before the commitment chain while the
        circuit (and witness_from_redaction) use revealedLeaves[i] = mask[i]*leaf[i] directly.

        This test replicates the witness formula without running WASM so it passes in
        the unit CI lane.
        """
        # Replicate witness_from_redaction's commitment formula exactly
        # (redaction_validity.circom lines 123, 136-148):
        #   revealedLeaves[i] = revealMask[i] * originalLeaves[i]
        #   acc[0] = DomainPoseidon(3)(revealedCount, revealedLeaves[0])
        #   acc[k] = DomainPoseidon(3)(acc[k-1], revealedLeaves[k])
        leaves = self._leaves([111, 222, 333, 444])
        mask = [1, 0, 1, 0]
        F = SNARK_SCALAR_FIELD

        revealed = [(mask[i] * leaves[i]) % F for i in range(len(leaves))]
        revealed_count = sum(mask)
        expected = poseidon_hash_with_domain(
            revealed_count, revealed[0], POSEIDON_DOMAIN_COMMITMENT
        )
        for k in range(1, len(leaves)):
            expected = poseidon_hash_with_domain(expected, revealed[k], POSEIDON_DOMAIN_COMMITMENT)
        expected_str = str(expected % F)

        api_commitment, _ = compute_redaction_commitments(leaves, mask, revealed_count)

        assert api_commitment == expected_str, (
            "compute_redaction_commitments diverges from the circuit formula — "
            "the stored API value will not match the ZK circuit's commitment"
        )

    def test_deterministic(self) -> None:
        """Same inputs always produce the same commitments."""
        leaves = self._leaves([9, 8, 7, 6])
        mask = [1, 0, 0, 1]
        r1, m1 = compute_redaction_commitments(leaves, mask, sum(mask))
        r2, m2 = compute_redaction_commitments(leaves, mask, sum(mask))
        assert r1 == r2
        assert m1 == m2

    def test_different_masks_produce_different_commitments(self) -> None:
        leaves = self._leaves([100, 200, 300, 400])
        r_partial, _ = compute_redaction_commitments(leaves, [1, 0, 1, 0], 2)
        r_full, _ = compute_redaction_commitments(leaves, [1, 1, 1, 1], 4)
        assert r_partial != r_full

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_redaction_commitments([], [], 0)

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_redaction_commitments([1, 2, 3], [1, 0], 1)
