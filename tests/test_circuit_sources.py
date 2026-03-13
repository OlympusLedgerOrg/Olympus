"""Regression checks for circuit source-level semantics."""

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _template_block(source: str, template_name: str) -> str:
    marker = f"template {template_name}("
    start = source.index(marker)
    next_template = source.find("template ", start + len(marker))
    if next_template == -1:
        return source[start:]
    return source[start:next_template]


def test_merkle_tree_inclusion_reuses_merkle_proof_template() -> None:
    source = (REPO_ROOT / "proofs" / "circuits" / "lib" / "merkleProof.circom").read_text(
        encoding="utf-8"
    )
    inclusion_template = _template_block(source, "MerkleTreeInclusionProof")

    assert "component proof = MerkleProof(levels);" in inclusion_template
    assert "root === proof.root;" in inclusion_template
    assert "hashers[i] = Poseidon(2);" not in inclusion_template


def test_redaction_validity_uses_bit_weights_and_zero_padding() -> None:
    source = (REPO_ROOT / "proofs" / "circuits" / "redaction_validity.circom").read_text(
        encoding="utf-8"
    )

    assert "var bitWeight = 1 << b;" in source
    assert "idxAccum[b + 1] <== idxAccum[b] + pathIndices[i][b] * bitWeight;" in source
    assert "revealedLeaves[i] <== revealMask[i] * originalLeaves[i];" in source
    assert "zero-pad the commitment chain" in source


# ---------------------------------------------------------------------------
# B1: IsZero hardening — treeSizeInv replaced in document_existence + unified
# ---------------------------------------------------------------------------


@pytest.mark.layer4
@pytest.mark.circuits
class TestB1IsZeroHardening:
    def test_no_unconstrained_treesize_inv_in_document_existence(self):
        src = (REPO_ROOT / "proofs" / "circuits" / "document_existence.circom").read_text()
        assert "treeSizeInv" not in src, "treeSizeInv unconstrained hint still present"
        assert "IsZero" in src, "IsZero gadget not found — fix not applied"

    def test_no_unconstrained_treesize_inv_in_unified(self):
        src = (
            REPO_ROOT
            / "proofs"
            / "circuits"
            / "unified_canonicalization_inclusion_root_sign.circom"
        ).read_text()
        assert "treeSizeInv" not in src
        assert "IsZero" in src

    def test_iszero_import_present_in_document_existence(self):
        src = (REPO_ROOT / "proofs" / "circuits" / "document_existence.circom").read_text()
        assert "iszero.circom" in src

    def test_iszero_import_present_in_unified(self):
        src = (
            REPO_ROOT
            / "proofs"
            / "circuits"
            / "unified_canonicalization_inclusion_root_sign.circom"
        ).read_text()
        assert "iszero.circom" in src


# ---------------------------------------------------------------------------
# B5: Non-existence circuit — key-based design
# ---------------------------------------------------------------------------


@pytest.mark.layer4
@pytest.mark.circuits
class TestB5NonExistenceKeyBased:
    def test_non_existence_uses_key_not_leaf_index(self):
        src = (REPO_ROOT / "proofs" / "circuits" / "non_existence.circom").read_text()
        assert "signal input key[32]" in src, "key[32] input not found"
        assert "signal input leafIndex" not in src, "old leafIndex input still present"
        assert "signal input treeSize" not in src, "treeSize removed for SMT design"

    def test_non_existence_path_derivation_is_internal(self):
        src = (REPO_ROOT / "proofs" / "circuits" / "non_existence.circom").read_text()
        assert "signal input pathIndices" not in src, \
            "pathIndices must be internal (derived from key), not a prover input"
        assert "signal pathIndices" in src, "internal pathIndices signal not found"

    def test_non_existence_msb_first_bit_ordering(self):
        # Verify the circuit comment documents MSB-first and references ssmf.py.
        src = (REPO_ROOT / "proofs" / "circuits" / "non_existence.circom").read_text()
        assert "MSB" in src, "MSB-first ordering not documented in circuit"
        assert "ssmf.py" in src or "_key_to_path_bits" in src, \
            "Circuit must reference ssmf.py to make the bit-ordering contract explicit"

    def test_non_existence_depth_is_256(self):
        src = (REPO_ROOT / "proofs" / "circuits" / "parameters.circom").read_text()
        assert "NON_EXISTENCE_MERKLE_DEPTH = 256" in src, \
            "NON_EXISTENCE_MERKLE_DEPTH must be 256 for a 256-bit sparse Merkle tree"

    def test_non_existence_iszero_still_not_needed(self):
        # The new design removes treeSize entirely so there is no treeSizeIsPositive
        # to worry about. Verify treeSizeInv is gone.
        src = (REPO_ROOT / "proofs" / "circuits" / "non_existence.circom").read_text()
        assert "treeSizeInv" not in src
        assert "<-- (treeSize" not in src
