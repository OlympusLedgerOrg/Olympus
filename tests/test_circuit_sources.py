"""Regression checks for circuit source-level semantics."""

from pathlib import Path


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
