"""Regression checks for the explanatory notebooks in examples/."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"


def extract_notebook_sources(data: dict) -> str:
    """Return the concatenated source text from every notebook cell."""
    return "\n".join("".join(cell.get("source", [])) for cell in data["cells"])


def extract_notebook_outputs(data: dict) -> str:
    """Return concatenated stream output text from every notebook code cell."""
    return "\n".join(
        "".join(output.get("text", []))
        for cell in data["cells"]
        for output in cell.get("outputs", [])
        if output.get("output_type") == "stream"
    )


@pytest.mark.parametrize(
    ("name", "required_strings", "required_output"),
    [
        (
            "poseidon_deep_dive.ipynb",
            [
                "protocol/poseidon_bn128.py",
                "Poseidon(1, 2)",
                "reference_vectors",
                "_M",
            ],
            "Poseidon(1, 2) => expected 7853200120776062878684798364095072458815029376092732009249414926327459813530",
        ),
        (
            "zk_proof_lifecycle.ipynb",
            [
                "verify_zk_redaction",
                "RedactionProtocol.commit_document",
                "commit_document_dual",
                "verify_smt_anchor",
            ],
            "verify_zk_redaction(...) => True",
        ),
        (
            "smt_explainer.ipynb",
            [
                "SparseMerkleTree",
                "prove_existence",
                "prove_nonexistence",
                "256-level sparse Merkle tree",
            ],
            "Inclusion proof path for 1010",
        ),
        (
            "groth16_verify_walkthrough.ipynb",
            [
                "Groth16Prover.verify",
                "snarkjs groth16 verify",
                "document_existence_vkey.json",
                "pairing equation",
            ],
            "snarkjs command:",
        ),
    ],
)
def test_explanatory_notebook_exists_and_contains_expected_walkthrough(
    name: str,
    required_strings: list[str],
    required_output: str,
) -> None:
    """Each explanatory notebook should exist, be valid JSON, and retain key walkthrough content."""
    notebook_path = EXAMPLES_DIR / name
    assert notebook_path.exists(), f"Missing notebook: {notebook_path}"

    data = json.loads(notebook_path.read_text(encoding="utf-8"))
    assert data["nbformat"] == 4
    assert data["cells"], f"Notebook {name} has no cells"

    sources = extract_notebook_sources(data)
    outputs = extract_notebook_outputs(data)

    for text in required_strings:
        assert text in sources, f"Notebook {name} is missing walkthrough text: {text!r}"
    assert required_output in outputs, (
        f"Notebook {name} is missing saved output: {required_output!r}"
    )
