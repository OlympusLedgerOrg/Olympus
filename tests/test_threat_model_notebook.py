"""Regression checks for the threat model walkthrough notebook."""

from __future__ import annotations

import json
from pathlib import Path


NOTEBOOK_PATH = Path(__file__).parent.parent / "docs" / "threat_model_walkthrough.ipynb"


def test_threat_model_notebook_exists_and_has_expected_sections():
    """Threat model notebook should cover protections, non-goals, and attack scenarios."""
    notebook = json.loads(NOTEBOOK_PATH.read_text(encoding="utf-8"))

    assert notebook["nbformat"] == 4
    assert notebook["cells"]

    combined_source = "\n".join(
        "".join(cell.get("source", []))
        for cell in notebook["cells"]
    )
    assert "what Olympus **protects**" in combined_source
    assert "does not protect" in combined_source
    assert "Attack scenarios" in combined_source
    assert "Selective withholding before commitment" in combined_source
    assert "classify_event" in combined_source
