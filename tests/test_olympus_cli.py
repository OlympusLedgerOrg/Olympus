"""
Tests for the unified olympus CLI.
"""

import json
import subprocess
import sys
from pathlib import Path


CLI_PATH = Path(__file__).parent.parent / "tools" / "olympus.py"
REGISTRY_PATH = Path(__file__).parent.parent / "examples" / "federation_registry.json"


def test_olympus_canon_outputs_canonical_json(tmp_path):
    """olympus canon normalizes whitespace and preserves deterministic output."""
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"body": "Hello  world", "title": "Example"}))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "canon", str(input_file), "--format", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    canonical = json.loads(result.stdout)
    assert canonical["body"] == "Hello world"


def test_olympus_node_list_outputs_registry_nodes() -> None:
    """olympus node list should print the static federation registry."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "node", "list", "--registry", str(REGISTRY_PATH)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "olympus-node-1" in result.stdout
    assert "City Records Office" in result.stdout
    assert "https://node3.olympus.org" in result.stdout


def test_olympus_federation_status_reports_counts_without_live_nodes() -> None:
    """olympus federation status should report registry counts even without live endpoints."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "federation", "status", "--registry", str(REGISTRY_PATH)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Federation Status" in result.stdout
    assert "Nodes: 3" in result.stdout
    assert "Active: 3" in result.stdout
    assert "Quorum: 2" in result.stdout
