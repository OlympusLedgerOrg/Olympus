"""
Tests for the unified olympus CLI.
"""

import json
import subprocess
import sys
from pathlib import Path


CLI_PATH = Path(__file__).parent.parent / "tools" / "olympus.py"


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
