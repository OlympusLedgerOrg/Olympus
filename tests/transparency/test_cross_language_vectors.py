from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from verifiers.python.witness_cosignature import verify_witness_envelope


def _run(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise AssertionError(
            f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )


def test_witness_cosigned_vector_acceptance_cross_language() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    vector = repo_root / "tests" / "golden" / "witness_cosignature" / "envelope_v1.json"

    assert verify_witness_envelope(vector)

    _run(["go", "run", "./cmd/verify_witness", str(vector)], repo_root / "verifiers" / "go")
    _run(["node", "witness_cosignature.mjs", str(vector)], repo_root / "verifiers" / "js")
    _run(
        ["cargo", "run", "--quiet", "--bin", "verify_witness", "--", str(vector)],
        repo_root / "verifiers" / "rust",
    )
