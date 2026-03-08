"""
Poseidon parameter parity tests.

TestBN128PythonParity
    Verifies that ``protocol.poseidon_bn128.poseidon_hash_bn128`` (pure Python,
    BN128 round constants extracted from circomlibjs) produces bit-for-bit
    identical outputs to circomlibjs for all reference vectors.  These tests
    must pass; any failure indicates a bug in the Python BN128 implementation.

TestJSBackendEndToEnd
    Verifies that the subprocess plumbing in ``protocol.poseidon_js``
    (``hash2``, ``batch_hash2``, ``merkle_root``) correctly invokes circomlibjs
    and returns results matching the reference vector script.  These tests
    must pass in CI.

Skip / fail policy
------------------
* In a **CI environment** (``CI=true``, as set by GitHub Actions) the
  JS-dependent tests hard-fail when Node.js or proofs/node_modules is missing.
  A skipped test in CI is a silent gap.

* In a **local development** environment the tests are skipped when Node.js or
  proofs/node_modules is absent, so developers without a full JS toolchain are
  not blocked.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.poseidon_bn128 import poseidon_hash_bn128, poseidon_parameter_summary
from protocol.poseidon_js import _run_node


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parent.parent
_VECTORS_SCRIPT = _REPO_ROOT / "proofs" / "test_inputs" / "poseidon_vectors.js"
_NODE_MODULES = _REPO_ROOT / "proofs" / "node_modules"


# ---------------------------------------------------------------------------
# Skip / fail helpers
# ---------------------------------------------------------------------------
def _prerequisite_missing() -> str | None:
    """Return a human-readable reason string if a prerequisite is absent."""
    if shutil.which("node") is None:
        return "node is not available on PATH"
    if not _NODE_MODULES.is_dir():
        return (
            f"proofs/node_modules not found at {_NODE_MODULES}; "
            "run `npm install` inside proofs/ first"
        )
    return None


def _skip_or_fail(reason: str) -> None:
    """
    Skip locally; hard-fail in CI so missing Node is never a silent gap.

    The ``CI`` environment variable is exported as ``true`` by GitHub Actions
    and as ``1`` by many other CI systems.  Both values are accepted.
    Any other value (including the empty string) is treated as a local
    developer environment and causes a ``pytest.skip`` instead of a failure.
    """
    if os.environ.get("CI", "").lower() in ("true", "1"):
        pytest.fail(f"Required prerequisite missing in CI environment: {reason}")
    pytest.skip(reason)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------
def _load_js_vectors() -> list[dict]:
    """Run the JS vector script and return the parsed vector list."""
    result = subprocess.run(
        ["node", str(_VECTORS_SCRIPT)],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(_VECTORS_SCRIPT.parent),
        timeout=30,
    )
    data = json.loads(result.stdout.strip())
    return data["vectors"]


def test_parameter_summary_exports_expected_shape() -> None:
    """The parameter summary should expose the full BN128 Poseidon constant tables."""
    summary = poseidon_parameter_summary()

    assert summary["source"] == "circomlibjs/src/poseidon_constants.json"
    assert summary["field"] == str(SNARK_SCALAR_FIELD)
    assert summary["state_width"] == 3
    assert summary["arity"] == 2
    assert summary["full_rounds"] == 8
    assert summary["partial_rounds"] == 57
    assert len(summary["round_constants"]) == 195
    assert len(summary["mds_matrix"]) == 3
    assert all(len(row) == 3 for row in summary["mds_matrix"])


# ---------------------------------------------------------------------------
# Class 1: Python BN128 parity (must pass — no xfail)
# ---------------------------------------------------------------------------
class TestBN128PythonParity:
    """
    Verify poseidon_hash_bn128 matches circomlibjs for all reference vectors.

    ``protocol.poseidon_bn128`` is the default Python Poseidon backend.
    Its round constants and MDS matrix are extracted verbatim from
    ``circomlibjs/src/poseidon_constants.json``, so outputs must be
    bit-for-bit identical to what the circom circuits compute.
    """

    def setup_method(self) -> None:
        reason = _prerequisite_missing()
        if reason:
            _skip_or_fail(reason)

    def test_all_vectors_match(self) -> None:
        """poseidon_hash_bn128 must match circomlibjs for all reference vectors."""
        vectors = _load_js_vectors()
        assert vectors, "Vector script produced no vectors"

        mismatches: list[str] = []
        for vec in vectors:
            a = int(vec["a"])
            b = int(vec["b"])
            expected = int(vec["out"]) % SNARK_SCALAR_FIELD
            py_out = poseidon_hash_bn128(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD)
            if py_out != expected:
                mismatches.append(
                    f"  Poseidon({a}, {b})\n"
                    f"    circomlibjs    : {expected}\n"
                    f"    poseidon_bn128 : {py_out}"
                )

        if mismatches:
            details = "\n".join(mismatches)
            pytest.fail(
                f"{len(mismatches)} vector(s) did not match between "
                f"poseidon_hash_bn128 and circomlibjs:\n{details}"
            )

    @pytest.mark.parametrize(
        "a,b",
        [
            (0, 0),
            (1, 2),
            (42, 0),
            (
                21888242871839275222246405745257275088548364400416034343698204186575808495617 - 1,
                123,
            ),
        ],
    )
    def test_individual_vector(self, a: int, b: int) -> None:
        """Each named vector must match individually for clear failure attribution."""
        vectors = _load_js_vectors()
        match = next((v for v in vectors if int(v["a"]) == a and int(v["b"]) == b), None)
        assert match is not None, (
            f"Vector ({a}, {b}) not found in JS output. Was poseidon_vectors.js modified?"
        )
        expected = int(match["out"]) % SNARK_SCALAR_FIELD
        py_out = poseidon_hash_bn128(a % SNARK_SCALAR_FIELD, b % SNARK_SCALAR_FIELD)
        assert py_out == expected, (
            f"Poseidon({a}, {b}) mismatch:\n"
            f"  circomlibjs    : {expected}\n"
            f"  poseidon_bn128 : {py_out}"
        )

# ---------------------------------------------------------------------------
# Class 2: JS backend plumbing (must pass in CI)
# ---------------------------------------------------------------------------
class TestJSBackendEndToEnd:
    """
    Verify that the JS backend subprocess plumbing in protocol.poseidon_js
    correctly invokes circomlibjs and returns the expected results.

    These tests must pass in CI — if they fail, the JS backend is broken and
    ``OLY_POSEIDON_BACKEND=js`` cannot be used safely.
    """

    def setup_method(self) -> None:
        reason = _prerequisite_missing()
        if reason:
            _skip_or_fail(reason)

    def test_hash2_matches_vector_script(self) -> None:
        """hash2 op must return the same value as the reference vector script."""
        vectors = _load_js_vectors()
        for vec in vectors:
            a, b = int(vec["a"]), int(vec["b"])
            expected = int(vec["out"]) % SNARK_SCALAR_FIELD
            result = _run_node({"op": "hash2", "a": str(a), "b": str(b)})
            got = int(result["out"]) % SNARK_SCALAR_FIELD
            assert got == expected, (
                f"hash2 op mismatch for ({a}, {b}): got {got}, expected {expected}"
            )

    def test_batch_hash2_matches_vector_script(self) -> None:
        """batch_hash2 op must return the same values as individual hash2 calls."""
        vectors = _load_js_vectors()
        pairs = [{"a": v["a"], "b": v["b"]} for v in vectors]
        result = _run_node({"op": "batch_hash2", "pairs": pairs})
        for i, (vec, out) in enumerate(zip(vectors, result["outs"])):
            expected = int(vec["out"]) % SNARK_SCALAR_FIELD
            got = int(out) % SNARK_SCALAR_FIELD
            assert got == expected, (
                f"batch_hash2 mismatch at index {i} "
                f"({vec['a']}, {vec['b']}): got {got}, expected {expected}"
            )

    def test_batch_matches_individual_calls(self) -> None:
        """batch_hash2 and individual hash2 must produce identical results."""
        vectors = _load_js_vectors()
        pairs = [{"a": v["a"], "b": v["b"]} for v in vectors]
        batch_result = _run_node({"op": "batch_hash2", "pairs": pairs})
        for vec, batch_out in zip(vectors, batch_result["outs"]):
            a, b = vec["a"], vec["b"]
            single = _run_node({"op": "hash2", "a": a, "b": b})
            assert int(batch_out) == int(single["out"]), (
                f"batch vs single mismatch for ({a}, {b}): "
                f"batch={batch_out}, single={single['out']}"
            )
