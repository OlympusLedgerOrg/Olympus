"""Cross-implementation differential fuzzing tests.

Uses Hypothesis to generate random inputs and verifies that all Olympus
verifier implementations (Python, Go, Rust, JavaScript) produce identical
outputs for the same inputs.

Operations tested:
- BLAKE3 raw hashing
- Merkle leaf hashing (domain-separated)
- Merkle root computation (CT-style promotion)

The external verifier batch tools are invoked via subprocess.  Tests are
skipped when the required toolchain (Go, Rust/Cargo, Node) is not
available on the current system.  To run the full cross-language suite::

    pytest tests/test_differential_fuzz.py -m differential

Internally the tests batch Hypothesis-generated examples and invoke each
external verifier once per batch to avoid per-example process overhead.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from protocol.hashes import blake3_hash
from protocol.merkle import MerkleTree, merkle_leaf_hash


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
GO_DIR = REPO_ROOT / "verifiers" / "go"
RUST_DIR = REPO_ROOT / "verifiers" / "rust"
JS_DIR = REPO_ROOT / "verifiers" / "javascript"


# ---------------------------------------------------------------------------
# Toolchain availability detection
# ---------------------------------------------------------------------------

HAS_GO = shutil.which("go") is not None
HAS_CARGO = shutil.which("cargo") is not None
HAS_NODE = shutil.which("node") is not None and (JS_DIR / "node_modules").is_dir()

# Maximum time (seconds) to wait for a batch hasher subprocess.  Includes
# toolchain compilation on first invocation (Go/Rust may need to build).
_SUBPROCESS_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_batch(
    command: list[str],
    cwd: Path,
    op: str,
    records: list[bytes],
) -> list[str]:
    """Call an external batch hasher with the given op and records."""
    request = {
        "op": op,
        "records_b64": [base64.b64encode(r).decode("ascii") for r in records],
    }
    proc = subprocess.run(
        command,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=cwd,
        check=False,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)!r} (op={op}) failed (rc={proc.returncode}):\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    response = json.loads(proc.stdout)
    hashes = response.get("hashes")
    if not isinstance(hashes, list):
        raise RuntimeError(f"Invalid response from {' '.join(command)!r}: {proc.stdout}")
    return hashes


def _python_blake3(records: list[bytes]) -> list[str]:
    return [blake3_hash([r]).hex() for r in records]


def _python_merkle_leaf_hash(records: list[bytes]) -> list[str]:
    return [merkle_leaf_hash(r).hex() for r in records]


def _python_merkle_root(leaves: list[bytes]) -> str:
    tree = MerkleTree(leaves)
    return tree.get_root().hex()


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Arbitrary byte strings 0-1024 bytes long
byte_data = st.binary(min_size=0, max_size=1024)

# Lists of 1-16 byte strings (for Merkle tree leaves)
leaf_lists = st.lists(st.binary(min_size=1, max_size=256), min_size=1, max_size=16)


# ---------------------------------------------------------------------------
# Python-only property tests (always run, no external toolchain needed)
# ---------------------------------------------------------------------------


class TestPythonCryptoProperties:
    """Property-based tests for Python crypto primitives."""

    @given(data=byte_data)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_blake3_deterministic(self, data: bytes) -> None:
        """BLAKE3 must be deterministic: same input always produces same output."""
        h1 = blake3_hash([data])
        h2 = blake3_hash([data])
        assert h1 == h2

    @given(data=byte_data)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_blake3_output_length(self, data: bytes) -> None:
        """BLAKE3 output must always be 32 bytes."""
        h = blake3_hash([data])
        assert len(h) == 32

    @given(data=byte_data)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_leaf_hash_domain_separation(self, data: bytes) -> None:
        """Leaf hash must differ from raw BLAKE3 hash (domain separation)."""
        raw = blake3_hash([data])
        leaf = merkle_leaf_hash(data)
        assert raw != leaf, "Domain separation failed: leaf hash equals raw hash"

    @given(data=byte_data)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_leaf_hash_deterministic(self, data: bytes) -> None:
        """Merkle leaf hash must be deterministic."""
        h1 = merkle_leaf_hash(data)
        h2 = merkle_leaf_hash(data)
        assert h1 == h2

    @given(leaves=leaf_lists)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_root_deterministic(self, leaves: list[bytes]) -> None:
        """Merkle root must be deterministic for the same leaf set."""
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)
        assert tree1.get_root() == tree2.get_root()

    @given(leaves=leaf_lists)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_root_output_length(self, leaves: list[bytes]) -> None:
        """Merkle root must always be 32 bytes."""
        tree = MerkleTree(leaves)
        assert len(tree.get_root()) == 32

    @given(data=st.binary(min_size=1, max_size=256))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_single_leaf_tree_equals_leaf_hash(self, data: bytes) -> None:
        """A single-leaf Merkle tree root must equal the leaf hash."""
        tree = MerkleTree([data])
        leaf = merkle_leaf_hash(data)
        assert tree.get_root() == leaf


# ---------------------------------------------------------------------------
# Cross-implementation differential tests (require external toolchains)
# ---------------------------------------------------------------------------


@pytest.mark.differential
class TestCrossImplBlake3:
    """Differential fuzzing of BLAKE3 across Python, Go, Rust, JavaScript."""

    @pytest.mark.skipif(not HAS_GO, reason="Go toolchain not available")
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_blake3_python_vs_go(self, data: list[bytes]) -> None:
        py_hashes = _python_blake3(data)
        go_hashes = _run_batch(["go", "run", "./cmd/hash_batch"], GO_DIR, "blake3", data)
        assert py_hashes == go_hashes, "Python vs Go BLAKE3 divergence"

    @pytest.mark.skipif(not HAS_CARGO, reason="Cargo toolchain not available")
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_blake3_python_vs_rust(self, data: list[bytes]) -> None:
        py_hashes = _python_blake3(data)
        rust_hashes = _run_batch(
            ["cargo", "run", "--quiet", "--bin", "hash_batch"],
            RUST_DIR,
            "blake3",
            data,
        )
        assert py_hashes == rust_hashes, "Python vs Rust BLAKE3 divergence"

    @pytest.mark.skipif(
        not HAS_NODE, reason="Node.js or verifiers/javascript/node_modules not available"
    )
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_blake3_python_vs_js(self, data: list[bytes]) -> None:
        py_hashes = _python_blake3(data)
        js_hashes = _run_batch(["node", "hash_batch.js"], JS_DIR, "blake3", data)
        assert py_hashes == js_hashes, "Python vs JavaScript BLAKE3 divergence"


@pytest.mark.differential
class TestCrossImplMerkleLeafHash:
    """Differential fuzzing of Merkle leaf hashing across implementations."""

    @pytest.mark.skipif(not HAS_GO, reason="Go toolchain not available")
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_leaf_python_vs_go(self, data: list[bytes]) -> None:
        py_hashes = _python_merkle_leaf_hash(data)
        go_hashes = _run_batch(["go", "run", "./cmd/hash_batch"], GO_DIR, "merkle_leaf_hash", data)
        assert py_hashes == go_hashes, "Python vs Go merkle_leaf_hash divergence"

    @pytest.mark.skipif(not HAS_CARGO, reason="Cargo toolchain not available")
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_leaf_python_vs_rust(self, data: list[bytes]) -> None:
        py_hashes = _python_merkle_leaf_hash(data)
        rust_hashes = _run_batch(
            ["cargo", "run", "--quiet", "--bin", "hash_batch"],
            RUST_DIR,
            "merkle_leaf_hash",
            data,
        )
        assert py_hashes == rust_hashes, "Python vs Rust merkle_leaf_hash divergence"

    @pytest.mark.skipif(
        not HAS_NODE, reason="Node.js or verifiers/javascript/node_modules not available"
    )
    @given(data=st.lists(byte_data, min_size=1, max_size=50))
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_leaf_python_vs_js(self, data: list[bytes]) -> None:
        py_hashes = _python_merkle_leaf_hash(data)
        js_hashes = _run_batch(["node", "hash_batch.js"], JS_DIR, "merkle_leaf_hash", data)
        assert py_hashes == js_hashes, "Python vs JavaScript merkle_leaf_hash divergence"


@pytest.mark.differential
class TestCrossImplMerkleRoot:
    """Differential fuzzing of Merkle root computation across implementations."""

    @pytest.mark.skipif(not HAS_GO, reason="Go toolchain not available")
    @given(leaves=leaf_lists)
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_root_python_vs_go(self, leaves: list[bytes]) -> None:
        py_root = _python_merkle_root(leaves)
        go_result = _run_batch(["go", "run", "./cmd/hash_batch"], GO_DIR, "merkle_root", leaves)
        assert [py_root] == go_result, "Python vs Go merkle_root divergence"

    @pytest.mark.skipif(not HAS_CARGO, reason="Cargo toolchain not available")
    @given(leaves=leaf_lists)
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_root_python_vs_rust(self, leaves: list[bytes]) -> None:
        py_root = _python_merkle_root(leaves)
        rust_result = _run_batch(
            ["cargo", "run", "--quiet", "--bin", "hash_batch"],
            RUST_DIR,
            "merkle_root",
            leaves,
        )
        assert [py_root] == rust_result, "Python vs Rust merkle_root divergence"

    @pytest.mark.skipif(
        not HAS_NODE, reason="Node.js or verifiers/javascript/node_modules not available"
    )
    @given(leaves=leaf_lists)
    @settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_root_python_vs_js(self, leaves: list[bytes]) -> None:
        py_root = _python_merkle_root(leaves)
        js_result = _run_batch(["node", "hash_batch.js"], JS_DIR, "merkle_root", leaves)
        assert [py_root] == js_result, "Python vs JavaScript merkle_root divergence"
