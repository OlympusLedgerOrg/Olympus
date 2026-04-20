"""Standalone Rust hot-path smoke checks for Olympus startup."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any


logger = logging.getLogger(__name__)

_TRUTHY_ENV_VALUES = {"1", "true", "yes", "on"}
ZERO_HASH = b"\x00" * 32
ZERO_SIBLINGS = (ZERO_HASH,) * 256
VALUE_HASH = bytes.fromhex("406e2beefc09af83846c24f1f4dd95e93c9592261e78d535aa7d18f4d3fd9289")

# Pinned from the pure-Python implementations so stale or mismatched Rust
# extension builds are caught immediately at startup.
PINNED_GOLDEN_VECTORS: dict[str, str] = {
    "blake3_hash": "2c3bbac58e97e3fecb016078d28ae954977ee82784f7c029d4602bdf37afa4b9",
    "record_key": "a214f2689de915c85ffe80094ce259adacb358f4d568029ad5c9f01566f9cf0c",
    "global_key": "b071e17db59fdba9c316129cf8efedf9785aa0662a0b17ffa1756bcf29f419e2",
    "leaf_hash": "dfa43c7d40caebc9541cfe528fed1f73eba3631f36f22bb9cbc7f741512a45c8",
    "node_hash": "cf2ac37294b1b07c5d734e52c71f0769b6e54b2ef082bed5e5a95a74da481fad",
    "canonical_json_encode": (
        '{"a":[1,2.5,{"a":null,"b":"Ω"}],"nested":{"alpha":"é","beta":true},"z":"é"}'
    ),
    "RustSparseMerkleTree.incremental_update": (
        "b1b866dfcf2ba9d455691e732adc5d1af392e3bc5e529f7594257a41a0c9a01e"
    ),
}

BLAKE3_HASH_PARTS = (b"OLY", b":", bytes(range(16)), b"\x00\xff")
RECORD_KEY_ARGS = ("document", "watauga:budget:2025", 7)
GLOBAL_KEY_ARGS = ("watauga:2025:budget", bytes.fromhex(PINNED_GOLDEN_VECTORS["record_key"]))
LEAF_HASH_ARGS = (
    bytes.fromhex(PINNED_GOLDEN_VECTORS["global_key"]),
    VALUE_HASH,
    "docling@2.3.1",
    "v1",
)
NODE_HASH_ARGS = (bytes.fromhex(PINNED_GOLDEN_VECTORS["leaf_hash"]), ZERO_HASH)
CANONICAL_JSON_INPUT: dict[str, Any] = {
    "z": "é",
    "a": [1, Decimal("2.50"), {"b": "Ω", "a": None}],
    "nested": {"beta": True, "alpha": "e\u0301"},
}
SMT_INCREMENTAL_ARGS = (
    bytes.fromhex(PINNED_GOLDEN_VECTORS["global_key"]),
    VALUE_HASH,
    ZERO_SIBLINGS,
    "docling@2.3.1",
    "v1",
)

PROBE_NAMES = (
    "blake3_hash",
    "record_key",
    "global_key",
    "leaf_hash",
    "node_hash",
    "canonical_json_encode",
    "RustSparseMerkleTree.incremental_update",
    "verify_groth16_bn254",
)


@dataclass(frozen=True)
class RustProbeResult:
    """Result of a single Rust hot-path smoke probe."""

    name: str
    ok: bool
    detail: str

    def __bool__(self) -> bool:
        """Treat probe results as truthy when they passed."""
        return self.ok


@dataclass(frozen=True)
class RustSmokeReport:
    """Aggregated result of the Rust hot-path smoke checks."""

    probe_results: tuple[RustProbeResult, ...]

    @property
    def ok(self) -> bool:
        """Return True when every probe passed."""
        return all(result.ok for result in self.probe_results)

    @property
    def degraded(self) -> bool:
        """Return True when at least one probe failed."""
        return not self.ok

    @property
    def failed_probes(self) -> tuple[str, ...]:
        """Return the names of probes that failed."""
        return tuple(result.name for result in self.probe_results if not result.ok)

    @property
    def failure_summary(self) -> str:
        """Return a human-readable summary of probe failures."""
        return "; ".join(
            f"{result.name}: {result.detail}" for result in self.probe_results if not result.ok
        )


@dataclass(frozen=True)
class _RustBindings:
    crypto: Any
    canonical: Any
    sparse_merkle_tree: Any
    verify_groth16_bn254: Any


# Type alias for probe functions
_ProbeFunc = Callable[[_RustBindings], RustProbeResult]


def _env_flag_enabled(name: str) -> bool:
    """Return True when *name* is set to a common truthy value."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY_ENV_VALUES


def _load_rust_bindings() -> _RustBindings:
    """Import the Rust symbols used by the smoke probes."""
    import olympus_core.canonical as rust_canonical
    import olympus_core.crypto as rust_crypto
    from olympus_core import RustSparseMerkleTree, verify_groth16_bn254

    return _RustBindings(
        crypto=rust_crypto,
        canonical=rust_canonical,
        sparse_merkle_tree=RustSparseMerkleTree,
        verify_groth16_bn254=verify_groth16_bn254,
    )


def _bytes_probe(name: str, actual: bytes, expected_hex: str) -> RustProbeResult:
    """Compare a bytes result against a pinned hex vector."""
    actual_hex = actual.hex()
    if actual_hex != expected_hex:
        return RustProbeResult(
            name=name,
            ok=False,
            detail=f"expected {expected_hex}, got {actual_hex}",
        )
    return RustProbeResult(name=name, ok=True, detail="matched pinned golden vector")


def _text_probe(name: str, actual: str, expected_text: str) -> RustProbeResult:
    """Compare a text result against a pinned string vector."""
    if actual != expected_text:
        return RustProbeResult(
            name=name,
            ok=False,
            detail=f"expected {expected_text!r}, got {actual!r}",
        )
    return RustProbeResult(name=name, ok=True, detail="matched pinned golden vector")


def probe_blake3_hash(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.crypto.blake3_hash."""
    actual = bindings.crypto.blake3_hash(list(BLAKE3_HASH_PARTS))
    return _bytes_probe("blake3_hash", actual, PINNED_GOLDEN_VECTORS["blake3_hash"])


def probe_record_key(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.crypto.record_key."""
    actual = bindings.crypto.record_key(*RECORD_KEY_ARGS)
    return _bytes_probe("record_key", actual, PINNED_GOLDEN_VECTORS["record_key"])


def probe_global_key(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.crypto.global_key."""
    actual = bindings.crypto.global_key(*GLOBAL_KEY_ARGS)
    return _bytes_probe("global_key", actual, PINNED_GOLDEN_VECTORS["global_key"])


def probe_leaf_hash(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.crypto.leaf_hash."""
    actual = bindings.crypto.leaf_hash(*LEAF_HASH_ARGS)
    return _bytes_probe("leaf_hash", actual, PINNED_GOLDEN_VECTORS["leaf_hash"])


def probe_node_hash(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.crypto.node_hash."""
    actual = bindings.crypto.node_hash(*NODE_HASH_ARGS)
    return _bytes_probe("node_hash", actual, PINNED_GOLDEN_VECTORS["node_hash"])


def probe_canonical_json_encode(bindings: _RustBindings) -> RustProbeResult:
    """Probe olympus_core.canonical.canonical_json_encode."""
    actual = bindings.canonical.canonical_json_encode(CANONICAL_JSON_INPUT)
    return _text_probe(
        "canonical_json_encode",
        actual,
        PINNED_GOLDEN_VECTORS["canonical_json_encode"],
    )


def probe_incremental_update(bindings: _RustBindings) -> RustProbeResult:
    """Probe RustSparseMerkleTree.incremental_update with a zero-sibling path."""
    key, value_hash, siblings, parser_id, canonical_parser_version = SMT_INCREMENTAL_ARGS
    root_hash, proof_siblings, node_deltas = bindings.sparse_merkle_tree.incremental_update(
        key,
        value_hash,
        list(siblings),
        parser_id,
        canonical_parser_version,
    )
    root_result = _bytes_probe(
        "RustSparseMerkleTree.incremental_update",
        root_hash,
        PINNED_GOLDEN_VECTORS["RustSparseMerkleTree.incremental_update"],
    )
    if not root_result.ok:
        return root_result
    if len(proof_siblings) != 256:
        return RustProbeResult(
            name="RustSparseMerkleTree.incremental_update",
            ok=False,
            detail=f"expected 256 proof siblings, got {len(proof_siblings)}",
        )
    if len(node_deltas) != 256:
        return RustProbeResult(
            name="RustSparseMerkleTree.incremental_update",
            ok=False,
            detail=f"expected 256 node deltas, got {len(node_deltas)}",
        )
    return RustProbeResult(
        name="RustSparseMerkleTree.incremental_update",
        ok=True,
        detail="matched pinned one-leaf root vector",
    )


def probe_verify_groth16_bn254(bindings: _RustBindings) -> RustProbeResult:
    """Probe verify_groth16_bn254 with malformed JSON and expect False."""
    verified = bindings.verify_groth16_bn254("{", "{", [])
    if verified is not False:
        return RustProbeResult(
            name="verify_groth16_bn254",
            ok=False,
            detail=f"expected False for malformed proof input, got {verified!r}",
        )
    return RustProbeResult(
        name="verify_groth16_bn254",
        ok=True,
        detail="returned False for malformed input without panicking",
    )


def _safe_probe(name: str, probe: _ProbeFunc, bindings: _RustBindings) -> RustProbeResult:
    """Run a probe and convert unexpected exceptions into probe failures."""
    try:
        result: RustProbeResult = probe(bindings)
        return result
    except Exception as exc:
        return RustProbeResult(name=name, ok=False, detail=f"{type(exc).__name__}: probe failed")


def run_smoke() -> RustSmokeReport:
    """Run all Rust hot-path smoke probes and return an aggregate report."""
    try:
        bindings = _load_rust_bindings()
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        return RustSmokeReport(
            tuple(RustProbeResult(name=name, ok=False, detail=detail) for name in PROBE_NAMES)
        )

    probes = (
        ("blake3_hash", probe_blake3_hash),
        ("record_key", probe_record_key),
        ("global_key", probe_global_key),
        ("leaf_hash", probe_leaf_hash),
        ("node_hash", probe_node_hash),
        ("canonical_json_encode", probe_canonical_json_encode),
        ("RustSparseMerkleTree.incremental_update", probe_incremental_update),
        ("verify_groth16_bn254", probe_verify_groth16_bn254),
    )
    return RustSmokeReport(tuple(_safe_probe(name, probe, bindings) for name, probe in probes))


def assert_rust_hot_path() -> RustSmokeReport:
    """Enforce Rust hot-path availability based on OLYMPUS_REQUIRE_RUST."""
    report = run_smoke()
    if report.ok:
        return report

    message = f"Rust hot-path smoke failed: {report.failure_summary}"
    if _env_flag_enabled("OLYMPUS_REQUIRE_RUST"):
        raise RuntimeError(message)

    logger.warning(
        "%s; continuing in degraded mode because OLYMPUS_REQUIRE_RUST is not enabled",
        message,
    )
    return report


def main() -> int:
    """Run the standalone Rust smoke runner and return an exit code."""
    report = run_smoke()
    if report.ok:
        print("Rust hot-path smoke: OK")
        return 0

    print("Rust hot-path smoke: DEGRADED")
    for result in report.probe_results:
        print(f"{result.name}: {'ok' if result.ok else 'fail'} - {result.detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
