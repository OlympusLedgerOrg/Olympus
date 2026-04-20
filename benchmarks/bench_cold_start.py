"""
Cold-start performance benchmark: Rust backend vs pure-Python baseline.

Measures throughput (records/second) across every hot-path function in the
Olympus crypto/canonical pipeline, then reports a combined end-to-end figure.

Usage
-----
    python benchmarks/bench_cold_start.py                  # defaults
    python benchmarks/bench_cold_start.py --records 50000  # more iterations
    python benchmarks/bench_cold_start.py --no-rust        # baseline only

Output
------
Prints a formatted table:

    ┌──────────────────────────────┬──────────────┬──────────────┬─────────┐
    │ Operation                    │  Python rec/s│   Rust rec/s │ Speedup │
    ├──────────────────────────────┼──────────────┼──────────────┼─────────┤
    │ blake3_hash (128 B)          │   1,234,567  │   9,876,543  │  8.00×  │
    │ ...                          │              │              │         │
    └──────────────────────────────┴──────────────┴──────────────┴─────────┘

The "cold start" section shows first-call latency before any Python warmup.
The "throughput" section shows steady-state records/second.
"""

from __future__ import annotations

import argparse
import importlib
import statistics
import sys
import time
from decimal import Decimal
from pathlib import Path

# Add repo root to sys.path so `protocol` is importable when the script is
# run directly (e.g. `python benchmarks/bench_cold_start.py`).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

_parser = argparse.ArgumentParser(
    description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
)
_parser.add_argument(
    "--records", type=int, default=20_000, help="iterations per benchmark (default: 20000)"
)
_parser.add_argument(
    "--warmup", type=int, default=500, help="warmup iterations before timing (default: 500)"
)
_parser.add_argument(
    "--no-rust", dest="no_rust", action="store_true", help="skip Rust timings (baseline-only mode)"
)
_ARGS, _UNKNOWN = _parser.parse_known_args()

# ---------------------------------------------------------------------------
# Cold-start: measure module import time BEFORE importing anything else
# ---------------------------------------------------------------------------

_t_import_start = time.perf_counter()
import blake3 as _blake3  # noqa: E402

_t_blake3_imported = time.perf_counter()

import unicodedata  # noqa: E402
import json as _json  # noqa: E402

_t_python_stdlib = time.perf_counter()

_rust_available = False
_t_rust_import_start = time.perf_counter()
try:
    import olympus_core.crypto as _rust_crypto
    import olympus_core.canonical as _rust_canonical

    _rust_available = True
except ImportError:
    pass
_t_rust_imported = time.perf_counter()

# ---------------------------------------------------------------------------
# Pure-Python implementations (used regardless of whether Rust is built,
# so we get a clean apples-to-apples comparison)
# ---------------------------------------------------------------------------

_KEY_PREFIX = b"OLY:KEY:V1"
_LEAF_PREFIX = b"OLY:LEAF:V1"
_NODE_PREFIX = b"OLY:NODE:V1"
_SEP = b"|"
from protocol.hashes import _GLOBAL_SMT_KEY_CONTEXT as _GSK_CONTEXT  # noqa: E402


def _lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def py_blake3_hash(parts: list[bytes]) -> bytes:
    return _blake3.blake3(b"".join(parts)).digest()


def py_record_key(record_type: str, record_id: str, version: int) -> bytes:
    return _blake3.blake3(
        _KEY_PREFIX
        + _lp(record_type.encode())
        + _lp(record_id.encode())
        + version.to_bytes(8, "big")
    ).digest()


def py_global_key(shard_id: str, rk: bytes) -> bytes:
    return _blake3.blake3(
        _lp(shard_id.encode()) + _lp(rk),
        derive_key_context=_GSK_CONTEXT,
    ).digest()


def py_leaf_hash(key: bytes, value_hash: bytes) -> bytes:
    return _blake3.blake3(_LEAF_PREFIX + _SEP + key + _SEP + value_hash).digest()


def py_node_hash(left: bytes, right: bytes) -> bytes:
    return _blake3.blake3(_NODE_PREFIX + _SEP + left + _SEP + right).digest()


def py_canonical_json_encode(obj: object) -> str:
    # Minimal JCS encoder matching the protocol implementation exactly
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        d = Decimal(obj)
        if d == 0:
            return "0"
        n = d.normalize()
        digits = str(abs(int(n)))
        exp = int(n.log10()) if n != 0 else 0  # approx; use as_tuple for precision
        at = n.as_tuple()
        sign = "-" if at.sign else ""
        digs = "".join(str(x) for x in at.digits)
        e = at.exponent
        adj = len(digs) - 1 + e
        if -6 <= adj <= 20:
            if e >= 0:
                return f"{sign}{digs}{'0' * e}"
            idx = len(digs) + e
            if idx > 0:
                return f"{sign}{digs[:idx]}.{digs[idx:]}"
            return f"{sign}0.{'0' * (-idx)}{digs}"
        m = f"{digs[0]}.{digs[1:]}" if len(digs) > 1 else digs
        ep = "+" if adj >= 0 else ""
        return f"{sign}{m}e{ep}{adj}"
    if isinstance(obj, Decimal):
        if not obj.is_finite():
            raise ValueError("non-finite Decimal")
        if obj.is_zero():
            return "0"
        n = obj.normalize()
        at = n.as_tuple()
        sign = "-" if at.sign else ""
        digs = "".join(str(x) for x in at.digits)
        e = at.exponent
        adj = len(digs) - 1 + e
        if -6 <= adj <= 20:
            if e >= 0:
                return f"{sign}{digs}{'0' * e}"
            idx = len(digs) + e
            if idx > 0:
                return f"{sign}{digs[:idx]}.{digs[idx:]}"
            return f"{sign}0.{'0' * (-idx)}{digs}"
        m = f"{digs[0]}.{digs[1:]}" if len(digs) > 1 else digs
        ep = "+" if adj >= 0 else ""
        return f"{sign}{m}e{ep}{adj}"
    if isinstance(obj, str):
        nfc = unicodedata.normalize("NFC", obj)
        return _json.dumps(nfc, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(py_canonical_json_encode(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted((unicodedata.normalize("NFC", k), v) for k, v in obj.items())
        return (
            "{"
            + ",".join(
                f"{_json.dumps(k, ensure_ascii=False)}:{py_canonical_json_encode(v)}"
                for k, v in items
            )
            + "}"
        )
    raise TypeError(f"not serializable: {type(obj)}")


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------


def _bench(fn, n: int, warmup: int) -> tuple[float, float]:
    """Return (throughput_recs_per_sec, first_call_ns)."""
    # cold first call
    t0 = time.perf_counter_ns()
    fn()
    first_ns = time.perf_counter_ns() - t0

    # warmup (not timed)
    for _ in range(warmup):
        fn()

    # timed run
    t_start = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - t_start

    throughput = n / elapsed
    return throughput, first_ns


# ---------------------------------------------------------------------------
# Benchmark payloads
# ---------------------------------------------------------------------------

_SHARD = "watauga:2025:budget"
_RTYPE = "document"
_RID = "doc-abc-001"
_VERSION = 42

_SMALL_DOC = {
    "agency": "Watauga County",
    "year": 2025,
    "type": "budget",
    "total": Decimal("1234567.89"),
    "redacted": False,
}

_LARGE_DOC = {
    "agency": "Watauga County Department of Public Works",
    "year": 2025,
    "fiscal_period": "Q3",
    "type": "expenditure_report",
    "items": [
        {"code": f"EXP-{i:04d}", "amount": Decimal(f"{i * 1.23:.2f}"), "approved": True}
        for i in range(50)
    ],
    "total": Decimal("987654.32"),
    "notes": "Includes capital outlays for infrastructure. Unicode: café résumé naïve",
    "metadata": {
        "submitted_by": "county_auditor",
        "reviewed": True,
        "version": 7,
    },
}

_SMALL_BYTES = b"canonical bytes" * 8  # 128 B
_LARGE_BYTES = b"canonical bytes" * 512  # 8 KB

_RK = py_record_key(_RTYPE, _RID, _VERSION)
_GK = py_global_key(_SHARD, _RK)
_VH = py_blake3_hash([b"value data" * 16])
_LEFT = bytes(range(32))
_RIGHT = bytes(range(32, 64))


# ---------------------------------------------------------------------------
# Suite definitions
# ---------------------------------------------------------------------------

BenchSuite = list  # list of (label, py_fn, rust_fn_or_none)


def _make_suite() -> BenchSuite:
    suite: BenchSuite = []

    # ── blake3_hash ──────────────────────────────────────────────────────────
    suite.append(
        (
            "blake3_hash (128 B)",
            lambda: py_blake3_hash([_SMALL_BYTES]),
            (lambda: _rust_crypto.blake3_hash([_SMALL_BYTES])) if _rust_available else None,
        )
    )
    suite.append(
        (
            "blake3_hash (8 KB)",
            lambda: py_blake3_hash([_LARGE_BYTES]),
            (lambda: _rust_crypto.blake3_hash([_LARGE_BYTES])) if _rust_available else None,
        )
    )

    # ── record_key ───────────────────────────────────────────────────────────
    suite.append(
        (
            "record_key",
            lambda: py_record_key(_RTYPE, _RID, _VERSION),
            (lambda: _rust_crypto.record_key(_RTYPE, _RID, _VERSION)) if _rust_available else None,
        )
    )

    # ── global_key ───────────────────────────────────────────────────────────
    suite.append(
        (
            "global_key",
            lambda: py_global_key(_SHARD, _RK),
            (lambda: _rust_crypto.global_key(_SHARD, _RK)) if _rust_available else None,
        )
    )

    # ── leaf_hash ────────────────────────────────────────────────────────────
    suite.append(
        (
            "leaf_hash",
            lambda: py_leaf_hash(_GK, _VH),
            (lambda: _rust_crypto.leaf_hash(_GK, _VH, "docling@2.3.1", "v1")) if _rust_available else None,
        )
    )

    # ── node_hash ────────────────────────────────────────────────────────────
    suite.append(
        (
            "node_hash",
            lambda: py_node_hash(_LEFT, _RIGHT),
            (lambda: _rust_crypto.node_hash(_LEFT, _RIGHT)) if _rust_available else None,
        )
    )

    # ── canonical_json_encode ────────────────────────────────────────────────
    suite.append(
        (
            "canonical_json (small doc)",
            lambda: py_canonical_json_encode(_SMALL_DOC),
            (lambda: _rust_canonical.canonical_json_encode(_SMALL_DOC))
            if _rust_available
            else None,
        )
    )
    suite.append(
        (
            "canonical_json (large doc, 50 items)",
            lambda: py_canonical_json_encode(_LARGE_DOC),
            (lambda: _rust_canonical.canonical_json_encode(_LARGE_DOC))
            if _rust_available
            else None,
        )
    )

    # ── end-to-end pipeline ──────────────────────────────────────────────────
    def _py_pipeline():
        canonical = py_canonical_json_encode(_SMALL_DOC)
        vh = py_blake3_hash([canonical.encode("utf-8")])
        rk = py_record_key(_RTYPE, _RID, _VERSION)
        gk = py_global_key(_SHARD, rk)
        return py_leaf_hash(gk, vh)

    def _rust_pipeline():
        canonical = _rust_canonical.canonical_json_encode(_SMALL_DOC)
        vh = _rust_crypto.blake3_hash([canonical.encode("utf-8")])
        rk = _rust_crypto.record_key(_RTYPE, _RID, _VERSION)
        gk = _rust_crypto.global_key(_SHARD, rk)
        return _rust_crypto.leaf_hash(gk, vh, "docling@2.3.1", "v1")

    suite.append(
        (
            "── FULL PIPELINE (small doc) ──",
            _py_pipeline,
            _rust_pipeline if _rust_available else None,
        )
    )

    return suite


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _fmt_throughput(rps: float) -> str:
    if rps >= 1_000_000:
        return f"{rps / 1_000_000:7.3f}M"
    if rps >= 1_000:
        return f"{rps / 1_000:7.1f}k"
    return f"{rps:8.1f} "


def _fmt_latency_ns(ns: float) -> str:
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.1f} µs"
    return f"{ns:.0f} ns"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run_benchmarks() -> None:
    n = _ARGS.records
    warmup = _ARGS.warmup
    no_rust = _ARGS.no_rust or not _rust_available

    W_OP = 38
    W_NUM = 12
    W_SPD = 9

    header_sep = (
        "┌"
        + "─" * (W_OP + 2)
        + "┬"
        + "─" * (W_NUM + 2)
        + "┬"
        + "─" * (W_NUM + 2)
        + "┬"
        + "─" * (W_SPD + 2)
        + "┐"
    )
    row_sep = (
        "├"
        + "─" * (W_OP + 2)
        + "┼"
        + "─" * (W_NUM + 2)
        + "┼"
        + "─" * (W_NUM + 2)
        + "┼"
        + "─" * (W_SPD + 2)
        + "┤"
    )
    footer_sep = (
        "└"
        + "─" * (W_OP + 2)
        + "┴"
        + "─" * (W_NUM + 2)
        + "┴"
        + "─" * (W_NUM + 2)
        + "┴"
        + "─" * (W_SPD + 2)
        + "┘"
    )

    def _row(op, py_val, rust_val, spd):
        return f"│ {op:<{W_OP}} │ {py_val:>{W_NUM}} │ {rust_val:>{W_NUM}} │ {spd:>{W_SPD}} │"

    print()
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║  Olympus Cold-Start Performance Benchmark                                  ║")
    print("║  Rust PyO3 backend vs pure-Python baseline                                 ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()

    # ── Import timings ───────────────────────────────────────────────────────
    py_import_ms = (_t_python_stdlib - _t_import_start) * 1000
    rust_import_ms = (_t_rust_imported - _t_rust_import_start) * 1000

    print("  Import latency (cold start)")
    print(f"    Python stdlib + blake3 ........... {py_import_ms:7.1f} ms")
    if _rust_available:
        print(f"    olympus_core (Rust extension) .... {rust_import_ms:7.1f} ms")
    else:
        print("    olympus_core ..................... NOT BUILT (skipped)")
    print()

    # ── Throughput table ─────────────────────────────────────────────────────
    print(f"  Iterations: {n:,}  |  Warmup: {warmup:,}")
    print()
    print(header_sep)
    print(_row("Operation", "Python rec/s", "Rust rec/s", "Speedup"))
    print(row_sep)

    suite = _make_suite()
    pipeline_py_rps = None
    pipeline_rust_rps = None

    for i, (label, py_fn, rust_fn) in enumerate(suite):
        is_pipeline = "PIPELINE" in label

        py_rps, py_cold_ns = _bench(py_fn, n, warmup)
        py_str = _fmt_throughput(py_rps)

        if not no_rust and rust_fn is not None:
            rust_rps, rust_cold_ns = _bench(rust_fn, n, warmup)
            rust_str = _fmt_throughput(rust_rps)
            speedup = rust_rps / py_rps
            spd_str = f"{speedup:6.2f}×"
        else:
            rust_rps = None
            rust_str = "     —"
            spd_str = "   —"

        if is_pipeline:
            print(row_sep)
            pipeline_py_rps = py_rps
            pipeline_rust_rps = rust_rps

        print(_row(label, py_str, rust_str, spd_str))

    print(footer_sep)
    print()
    print("  Note: blake3_hash in isolation runs near-parity because the Python")
    print("  `blake3` package is itself a Rust extension (PyO3), so Python already")
    print("  calls Rust directly.  Our wrapper adds one extra PyO3 crossing, which")
    print("  is visible on small payloads.  The composite functions (record_key,")
    print("  global_key, leaf_hash) show the real gain: they bundle multiple BLAKE3")
    print("  calls + logic into a single Python→Rust crossing, slashing overhead.")
    print()

    # ── Summary ──────────────────────────────────────────────────────────────
    if pipeline_py_rps is not None:
        print("  ┌─ Summary ──────────────────────────────────────────────────┐")
        print(
            f"  │  Python pipeline ..... {_fmt_throughput(pipeline_py_rps):>10} rec/s                  │"
        )
        if pipeline_rust_rps is not None:
            overall_speedup = pipeline_rust_rps / pipeline_py_rps
            print(
                f"  │  Rust   pipeline ..... {_fmt_throughput(pipeline_rust_rps):>10} rec/s                  │"
            )
            print(f"  │                                                            │")
            print(
                f"  │  End-to-end speedup .. {overall_speedup:>8.2f}×                           │"
            )
        print("  └────────────────────────────────────────────────────────────┘")
        print()

    if not _rust_available:
        print("  ⚠  olympus_core not built — Rust columns empty.")
        print("     Run `maturin develop --release` to enable the Rust backend.")
        print()


if __name__ == "__main__":
    run_benchmarks()
