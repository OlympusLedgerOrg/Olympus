"""Tests for api.rust_smoke."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import blake3
import pytest

from api import rust_smoke
from protocol.canonical_json import _encode_value, _normalize_for_canonical_json
from protocol.hashes import _GLOBAL_SMT_KEY_CONTEXT


try:
    import olympus_core  # noqa: F401

    HAS_RUST = True
except ImportError:
    HAS_RUST = False

RUST_ONLY = pytest.mark.skipif(not HAS_RUST, reason="Rust extension not built")
REPO_ROOT = Path(__file__).resolve().parent.parent

_KEY_PREFIX = b"OLY:KEY:V1"
_LEAF_PREFIX = b"OLY:LEAF:V1"
_NODE_PREFIX = b"OLY:NODE:V1"
_SEP = b"|"


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _py_blake3_hash(parts: tuple[bytes, ...]) -> bytes:
    return blake3.blake3(b"".join(parts)).digest()


def _py_record_key(record_type: str, record_id: str, version: int) -> bytes:
    payload = b"".join(
        [
            _KEY_PREFIX,
            _length_prefix(record_type.encode("utf-8")),
            _length_prefix(record_id.encode("utf-8")),
            version.to_bytes(8, "big"),
        ]
    )
    return blake3.blake3(payload).digest()


def _py_global_key(shard_id: str, record_key_bytes: bytes) -> bytes:
    payload = _length_prefix(shard_id.encode("utf-8")) + _length_prefix(record_key_bytes)
    return blake3.blake3(payload, derive_key_context=_GLOBAL_SMT_KEY_CONTEXT).digest()


def _py_leaf_hash(
    key: bytes, value_hash: bytes, parser_id: str, canonical_parser_version: str
) -> bytes:
    pid = parser_id.encode("utf-8")
    cpv = canonical_parser_version.encode("utf-8")
    return _py_blake3_hash(
        (
            _LEAF_PREFIX,
            _SEP,
            key,
            _SEP,
            value_hash,
            _SEP,
            len(pid).to_bytes(4, "big"),
            pid,
            _SEP,
            len(cpv).to_bytes(4, "big"),
            cpv,
        )
    )


def _py_node_hash(left: bytes, right: bytes) -> bytes:
    return _py_blake3_hash((_NODE_PREFIX, _SEP, left, _SEP, right))


def _py_canonical_json(value: object) -> str:
    return _encode_value(_normalize_for_canonical_json(value))


def _py_zero_sibling_root(key: bytes, value_hash: bytes, parser_id: str, canonical_parser_version: str) -> bytes:
    current = _py_leaf_hash(key, value_hash, parser_id, canonical_parser_version)
    path_bits: list[int] = []
    for byte in key:
        for bit_index in range(8):
            path_bits.append((byte >> (7 - bit_index)) & 1)
    for level in range(256):
        bit_pos = 255 - level
        if path_bits[bit_pos] == 0:
            current = _py_node_hash(current, rust_smoke.ZERO_HASH)
        else:
            current = _py_node_hash(rust_smoke.ZERO_HASH, current)
    return current


@pytest.mark.parametrize(
    ("name", "actual"),
    [
        (
            "blake3_hash",
            lambda: _py_blake3_hash(rust_smoke.BLAKE3_HASH_PARTS).hex(),
        ),
        (
            "record_key",
            lambda: _py_record_key(*rust_smoke.RECORD_KEY_ARGS).hex(),
        ),
        (
            "global_key",
            lambda: _py_global_key(*rust_smoke.GLOBAL_KEY_ARGS).hex(),
        ),
        (
            "leaf_hash",
            lambda: _py_leaf_hash(*rust_smoke.LEAF_HASH_ARGS).hex(),
        ),
        (
            "node_hash",
            lambda: _py_node_hash(*rust_smoke.NODE_HASH_ARGS).hex(),
        ),
        (
            "canonical_json_encode",
            lambda: _py_canonical_json(rust_smoke.CANONICAL_JSON_INPUT),
        ),
        (
            "RustSparseMerkleTree.incremental_update",
            lambda: _py_zero_sibling_root(
                rust_smoke.SMT_INCREMENTAL_ARGS[0],
                rust_smoke.SMT_INCREMENTAL_ARGS[1],
                rust_smoke.SMT_INCREMENTAL_ARGS[3],
                rust_smoke.SMT_INCREMENTAL_ARGS[4],
            ).hex(),
        ),
    ],
)
def test_pinned_vectors_match_python_implementations(name, actual):
    """Pinned vectors should stay in lock-step with the Python implementations."""
    assert actual() == rust_smoke.PINNED_GOLDEN_VECTORS[name]


def test_probe_result_bool_true():
    """Truthy probe results represent success."""
    assert bool(rust_smoke.RustProbeResult(name="x", ok=True, detail="ok")) is True


def test_probe_result_bool_false():
    """Falsey probe results represent failure."""
    assert bool(rust_smoke.RustProbeResult(name="x", ok=False, detail="boom")) is False


def test_smoke_report_ok_when_all_probes_pass():
    """All-passing probe reports should be healthy."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),)
    )
    assert report.ok is True


def test_smoke_report_ok_false_when_probe_fails():
    """Any failing probe should make the report unhealthy."""
    report = rust_smoke.RustSmokeReport(
        (
            rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),
            rust_smoke.RustProbeResult(name="b", ok=False, detail="boom"),
        )
    )
    assert report.ok is False


def test_smoke_report_degraded_true_when_probe_fails():
    """Any failing probe should put the report into degraded mode."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="b", ok=False, detail="boom"),)
    )
    assert report.degraded is True


def test_smoke_report_failed_probes_filters_only_failures():
    """failed_probes should expose just the failing probe names."""
    report = rust_smoke.RustSmokeReport(
        (
            rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),
            rust_smoke.RustProbeResult(name="b", ok=False, detail="boom"),
            rust_smoke.RustProbeResult(name="c", ok=False, detail="bad"),
        )
    )
    assert report.failed_probes == ("b", "c")


def test_smoke_report_failure_summary_empty_when_healthy():
    """Healthy reports should have an empty failure summary."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),)
    )
    assert report.failure_summary == ""


def test_smoke_report_failure_summary_lists_each_failure():
    """Failure summaries should include every failing probe."""
    report = rust_smoke.RustSmokeReport(
        (
            rust_smoke.RustProbeResult(name="b", ok=False, detail="boom"),
            rust_smoke.RustProbeResult(name="c", ok=False, detail="bad"),
        )
    )
    assert report.failure_summary == "b: boom; c: bad"


def test_assert_rust_hot_path_returns_report_when_smoke_passes(monkeypatch):
    """Successful smoke reports should be returned unchanged."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),)
    )
    monkeypatch.delenv("OLYMPUS_REQUIRE_RUST", raising=False)
    monkeypatch.setattr(rust_smoke, "run_smoke", lambda: report)
    assert rust_smoke.assert_rust_hot_path() is report


def test_assert_rust_hot_path_returns_report_when_required_and_smoke_passes(monkeypatch):
    """The env flag should not affect successful smoke reports."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=True, detail="ok"),)
    )
    monkeypatch.setenv("OLYMPUS_REQUIRE_RUST", "1")
    monkeypatch.setattr(rust_smoke, "run_smoke", lambda: report)
    assert rust_smoke.assert_rust_hot_path() is report


def test_assert_rust_hot_path_warns_when_smoke_fails_and_flag_unset(monkeypatch, caplog):
    """Without OLYMPUS_REQUIRE_RUST, failures should warn and degrade."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=False, detail="boom"),)
    )
    monkeypatch.delenv("OLYMPUS_REQUIRE_RUST", raising=False)
    monkeypatch.setattr(rust_smoke, "run_smoke", lambda: report)
    with caplog.at_level("WARNING", logger="api.rust_smoke"):
        assert rust_smoke.assert_rust_hot_path() is report
    assert "continuing in degraded mode" in caplog.text


def test_assert_rust_hot_path_warns_when_smoke_fails_and_flag_is_zero(monkeypatch, caplog):
    """Falsey env values should also degrade instead of raising."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=False, detail="boom"),)
    )
    monkeypatch.setenv("OLYMPUS_REQUIRE_RUST", "0")
    monkeypatch.setattr(rust_smoke, "run_smoke", lambda: report)
    with caplog.at_level("WARNING", logger="api.rust_smoke"):
        assert rust_smoke.assert_rust_hot_path() is report
    assert "continuing in degraded mode" in caplog.text


@pytest.mark.parametrize("flag", ["1", "true", "yes", "on"])
def test_assert_rust_hot_path_raises_when_required_and_smoke_fails(monkeypatch, flag):
    """Truthy OLYMPUS_REQUIRE_RUST values should hard-fail degraded startup."""
    report = rust_smoke.RustSmokeReport(
        (rust_smoke.RustProbeResult(name="a", ok=False, detail="boom"),)
    )
    monkeypatch.setenv("OLYMPUS_REQUIRE_RUST", flag)
    monkeypatch.setattr(rust_smoke, "run_smoke", lambda: report)
    with pytest.raises(RuntimeError, match="Rust hot-path smoke failed"):
        rust_smoke.assert_rust_hot_path()


@RUST_ONLY
def test_run_smoke_report_ok():
    """run_smoke should pass when the Rust extension is available and healthy."""
    assert rust_smoke.run_smoke().ok is True


@RUST_ONLY
def test_run_smoke_report_not_degraded():
    """Healthy run_smoke reports should not be degraded."""
    assert rust_smoke.run_smoke().degraded is False


@RUST_ONLY
def test_run_smoke_failed_probes_empty():
    """Healthy run_smoke reports should have no failed probes."""
    assert rust_smoke.run_smoke().failed_probes == ()


@RUST_ONLY
@pytest.mark.parametrize("name", rust_smoke.PROBE_NAMES)
def test_run_smoke_includes_probe_name(name):
    """run_smoke should emit a result for every expected probe."""
    report = rust_smoke.run_smoke()
    assert name in {result.name for result in report.probe_results}


@RUST_ONLY
@pytest.mark.parametrize("name", rust_smoke.PROBE_NAMES)
def test_run_smoke_marks_probe_ok(name):
    """When Rust is healthy, every probe should pass."""
    report = rust_smoke.run_smoke()
    probe_map = {result.name: result for result in report.probe_results}
    assert probe_map[name].ok is True


@RUST_ONLY
def test_standalone_runner_exits_zero():
    """The standalone runner should return exit code 0 when Rust is healthy."""
    env = dict(os.environ)
    result = subprocess.run(
        [sys.executable, "-m", "api.rust_smoke"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Rust hot-path smoke: OK" in result.stdout
