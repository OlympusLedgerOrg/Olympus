"""Unit tests for protocol.telemetry — OTel traces and Prometheus metrics."""

from __future__ import annotations

import logging

import pytest

from protocol.telemetry import (
    INGEST_TOTAL,
    LEDGER_HEIGHT,
    PROOF_LATENCY,
    PARTITION_EVENTS,
    SMT_DIVERGENCE_TOTAL,
    VIEW_CHANGE_WATERMARK,
    _NoOpSpan,
    _NoOpTracer,
    get_tracer,
    opentelemetry_available,
    prometheus_available,
    record_smt_divergence,
    timed_operation,
)


# ---------------------------------------------------------------------------
# get_tracer
# ---------------------------------------------------------------------------


def test_get_tracer_returns_something() -> None:
    """get_tracer() always returns an object that can be used as a context manager."""
    tracer = get_tracer()
    assert tracer is not None


def test_get_tracer_noop_tracer_span() -> None:
    """When OTel is not installed, get_tracer() returns a _NoOpTracer."""
    if opentelemetry_available():
        pytest.skip("OTel is installed; noop path not active")

    tracer = get_tracer()
    assert isinstance(tracer, _NoOpTracer)
    with tracer.start_as_current_span("test-span") as span:
        assert isinstance(span, _NoOpSpan)
        span.set_attribute("key", "value")  # must not raise
        span.set_status(None)
        span.record_exception(ValueError("test"))


# ---------------------------------------------------------------------------
# _NoOpSpan
# ---------------------------------------------------------------------------


def test_noop_span_context_manager() -> None:
    """_NoOpSpan works as a context manager."""
    span = _NoOpSpan()
    with span as s:
        assert s is span
        s.set_attribute("foo", 42)
        s.set_status("OK")
        s.record_exception(RuntimeError("boom"))


# ---------------------------------------------------------------------------
# timed_operation
# ---------------------------------------------------------------------------


def test_timed_operation_commit() -> None:
    """timed_operation wraps a block and emits latency metrics without error."""
    with timed_operation("commit", shard_id="test-shard") as span:
        span.set_attribute("key", "val")


def test_timed_operation_verify() -> None:
    """timed_operation works for the verify operation."""
    with timed_operation("verify") as span:
        span.set_attribute("content_hash", "aa" * 32)


def test_timed_operation_propagates_exception() -> None:
    """timed_operation re-raises exceptions from the wrapped block."""
    with pytest.raises(ValueError, match="intentional"):
        with timed_operation("commit"):
            raise ValueError("intentional")


# ---------------------------------------------------------------------------
# Prometheus metrics stubs / real objects
# ---------------------------------------------------------------------------


def test_proof_latency_labels_and_observe() -> None:
    """PROOF_LATENCY.labels(...).observe() does not raise."""
    PROOF_LATENCY.labels(operation="commit").observe(0.05)


def test_ledger_height_labels_and_set() -> None:
    """LEDGER_HEIGHT.labels(...).set() does not raise."""
    LEDGER_HEIGHT.labels(shard_id="test-shard").set(42)


def test_smt_divergence_total_labels_and_inc() -> None:
    """SMT_DIVERGENCE_TOTAL.labels(...).inc() does not raise."""
    SMT_DIVERGENCE_TOTAL.labels(shard_id="test-shard").inc()


def test_ingest_total_labels_and_inc() -> None:
    """INGEST_TOTAL.labels(...).inc() does not raise."""
    INGEST_TOTAL.labels(outcome="committed").inc()
    INGEST_TOTAL.labels(outcome="deduplicated").inc()
    INGEST_TOTAL.labels(outcome="error").inc()


def test_partition_events_labels_and_inc() -> None:
    """PARTITION_EVENTS.labels(...).inc() does not raise."""
    PARTITION_EVENTS.labels(event="quorum_lost").inc()
    PARTITION_EVENTS.labels(event="quorum_recovered").inc()
    PARTITION_EVENTS.labels(event="quorum_healthy").inc()


def test_view_change_watermark_labels_and_set() -> None:
    """VIEW_CHANGE_WATERMARK.labels(...).set() does not raise."""
    VIEW_CHANGE_WATERMARK.labels(bound="low").set(0)
    VIEW_CHANGE_WATERMARK.labels(bound="high").set(5)


# ---------------------------------------------------------------------------
# record_smt_divergence
# ---------------------------------------------------------------------------


def test_record_smt_divergence_emits_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """record_smt_divergence emits a WARNING log and increments the counter."""
    with caplog.at_level(logging.WARNING, logger="protocol.telemetry"):
        record_smt_divergence(
            shard_id="shard-1",
            local_root="aa" * 32,
            remote_root="bb" * 32,
            remote_node="https://node2.example",
        )

    warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("smt_root_divergence" in m for m in warning_messages)


def test_record_smt_divergence_does_not_raise() -> None:
    """record_smt_divergence never raises regardless of input values."""
    record_smt_divergence(
        shard_id="",
        local_root="",
        remote_root="",
        remote_node="",
    )


# ---------------------------------------------------------------------------
# Availability flags
# ---------------------------------------------------------------------------


def test_prometheus_available_returns_bool() -> None:
    """prometheus_available() returns a bool."""
    result = prometheus_available()
    assert isinstance(result, bool)


def test_opentelemetry_available_returns_bool() -> None:
    """opentelemetry_available() returns a bool."""
    result = opentelemetry_available()
    assert isinstance(result, bool)
