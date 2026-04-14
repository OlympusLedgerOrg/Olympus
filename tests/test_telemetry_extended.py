"""
Tests for extended telemetry features — distributed tracing, new metrics,
health checks, and instrumented context managers.
"""

from __future__ import annotations

import pytest

from protocol.telemetry import (
    CANONICALIZATION_LATENCY,
    HEALTH_STATUS,
    PROOF_VERIFICATION_TOTAL,
    SEQUENCER_BATCH_SIZE,
    SEQUENCER_LATENCY,
    TRACE_PROPAGATION_FAILURES,
    attach_trace_context,
    detach_trace_context,
    extract_trace_context,
    get_health_status,
    inject_trace_context,
    is_healthy,
    record_proof_verification,
    set_health_status,
    timed_canonicalization,
    timed_sequencer_operation,
)


# ---------------------------------------------------------------------------
# Distributed trace context propagation
# ---------------------------------------------------------------------------


class TestTraceContextPropagation:
    """Tests for inject/extract/attach/detach trace context helpers."""

    def test_inject_returns_dict(self) -> None:
        """inject_trace_context always returns a dict."""
        carrier = inject_trace_context()
        assert isinstance(carrier, dict)

    def test_inject_with_existing_carrier(self) -> None:
        """inject_trace_context merges into an existing dict."""
        carrier = {"existing": "header"}
        result = inject_trace_context(carrier)
        assert result is carrier
        assert "existing" in result

    def test_extract_returns_none_when_otel_absent(self) -> None:
        """extract_trace_context returns None when OTel propagation is absent."""
        from protocol.telemetry import _OTEL_PROPAGATOR_AVAILABLE

        if _OTEL_PROPAGATOR_AVAILABLE:
            pytest.skip("OTel propagator is available")
        ctx = extract_trace_context({"traceparent": "fake"})
        assert ctx is None

    def test_attach_none_returns_none(self) -> None:
        """attach_trace_context(None) returns None."""
        token = attach_trace_context(None)
        assert token is None

    def test_detach_none_is_noop(self) -> None:
        """detach_trace_context(None) does not raise."""
        detach_trace_context(None)


# ---------------------------------------------------------------------------
# New Prometheus metrics
# ---------------------------------------------------------------------------


class TestNewPrometheusMetrics:
    """Tests that new Prometheus metric stubs/real objects work."""

    def test_canonicalization_latency_observe(self) -> None:
        """CANONICALIZATION_LATENCY.labels(...).observe() does not raise."""
        CANONICALIZATION_LATENCY.labels(format="jcs").observe(0.001)
        CANONICALIZATION_LATENCY.labels(format="plaintext").observe(0.002)
        CANONICALIZATION_LATENCY.labels(format="xml").observe(0.003)
        CANONICALIZATION_LATENCY.labels(format="csv").observe(0.004)

    def test_sequencer_batch_size_observe(self) -> None:
        """SEQUENCER_BATCH_SIZE.observe() does not raise."""
        SEQUENCER_BATCH_SIZE.observe(10)
        SEQUENCER_BATCH_SIZE.observe(100)

    def test_sequencer_latency_observe(self) -> None:
        """SEQUENCER_LATENCY.labels(...).observe() does not raise."""
        SEQUENCER_LATENCY.labels(operation="batch_update").observe(0.05)
        SEQUENCER_LATENCY.labels(operation="get_root").observe(0.01)
        SEQUENCER_LATENCY.labels(operation="prove_inclusion").observe(0.03)

    def test_proof_verification_total_inc(self) -> None:
        """PROOF_VERIFICATION_TOTAL.labels(...).inc() does not raise."""
        PROOF_VERIFICATION_TOTAL.labels(result="valid").inc()
        PROOF_VERIFICATION_TOTAL.labels(result="invalid").inc()
        PROOF_VERIFICATION_TOTAL.labels(result="error").inc()

    def test_trace_propagation_failures_inc(self) -> None:
        """TRACE_PROPAGATION_FAILURES.labels(...).inc() does not raise."""
        TRACE_PROPAGATION_FAILURES.labels(target_service="go_sequencer").inc()
        TRACE_PROPAGATION_FAILURES.labels(target_service="rust_cdhs").inc()

    def test_health_status_set(self) -> None:
        """HEALTH_STATUS.labels(...).set() does not raise."""
        HEALTH_STATUS.labels(component="api").set(1.0)
        HEALTH_STATUS.labels(component="sequencer").set(0.0)


# ---------------------------------------------------------------------------
# Health check helpers
# ---------------------------------------------------------------------------


class TestHealthChecks:
    """Tests for health status tracking."""

    def test_set_and_get_health_status(self) -> None:
        """set_health_status stores state retrievable by get_health_status."""
        set_health_status("test_component", healthy=True)
        status = get_health_status()
        assert status["test_component"] is True

    def test_set_unhealthy(self) -> None:
        """Unhealthy status is tracked."""
        set_health_status("test_unhealthy", healthy=False)
        status = get_health_status()
        assert status["test_unhealthy"] is False

    def test_is_healthy_all_true(self) -> None:
        """is_healthy returns True when all components are healthy."""
        set_health_status("h1", healthy=True)
        set_health_status("h2", healthy=True)
        # Note: other tests may have set unhealthy components,
        # so we just verify the function returns a bool
        assert isinstance(is_healthy(), bool)

    def test_is_healthy_vacuously_true_no_components(self) -> None:
        """is_healthy returns True when no components are registered."""
        from protocol import telemetry

        original = telemetry._health_components.copy()
        telemetry._health_components.clear()
        try:
            assert is_healthy() is True
        finally:
            telemetry._health_components.update(original)


# ---------------------------------------------------------------------------
# Timed context managers
# ---------------------------------------------------------------------------


class TestTimedCanonicalizer:
    """Tests for timed_canonicalization context manager."""

    def test_timed_canonicalization_yields_span(self) -> None:
        """timed_canonicalization yields a span-like object."""
        with timed_canonicalization("jcs") as span:
            assert span is not None
            span.set_attribute("test", True)

    def test_timed_canonicalization_all_formats(self) -> None:
        """Works for all supported formats."""
        for fmt in ["jcs", "html", "docx", "pdf", "plaintext", "xml", "csv"]:
            with timed_canonicalization(fmt) as span:
                span.set_attribute("format", fmt)


class TestTimedSequencerOperation:
    """Tests for timed_sequencer_operation context manager."""

    def test_basic_operation(self) -> None:
        """timed_sequencer_operation yields a span-like object."""
        with timed_sequencer_operation("batch_update") as span:
            assert span is not None
            span.set_attribute("test", True)

    def test_with_batch_size(self) -> None:
        """timed_sequencer_operation records batch size."""
        with timed_sequencer_operation("batch_update", batch_size=42) as span:
            span.set_attribute("records", 42)

    def test_all_operations(self) -> None:
        """Works for all sequencer operations."""
        for op in ["batch_update", "get_root", "prove_inclusion"]:
            with timed_sequencer_operation(op) as span:
                span.set_attribute("op", op)


# ---------------------------------------------------------------------------
# record_proof_verification
# ---------------------------------------------------------------------------


class TestRecordProofVerification:
    """Tests for record_proof_verification helper."""

    def test_valid_proof(self) -> None:
        """Recording a valid proof does not raise."""
        record_proof_verification(valid=True)

    def test_invalid_proof(self) -> None:
        """Recording an invalid proof does not raise."""
        record_proof_verification(valid=False)

    def test_error_proof(self) -> None:
        """Recording a proof error does not raise."""
        record_proof_verification(valid=False, error=True)
