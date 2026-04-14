"""
Structured observability for Olympus — OpenTelemetry traces and Prometheus metrics.

This module provides:
- A configured OpenTelemetry tracer (``get_tracer``) for instrumenting
  commit / verify / redact flows with structured spans.
- Prometheus metrics covering proof-generation latency, ledger height, and
  SMT root divergence between nodes.
- A helper ``record_smt_divergence`` that increments the divergence counter
  and emits a warning log whenever two replicas report different SMT roots
  for the same shard.
- Distributed trace-context propagation helpers for cross-service spans
  (Python → Go sequencer → Rust CD-HS-ST).
- Health-check helpers exposing readiness/liveness state for Prometheus and
  Kubernetes probes.

Graceful degradation
--------------------
Both the OpenTelemetry SDK and ``prometheus-client`` are optional at import
time.  When they are absent, stub no-op implementations are used so the rest
of the codebase never has to guard against ``ImportError``.

Usage
-----
Wrap an operation with a span::

    from protocol.telemetry import get_tracer

    tracer = get_tracer()
    with tracer.start_as_current_span("ingest.commit") as span:
        span.set_attribute("shard_id", shard_id)
        ... # do work

Record a completed proof::

    from protocol.telemetry import PROOF_LATENCY, LEDGER_HEIGHT

    PROOF_LATENCY.labels(operation="commit").observe(elapsed_seconds)
    LEDGER_HEIGHT.set(new_height)

Alert on SMT root divergence::

    from protocol.telemetry import record_smt_divergence

    record_smt_divergence(shard_id, local_root, remote_root, remote_node)

Propagate trace context to Go/Rust services::

    from protocol.telemetry import inject_trace_context, extract_trace_context

    headers = inject_trace_context()
    # Pass headers to Go sequencer via gRPC metadata or HTTP headers
    # On the receiving side:
    ctx = extract_trace_context(headers)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from .log_sanitization import sanitize_for_log


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenTelemetry setup (optional dependency)
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False
_OTEL_PROPAGATOR_AVAILABLE = False

try:  # pragma: no cover
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    _resource = Resource.create({
        "service.name": os.getenv("OTEL_SERVICE_NAME", "olympus-ledger"),
        "service.version": os.getenv("OLYMPUS_VERSION", "0.0.0"),
        "deployment.environment": os.getenv("OLYMPUS_ENVIRONMENT", "development"),
    })

    _provider = TracerProvider(resource=_resource)

    # Auto-configure exporter: OTLP gRPC if OTEL_EXPORTER_OTLP_ENDPOINT is set,
    # otherwise fall back to console exporter for local development.
    _otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if _otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            _provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=_otlp_endpoint))
            )
        except ImportError:
            logger.warning(
                "OTEL_EXPORTER_OTLP_ENDPOINT is set but "
                "opentelemetry-exporter-otlp-proto-grpc is not installed; "
                "falling back to console exporter"
            )
            _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    _otel_trace.set_tracer_provider(_provider)
    _OTEL_AVAILABLE = True

    # Try to import propagation utilities for cross-service context
    try:
        from opentelemetry import context as _otel_context
        from opentelemetry.propagate import extract as _otel_extract
        from opentelemetry.propagate import inject as _otel_inject

        _OTEL_PROPAGATOR_AVAILABLE = True
    except ImportError:
        pass

except ImportError:
    pass


class _NoOpSpan:
    """Minimal no-op span used when OTel is unavailable."""

    def set_attribute(self, key: str, value: object) -> None:
        return

    def set_status(self, status: object) -> None:
        return

    def record_exception(self, exc: BaseException) -> None:
        return

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *_: object) -> None:
        return


class _NoOpTracer:
    """Minimal no-op tracer used when OTel is unavailable."""

    @contextmanager
    def start_as_current_span(
        self, name: str, **_kwargs: object
    ) -> Generator[_NoOpSpan, None, None]:
        yield _NoOpSpan()


def get_tracer(name: str = "olympus") -> Any:
    """
    Return an OpenTelemetry Tracer (or a no-op stub if OTel is not installed).

    Args:
        name: Instrumentation scope name (defaults to ``"olympus"``).

    Returns:
        A ``opentelemetry.trace.Tracer`` instance, or a no-op stub.
    """
    if _OTEL_AVAILABLE:  # pragma: no cover
        from opentelemetry import trace as _otel_trace  # re-import for type narrowing

        return _otel_trace.get_tracer(name)

    return _NoOpTracer()


# ---------------------------------------------------------------------------
# Prometheus metrics setup (optional dependency)
# ---------------------------------------------------------------------------

_PROM_AVAILABLE = False

try:  # pragma: no cover
    import prometheus_client as _prom

    # Proof-generation latency (seconds) broken down by operation type.
    # ``operation`` label values: ``"commit"``, ``"verify"``, ``"redact"``.
    PROOF_LATENCY = _prom.Histogram(
        "olympus_proof_generation_seconds",
        "Latency of cryptographic proof generation operations",
        labelnames=["operation"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )

    # Current ledger height (number of committed entries).
    LEDGER_HEIGHT = _prom.Gauge(
        "olympus_ledger_height",
        "Current number of entries in the append-only ledger",
    )

    # Total number of SMT root divergence events detected.
    # An alert rule should fire when this counter increases.
    SMT_DIVERGENCE_TOTAL = _prom.Counter(
        "olympus_smt_root_divergence_total",
        "Number of times an SMT root mismatch was detected between nodes",
    )

    LOAD_TREE_STATE_OUTSIDE_POSEIDON_TOTAL = _prom.Counter(
        "olympus_load_tree_state_outside_poseidon_total",
        "Number of deprecated _load_tree_state calls made outside the Poseidon carve-out",
    )

    # Total number of ingest operations by outcome.
    INGEST_TOTAL = _prom.Counter(
        "olympus_ingest_operations_total",
        "Total ingest operations by outcome",
        labelnames=["outcome"],  # "committed", "deduplicated", "error"
    )

    PARTITION_EVENTS = _prom.Counter(
        "olympus_partition_events_total",
        "Partition detector events by outcome",
        labelnames=["event"],  # "quorum_lost", "quorum_recovered", "quorum_healthy"
    )

    VIEW_CHANGE_WATERMARK = _prom.Gauge(
        "olympus_view_change_watermark",
        "Current view-change watermarks by bound",
        labelnames=["bound"],  # "low", "high"
    )

    # --- New metrics for distributed tracing and canonicalization ---

    # Canonicalization latency by format.
    CANONICALIZATION_LATENCY = _prom.Histogram(
        "olympus_canonicalization_seconds",
        "Latency of canonicalization operations by format",
        labelnames=["format"],  # "jcs", "html", "docx", "pdf", "plaintext", "xml", "csv"
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )

    # Sequencer batch size and latency.
    SEQUENCER_BATCH_SIZE = _prom.Histogram(
        "olympus_sequencer_batch_size",
        "Number of records per sequencer batch",
        buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000),
    )

    SEQUENCER_LATENCY = _prom.Histogram(
        "olympus_sequencer_seconds",
        "Latency of sequencer operations (batch commit to Rust service)",
        labelnames=["operation"],  # "batch_update", "get_root", "prove_inclusion"
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )

    # Proof verification counters.
    PROOF_VERIFICATION_TOTAL = _prom.Counter(
        "olympus_proof_verification_total",
        "Total proof verification attempts by result",
        labelnames=["result"],  # "valid", "invalid", "error"
    )

    # Cross-service span propagation failures.
    TRACE_PROPAGATION_FAILURES = _prom.Counter(
        "olympus_trace_propagation_failures_total",
        "Number of times trace context propagation failed between services",
        labelnames=["target_service"],  # "go_sequencer", "rust_cdhs"
    )

    # Health/readiness state.
    HEALTH_STATUS = _prom.Gauge(
        "olympus_health_status",
        "Health status of the service (1 = healthy, 0 = unhealthy)",
        labelnames=["component"],  # "api", "sequencer", "cdhs", "database"
    )

    _PROM_AVAILABLE = True

except ImportError:
    # Stub metric classes that silently absorb all calls.
    class _NullMetric:
        def labels(self, **_kwargs: object) -> _NullMetric:
            return self

        def observe(self, _v: float) -> None:
            return

        def set(self, _v: float) -> None:
            return

        def inc(self, _amount: float = 1) -> None:
            return

    PROOF_LATENCY = _NullMetric()
    LEDGER_HEIGHT = _NullMetric()
    SMT_DIVERGENCE_TOTAL = _NullMetric()
    LOAD_TREE_STATE_OUTSIDE_POSEIDON_TOTAL = _NullMetric()
    INGEST_TOTAL = _NullMetric()
    PARTITION_EVENTS = _NullMetric()
    VIEW_CHANGE_WATERMARK = _NullMetric()
    CANONICALIZATION_LATENCY = _NullMetric()
    SEQUENCER_BATCH_SIZE = _NullMetric()
    SEQUENCER_LATENCY = _NullMetric()
    PROOF_VERIFICATION_TOTAL = _NullMetric()
    TRACE_PROPAGATION_FAILURES = _NullMetric()
    HEALTH_STATUS = _NullMetric()


def prometheus_available() -> bool:
    """Return True if the prometheus-client library is installed."""
    return _PROM_AVAILABLE


def opentelemetry_available() -> bool:
    """Return True if the opentelemetry SDK is installed."""
    return _OTEL_AVAILABLE


# ---------------------------------------------------------------------------
# Context manager helpers
# ---------------------------------------------------------------------------


@contextmanager
def timed_operation(
    operation: str, shard_id: str | None = None
) -> Generator[_NoOpSpan, None, None]:
    """
    Context manager that instruments a named operation with both an OTel span
    and a Prometheus latency observation.

    Args:
        operation: Name of the operation (e.g. ``"commit"``, ``"verify"``,
                   ``"redact"``).  Used as the span name and Prometheus label.
        shard_id:  Optional shard identifier added as a span attribute.

    Yields:
        The active span (real or no-op).

    Example::

        with timed_operation("commit", shard_id=shard_id) as span:
            span.set_attribute("record_count", len(records))
            ... # perform work
    """
    tracer = get_tracer()
    start = time.monotonic()
    with tracer.start_as_current_span(f"olympus.{operation}") as span:
        if shard_id is not None:
            span.set_attribute("shard_id", shard_id)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            INGEST_TOTAL.labels(outcome="error").inc()
            raise
        finally:
            elapsed = time.monotonic() - start
            PROOF_LATENCY.labels(operation=operation).observe(elapsed)


# ---------------------------------------------------------------------------
# SMT root divergence helper
# ---------------------------------------------------------------------------


def record_smt_divergence(
    shard_id: str, local_root: str, remote_root: str, remote_node: str
) -> None:
    """
    Record an SMT root divergence event between the local node and a remote peer.

    This function:
    1. Increments the ``olympus_smt_root_divergence_total`` Prometheus counter
       for the affected shard (an alerting rule should fire on any increase).
    2. Emits a structured ``WARNING`` log entry with all relevant fields.

    In production a Prometheus alert rule such as::

        alert: OlympusSMTRootDivergence
        expr: increase(olympus_smt_root_divergence_total[5m]) > 0
        for: 0m
        severity: critical

    should page on-call immediately because any SMT root mismatch indicates
    either a replication bug or active tampering.

    Args:
        shard_id:    The shard whose SMT root diverged.
        local_root:  Hex-encoded SMT root computed locally.
        remote_root: Hex-encoded SMT root reported by the remote node.
        remote_node: Identifier (URL or node ID) of the remote peer.
    """
    SMT_DIVERGENCE_TOTAL.inc()
    logger.warning(
        "smt_root_divergence_detected",
        extra={
            "shard_id": sanitize_for_log(shard_id),
            "local_root": sanitize_for_log(local_root),
            "remote_root": sanitize_for_log(remote_root),
            "remote_node": sanitize_for_log(remote_node),
        },
    )


# ---------------------------------------------------------------------------
# Distributed trace context propagation (Python → Go → Rust)
# ---------------------------------------------------------------------------


def inject_trace_context(carrier: dict[str, str] | None = None) -> dict[str, str]:
    """Inject the current OpenTelemetry trace context into a carrier dict.

    The carrier can then be passed as gRPC metadata or HTTP headers to
    propagate the trace across service boundaries (e.g. Python API →
    Go sequencer → Rust CD-HS-ST).

    Uses the W3C TraceContext propagator (``traceparent`` / ``tracestate``
    headers) by default.

    Args:
        carrier: Optional existing dict to inject into.  A new dict is
            created if ``None``.

    Returns:
        The carrier dict with trace context headers injected (or an
        empty dict if OTel is not available).
    """
    if carrier is None:
        carrier = {}

    if _OTEL_PROPAGATOR_AVAILABLE:  # pragma: no cover
        _otel_inject(carrier)  # type: ignore[name-defined]

    return carrier


def extract_trace_context(carrier: dict[str, str]) -> Any:
    """Extract an OpenTelemetry context from incoming headers/metadata.

    Use this on the receiving side of a cross-service call to re-attach
    the parent span, producing a connected distributed trace.

    Args:
        carrier: Dict of header key-value pairs (e.g. gRPC metadata or
            HTTP headers from the upstream service).

    Returns:
        An ``opentelemetry.context.Context`` object (or ``None`` if OTel
        is not available).
    """
    if _OTEL_PROPAGATOR_AVAILABLE:  # pragma: no cover
        return _otel_extract(carrier)  # type: ignore[name-defined]

    return None


def attach_trace_context(ctx: Any) -> Any:
    """Attach an extracted trace context to the current execution.

    After calling :func:`extract_trace_context`, call this to make the
    extracted context active so that new spans become children of the
    upstream span.

    Args:
        ctx: Context object returned by :func:`extract_trace_context`.

    Returns:
        A token that can be used with ``detach_trace_context`` to
        restore the previous context, or ``None`` if OTel is not available.
    """
    if ctx is None:
        return None

    if _OTEL_PROPAGATOR_AVAILABLE:  # pragma: no cover
        return _otel_context.attach(ctx)  # type: ignore[name-defined]

    return None


def detach_trace_context(token: Any) -> None:
    """Detach a previously attached trace context.

    Args:
        token: Token returned by :func:`attach_trace_context`.
    """
    if token is None:
        return

    if _OTEL_PROPAGATOR_AVAILABLE:  # pragma: no cover
        _otel_context.detach(token)  # type: ignore[name-defined]


# ---------------------------------------------------------------------------
# Health / readiness helpers
# ---------------------------------------------------------------------------

_health_components: dict[str, bool] = {}


def set_health_status(component: str, *, healthy: bool) -> None:
    """Update the health status for a named component.

    This sets the ``olympus_health_status`` Prometheus gauge for
    observability dashboards and alerting, and stores the state for
    programmatic health checks.

    Args:
        component: Component name (e.g. ``"api"``, ``"sequencer"``,
            ``"cdhs"``, ``"database"``).
        healthy: Whether the component is healthy.
    """
    _health_components[component] = healthy
    HEALTH_STATUS.labels(component=component).set(1.0 if healthy else 0.0)


def get_health_status() -> dict[str, bool]:
    """Return the current health status of all registered components.

    Returns:
        Dict mapping component names to their health status.
    """
    return dict(_health_components)


def is_healthy() -> bool:
    """Return ``True`` if all registered components are healthy.

    Returns ``True`` when no components have been registered (vacuously
    healthy — the system has not started reporting yet).
    """
    if not _health_components:
        return True
    return all(_health_components.values())


@contextmanager
def timed_canonicalization(
    fmt: str,
) -> Generator[_NoOpSpan, None, None]:
    """Context manager that instruments a canonicalization operation.

    Records both an OTel span and a Prometheus histogram observation for
    the ``olympus_canonicalization_seconds`` metric.

    Args:
        fmt: Format name (e.g. ``"jcs"``, ``"plaintext"``, ``"xml"``).

    Yields:
        The active span (real or no-op).
    """
    tracer = get_tracer()
    start = time.monotonic()
    with tracer.start_as_current_span(f"olympus.canonicalize.{fmt}") as span:
        span.set_attribute("canonicalization.format", fmt)
        try:
            yield span
        finally:
            elapsed = time.monotonic() - start
            CANONICALIZATION_LATENCY.labels(format=fmt).observe(elapsed)


@contextmanager
def timed_sequencer_operation(
    operation: str, *, batch_size: int | None = None
) -> Generator[_NoOpSpan, None, None]:
    """Context manager that instruments a sequencer operation.

    Records an OTel span and Prometheus latency observation for the
    ``olympus_sequencer_seconds`` metric.  Optionally records the batch
    size.

    Args:
        operation: Operation name (e.g. ``"batch_update"``,
            ``"get_root"``, ``"prove_inclusion"``).
        batch_size: Optional number of records in the batch.

    Yields:
        The active span (real or no-op).
    """
    tracer = get_tracer()
    start = time.monotonic()
    with tracer.start_as_current_span(f"olympus.sequencer.{operation}") as span:
        span.set_attribute("sequencer.operation", operation)
        if batch_size is not None:
            span.set_attribute("sequencer.batch_size", batch_size)
            SEQUENCER_BATCH_SIZE.observe(batch_size)
        try:
            yield span
        finally:
            elapsed = time.monotonic() - start
            SEQUENCER_LATENCY.labels(operation=operation).observe(elapsed)


def record_proof_verification(*, valid: bool, error: bool = False) -> None:
    """Record a proof verification attempt.

    Args:
        valid: Whether the proof was valid.
        error: Whether an error occurred during verification.
    """
    if error:
        PROOF_VERIFICATION_TOTAL.labels(result="error").inc()
    elif valid:
        PROOF_VERIFICATION_TOTAL.labels(result="valid").inc()
    else:
        PROOF_VERIFICATION_TOTAL.labels(result="invalid").inc()
