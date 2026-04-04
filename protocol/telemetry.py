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
"""

from __future__ import annotations

import logging
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenTelemetry setup (optional dependency)
# ---------------------------------------------------------------------------

_OTEL_AVAILABLE = False

try:  # pragma: no cover
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    _provider = TracerProvider(
        resource=Resource.create({"service.name": "olympus-ledger"}),
    )
    # Default exporter: console / stdout.  In production, replace with an
    # OTLP exporter by setting OTEL_EXPORTER_OTLP_ENDPOINT in the environment
    # and using opentelemetry-exporter-otlp-proto-grpc.
    _provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    _otel_trace.set_tracer_provider(_provider)
    _OTEL_AVAILABLE = True
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
            "shard_id": shard_id,
            "local_root": local_root,
            "remote_root": remote_root,
            "remote_node": remote_node,
        },
    )
