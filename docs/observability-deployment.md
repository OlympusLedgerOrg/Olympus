# OpenTelemetry Deployment Guide for Olympus

*This document provides production deployment guidance for OpenTelemetry distributed tracing in Olympus.*

---

## Overview

Olympus instruments critical cryptographic flows (commit, verify, redact) with OpenTelemetry spans. This enables:

1. **End-to-end latency analysis** across API → protocol → storage layers
2. **Causality tracking** for multi-step operations (batch ingestion, redaction proof generation)
3. **Failure attribution** via automatic exception recording in spans
4. **Cross-service correlation** in federated deployments (Phase 1+)

---

## Prerequisites

- Python ≥ 3.10
- Olympus installed with `[observability]` extra: `pip install "olympus[observability]"`
- OpenTelemetry Collector (optional but recommended for production)
- Trace backend: Jaeger, Zipkin, Tempo, or cloud-native solution (Datadog, Honeycomb, etc.)

---

## Installation

### Development Setup (Console Exporter)

The default configuration exports traces to stdout, useful for local development:

```bash
pip install "olympus[observability]"
```

This installs:
- `opentelemetry-api==1.40.0`
- `opentelemetry-sdk==1.40.0`

No additional configuration required — traces will print to console when telemetry operations occur.

### Production Setup (OTLP Exporter)

For production, send traces to an OpenTelemetry Collector or directly to a backend:

```bash
pip install opentelemetry-exporter-otlp-proto-grpc
```

Then configure via environment variables (see Configuration section below).

---

## Configuration

### Environment Variables

Olympus respects standard OpenTelemetry environment variables:

| Variable | Purpose | Example |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector/backend URL | `http://otel-collector:4317` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | Protocol (grpc or http/protobuf) | `grpc` |
| `OTEL_SERVICE_NAME` | Override service name | `olympus-api-prod` |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes | `deployment.environment=production,region=us-east-1` |
| `OTEL_TRACES_SAMPLER` | Sampling strategy | `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | Sampler argument (e.g., ratio) | `0.1` (10% sampling) |

### Application Code Changes

**No code changes required.** Olympus already uses `protocol.telemetry.get_tracer()` and `timed_operation()` throughout the codebase.

To enable OTLP export, update `protocol/telemetry.py`:

```python
# Replace ConsoleSpanExporter with OTLP
try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _provider = TracerProvider(
        resource=Resource.create({
            "service.name": os.getenv("OTEL_SERVICE_NAME", "olympus-ledger"),
        }),
    )
    # OTLP exporter reads OTEL_EXPORTER_OTLP_ENDPOINT from environment
    _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    _otel_trace.set_tracer_provider(_provider)
    _OTEL_AVAILABLE = True
except ImportError:
    pass
```

Or use automatic instrumentation (see below).

---

## Deployment Patterns

### Pattern 1: Direct to Backend

Simple for small deployments. API sends traces directly to backend:

```
┌─────────────┐
│ Olympus API │
└──────┬──────┘
       │ OTLP/gRPC
       ▼
┌─────────────┐
│   Jaeger    │
└─────────────┘
```

**Configuration:**
```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
export OTEL_SERVICE_NAME=olympus-api
```

---

### Pattern 2: Via OpenTelemetry Collector (Recommended)

Collector provides buffering, sampling, and backend flexibility:

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ Olympus API │──────▶│ OTel        │──────▶│   Jaeger    │
└─────────────┘ OTLP  │ Collector   │ OTLP  └─────────────┘
                       └──────┬──────┘
                              │
                              ▼
                       ┌─────────────┐
                       │  Prometheus │ (optional: trace metrics)
                       └─────────────┘
```

**Collector Configuration (`otel-collector-config.yaml`):**

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 10s
    send_batch_size: 1024

  # Tail-based sampling: keep all error traces, sample 10% success
  tail_sampling:
    decision_wait: 10s
    policies:
      - name: errors
        type: status_code
        status_code:
          status_codes: [ERROR]
      - name: slow
        type: latency
        latency:
          threshold_ms: 2000
      - name: sample_success
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

  resource:
    attributes:
      - key: deployment.environment
        value: production
        action: upsert

exporters:
  otlp:
    endpoint: jaeger:4317
    tls:
      insecure: true

  # Optional: export span metrics to Prometheus
  prometheus:
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, tail_sampling, resource]
      exporters: [otlp, prometheus]
```

**Docker Compose:**

```yaml
services:
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.91.0
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    command: ["--config=/etc/otel-collector-config.yaml"]
    ports:
      - "4317:4317"  # OTLP gRPC
      - "4318:4318"  # OTLP HTTP
      - "8889:8889"  # Prometheus metrics

  jaeger:
    image: jaegertracing/all-in-one:1.52
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317"         # OTLP receiver
```

**Olympus API Configuration:**

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
export OTEL_SERVICE_NAME=olympus-api
```

---

### Pattern 3: Federated Multi-Region

Each region has a collector; traces aggregated to central backend:

```
Region US-East                      Region EU-West
┌─────────────┐                     ┌─────────────┐
│ Olympus API │                     │ Olympus API │
└──────┬──────┘                     └──────┬──────┘
       │                                   │
       ▼                                   ▼
┌─────────────┐                     ┌─────────────┐
│ Collector   │                     │ Collector   │
└──────┬──────┘                     └──────┬──────┘
       │                                   │
       └───────────────┬───────────────────┘
                       ▼
                ┌─────────────┐
                │   Tempo     │
                │  (central)  │
                └─────────────┘
```

Each regional collector adds `region` attribute via resource processor.

---

## Trace Schema

### Span Naming Convention

Olympus follows the `<module>.<operation>` naming pattern:

| Span Name | Source | Attributes | Parent |
|-----------|--------|------------|--------|
| `olympus.commit` | `api/ingest.py` | `shard_id`, `record_count` | — |
| `olympus.verify` | `api/ingest.py` | `content_hash` | — |
| `redaction.commit_document` | `protocol/redaction.py` | `document_parts_count`, `merkle_root` | — |
| `redaction.create_proof` | `protocol/redaction.py` | `revealed_indices_count`, `original_root` | — |
| `redaction.verify_proof` | `protocol/redaction.py` | `revealed_indices_count`, `original_root`, `verification_result` | — |

### Span Attributes

Standard attributes set on all spans:

- `shard_id`: Target shard for ledger operations
- `operation`: One of `commit`, `verify`, `redact`
- `record_count`: Number of records in batch operations
- `content_hash`: BLAKE3 hash being verified
- `verification_result`: Outcome of verification (e.g., `success`, `failed_hash_mismatch_at_2`)

### Exception Recording

All exceptions are automatically recorded in spans via:

```python
with tracer.start_as_current_span("olympus.commit") as span:
    try:
        # ... operation
    except Exception as exc:
        span.record_exception(exc)
        raise
```

Exceptions populate:
- `exception.type`
- `exception.message`
- `exception.stacktrace`

---

## Sampling Strategies

### Development: Always On

```bash
export OTEL_TRACES_SAMPLER=always_on
```

### Production: Tail-Based Sampling (Recommended)

Use the OpenTelemetry Collector's `tail_sampling` processor to:
- **Keep 100%** of error traces
- **Keep 100%** of slow traces (> 2s)
- **Sample 10%** of successful fast traces

This ensures debugging data is always available for failures while controlling volume.

### High-Volume: Head-Based Sampling

For extremely high-volume deployments, use head-based sampling in the SDK:

```bash
export OTEL_TRACES_SAMPLER=traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.01  # 1% sampling
```

**Trade-off:** You may miss traces for rare errors.

---

## Querying Traces

### Example Queries (Jaeger UI)

**Find slow commit operations:**
```
service=olympus-api operation=olympus.commit minDuration=2s
```

**Find failed redaction verifications:**
```
service=olympus-api operation=redaction.verify_proof tags="verification_result:failed*"
```

**Find all operations for a shard:**
```
service=olympus-api tags="shard_id:prod-shard-01"
```

### Example Queries (Tempo + Grafana)

TraceQL query for failed verifications:

```
{
  name="redaction.verify_proof" &&
  resource.service.name="olympus-api" &&
  span.verification_result=~"failed.*"
}
```

---

## Instrumentation Details

### API Layer (`api/ingest.py`)

Commit and verify endpoints use `timed_operation()` context manager:

```python
from protocol.telemetry import timed_operation

@router.post("/ingest/records")
async def ingest_records(request: BatchIngestionRequest):
    with timed_operation("commit", shard_id=shard_id) as span:
        span.set_attribute("record_count", len(request.records))
        # ... perform commit
```

This automatically:
1. Creates an OpenTelemetry span
2. Records span duration in Prometheus `olympus_proof_generation_seconds` histogram
3. Records exceptions if the block raises

### Protocol Layer (`protocol/redaction.py`)

Redaction operations use manual span creation for fine-grained control:

```python
from protocol.telemetry import get_tracer

tracer = get_tracer()
with tracer.start_as_current_span("redaction.verify_proof") as span:
    span.set_attribute("revealed_indices_count", len(proof.revealed_indices))
    span.set_attribute("original_root", proof.original_root)
    # ... perform verification
    span.set_attribute("verification_result", "success")
```

Failure paths set descriptive `verification_result` attributes:
- `failed_content_length_mismatch`
- `failed_hash_mismatch_at_2`
- `failed_merkle_proof_invalid_at_3`

---

## Performance Considerations

### Overhead

OpenTelemetry SDK overhead is typically **< 1% CPU** and **< 10 MB memory** per process.

Span creation cost: **~1 µs** per span (negligible for cryptographic operations that take milliseconds).

### Batching

The `BatchSpanProcessor` buffers spans and sends them asynchronously. Default configuration:
- Max batch size: 512 spans
- Max queue size: 2048 spans
- Export interval: 5 seconds

For high-throughput deployments, increase buffer sizes:

```python
from opentelemetry.sdk.trace.export import BatchSpanProcessor

processor = BatchSpanProcessor(
    OTLPSpanExporter(),
    max_queue_size=8192,
    max_export_batch_size=2048,
    schedule_delay_millis=5000,
)
```

---

## Troubleshooting

### Traces Not Appearing in Backend

**Check 1:** Verify OTLP endpoint is reachable:
```bash
curl -v http://otel-collector:4317
```

**Check 2:** Ensure observability packages are installed:
```bash
python -c "from opentelemetry import trace; print('OK')"
```

**Check 3:** Check API logs for exporter errors:
```bash
grep "OTLPSpanExporter" /var/log/olympus/api.log
```

**Check 4:** Enable debug logging in the SDK:
```bash
export OTEL_LOG_LEVEL=debug
```

---

### High Trace Volume

**Symptom:** Collector falling behind, high memory usage.

**Solution 1:** Enable tail-based sampling in the collector (see Pattern 2 above).

**Solution 2:** Reduce head-based sampling ratio:
```bash
export OTEL_TRACES_SAMPLER_ARG=0.01  # 1% sampling
```

**Solution 3:** Scale the collector horizontally behind a load balancer.

---

### Missing Attributes

**Symptom:** Spans appear but lack `shard_id` or other attributes.

**Solution:** Verify the attribute is set in the instrumentation code. Example:

```python
span.set_attribute("shard_id", shard_id)
```

If `shard_id` is `None`, the attribute will be omitted. Ensure the value is always set.

---

## Testing

### Manual Trace Generation

```python
from protocol.telemetry import get_tracer

tracer = get_tracer()
with tracer.start_as_current_span("test.manual") as span:
    span.set_attribute("test_attribute", "test_value")
    print("Trace generated")
```

Run the API and check the backend for the `test.manual` span.

### Automated Testing

Olympus tests do not require a live trace backend. The `_NoOpTracer` stub is used when OpenTelemetry is not installed:

```bash
pytest tests/test_redaction_semantics.py -v
```

Traces are generated but not exported (graceful degradation).

---

## Production Checklist

- [ ] Observability extras installed: `pip install "olympus[observability]"`
- [ ] OTLP exporter configured (not console exporter)
- [ ] `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable set
- [ ] OpenTelemetry Collector deployed and running
- [ ] Tail-based sampling configured in collector
- [ ] Backend (Jaeger/Tempo) accessible and ingesting traces
- [ ] Dashboards created for trace latency and error rates
- [ ] On-call team trained on trace query syntax
- [ ] Sampling strategy validated under production load

---

## Advanced: Custom Instrumentation

### Adding New Spans

To instrument a new operation:

```python
from protocol.telemetry import get_tracer

def my_new_operation(param: str) -> str:
    tracer = get_tracer()
    with tracer.start_as_current_span("my_module.my_operation") as span:
        span.set_attribute("param", param)
        # ... perform work
        result = "output"
        span.set_attribute("result_length", len(result))
        return result
```

### Span Links (Phase 1+ Federation)

To link spans across federation nodes:

```python
from opentelemetry import trace

# On node A
span_context = trace.get_current_span().get_span_context()
link_data = {
    "trace_id": span_context.trace_id,
    "span_id": span_context.span_id,
}

# Send link_data to node B via federation protocol

# On node B
from opentelemetry.trace import Link, SpanContext

span_context = SpanContext(
    trace_id=link_data["trace_id"],
    span_id=link_data["span_id"],
    is_remote=True,
)
with tracer.start_as_current_span("federation.verify_quorum", links=[Link(span_context)]) as span:
    # ... verification work
```

This creates a distributed trace across the federation.

---

## References

- OpenTelemetry Python Docs: https://opentelemetry.io/docs/instrumentation/python/
- OTLP Specification: https://opentelemetry.io/docs/reference/specification/protocol/otlp/
- Collector Configuration: https://opentelemetry.io/docs/collector/configuration/
- Olympus Telemetry Module: [`protocol/telemetry.py`](../protocol/telemetry.py)
- Prometheus Integration: [`docs/prometheus-alerting.md`](prometheus-alerting.md)
