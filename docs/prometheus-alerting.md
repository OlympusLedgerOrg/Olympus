# Prometheus Alerting for Olympus

*This document provides production-ready Prometheus alerting rules and configuration examples for the Olympus ledger system.*

---

## Overview

Olympus exports Prometheus metrics covering cryptographic proof generation, ledger state, and integrity divergence. This guide provides:

1. **Core alerting rules** for operational and security monitoring
2. **Alert severity classification** and recommended escalation paths
3. **Prometheus configuration** examples for scraping and federation
4. **Grafana dashboard** recommendations

---

## Prerequisites

- Prometheus server (≥ 2.30)
- Alertmanager (for alert routing and deduplication)
- Olympus API deployed with `[observability]` extra: `pip install "olympus[observability]"`

---

## Metrics Catalog

### Proof Generation Latency

**Metric:** `olympus_proof_generation_seconds{operation="commit|verify|redact"}`
**Type:** Histogram
**Labels:** `operation`
**Purpose:** Track cryptographic operation performance

**Usage:**
```promql
# 95th percentile proof latency by operation
histogram_quantile(0.95, rate(olympus_proof_generation_seconds_bucket[5m]))

# Slow operations (> 2s)
rate(olympus_proof_generation_seconds_bucket{le="2.5"}[5m]) < 0.95
```

---

### Ledger Height

**Metric:** `olympus_ledger_height{shard_id="<shard>"}`
**Type:** Gauge
**Labels:** `shard_id`
**Purpose:** Track current number of committed entries per shard

**Usage:**
```promql
# Current ledger height by shard
olympus_ledger_height

# Stalled ingestion (no height increase in 10m)
increase(olympus_ledger_height[10m]) == 0
```

---

### SMT Root Divergence

**Metric:** `olympus_smt_root_divergence_total{shard_id="<shard>"}`
**Type:** Counter
**Labels:** `shard_id`
**Purpose:** Detect when replicas report different SMT roots (tampering or replication bug)

**Usage:**
```promql
# Any increase in divergence counter
increase(olympus_smt_root_divergence_total[5m]) > 0
```

---

### Ingestion Operations

**Metric:** `olympus_ingest_operations_total{outcome="committed|deduplicated|error"}`
**Type:** Counter
**Labels:** `outcome`
**Purpose:** Track ingestion throughput and error rates

**Usage:**
```promql
# Error rate
rate(olympus_ingest_operations_total{outcome="error"}[5m])

# Success rate
rate(olympus_ingest_operations_total{outcome="committed"}[5m])
```

---

## Production Alerting Rules

### Critical Alerts (Page Immediately)

These alerts indicate active integrity violations or system compromise.

#### SMT Root Divergence

```yaml
groups:
  - name: olympus_integrity
    interval: 30s
    rules:
      - alert: OlympusSMTRootDivergence
        expr: increase(olympus_smt_root_divergence_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
          component: federation
        annotations:
          summary: "SMT root mismatch detected between federation nodes"
          description: |
            Shard {{ $labels.shard_id }} has detected an SMT root divergence.
            This indicates either:
            1. A replication bug causing inconsistent state
            2. Active tampering by a compromised node

            Immediate action required:
            - Check logs for `smt_root_divergence_detected` warnings
            - Compare shard headers across all federation nodes
            - Initiate incident response if tampering is suspected

            Current divergence count: {{ $value }}
          runbook_url: https://olympus-docs.example/runbooks/smt-divergence
```

#### Proof Generation Failure Spike

```yaml
      - alert: OlympusProofGenerationFailures
        expr: rate(olympus_ingest_operations_total{outcome="error"}[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
          component: cryptography
        annotations:
          summary: "High rate of proof generation failures"
          description: |
            Proof generation is failing at {{ $value | humanizePercentage }} of requests.

            Possible causes:
            - Database connection issues
            - Corrupted Merkle tree state
            - Resource exhaustion

            Check logs for exception traces and database connectivity.
```

---

### High Alerts (Investigate Within 30 Minutes)

These alerts indicate performance degradation or operational issues.

#### Slow Proof Generation

```yaml
      - alert: OlympusSlowProofGeneration
        expr: |
          histogram_quantile(0.95, rate(olympus_proof_generation_seconds_bucket[5m]))
          > 2.5
        for: 5m
        labels:
          severity: high
          component: performance
        annotations:
          summary: "Proof generation latency exceeds 2.5s at p95"
          description: |
            95th percentile proof latency: {{ $value }}s
            Operation: {{ $labels.operation }}

            This may indicate:
            - Database query slowness
            - CPU/memory resource contention
            - Large Merkle tree depth

            Review resource utilization and database query plans.
```

#### Stalled Ledger Ingestion

```yaml
      - alert: OlympusIngestStalled
        expr: increase(olympus_ledger_height[10m]) == 0
        for: 10m
        labels:
          severity: high
          component: ingestion
        annotations:
          summary: "No new ledger entries in 10 minutes"
          description: |
            Shard {{ $labels.shard_id }} has not ingested any new entries.
            Current height: {{ $value }}

            Check:
            - API endpoint health (/health)
            - Database write permissions
            - Client submission errors
```

---

### Medium Alerts (Investigate Within 24 Hours)

These alerts indicate potential future issues or anomalies.

#### High Deduplication Rate

```yaml
      - alert: OlympusHighDeduplicationRate
        expr: |
          rate(olympus_ingest_operations_total{outcome="deduplicated"}[5m])
          /
          rate(olympus_ingest_operations_total[5m])
          > 0.5
        for: 15m
        labels:
          severity: medium
          component: ingestion
        annotations:
          summary: "Over 50% of submissions are duplicates"
          description: |
            Deduplication rate: {{ $value | humanizePercentage }}

            This may indicate:
            - Client retry logic submitting the same records
            - Lack of client-side content-hash caching
            - Intentional re-submission for proof retrieval

            Review client integration patterns.
```

#### Sustained High Ingestion Volume

```yaml
      - alert: OlympusHighIngestionVolume
        expr: rate(olympus_ingest_operations_total{outcome="committed"}[5m]) > 100
        for: 30m
        labels:
          severity: medium
          component: capacity
        annotations:
          summary: "Sustained high ingestion rate"
          description: |
            Ingestion rate: {{ $value }} commits/sec

            Monitor for capacity planning:
            - Database disk usage growth
            - SMT insertion performance
            - Replication lag (if Phase 1+ deployed)
```

---

## Prometheus Configuration

### Scrape Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'olympus-api'
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: '/metrics'
    static_configs:
      - targets:
          - 'olympus-api-1.example.com:8000'
          - 'olympus-api-2.example.com:8000'
          - 'olympus-api-3.example.com:8000'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
      - source_labels: [__address__]
        regex: 'olympus-api-(\d+)\..*'
        target_label: node_id
        replacement: 'node-$1'
```

### Federation (Multi-Region)

If deploying multiple Prometheus instances (e.g., one per region):

```yaml
# In the global Prometheus aggregator
scrape_configs:
  - job_name: 'federated-olympus'
    scrape_interval: 30s
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job="olympus-api"}'
        - '{__name__=~"olympus_.*"}'
    static_configs:
      - targets:
          - 'prom-us-east.example.com:9090'
          - 'prom-eu-west.example.com:9090'
          - 'prom-ap-south.example.com:9090'
```

---

## Alertmanager Configuration

### Route Hierarchy

```yaml
route:
  group_by: ['alertname', 'shard_id']
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'default-receiver'

  routes:
    # Critical alerts → page on-call immediately
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      group_wait: 0s
      repeat_interval: 5m

    # High alerts → notify Slack + email
    - match:
        severity: high
      receiver: 'slack-high-email'
      group_interval: 10m

    # Medium alerts → Slack only
    - match:
        severity: medium
      receiver: 'slack-medium'

receivers:
  - name: 'default-receiver'
    webhook_configs:
      - url: 'http://webhook.example.com/alerts'

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '<PAGERDUTY_SERVICE_KEY>'
        severity: 'critical'
        description: '{{ .GroupLabels.alertname }}: {{ .CommonAnnotations.summary }}'

  - name: 'slack-high-email'
    slack_configs:
      - api_url: '<SLACK_WEBHOOK_URL>'
        channel: '#olympus-alerts'
        title: '🚨 {{ .GroupLabels.alertname }}'
        text: '{{ .CommonAnnotations.description }}'
    email_configs:
      - to: 'oncall@example.com'
        from: 'alerts@olympus.example.com'
        smarthost: 'smtp.example.com:587'

  - name: 'slack-medium'
    slack_configs:
      - api_url: '<SLACK_WEBHOOK_URL>'
        channel: '#olympus-monitoring'
        title: '⚠️ {{ .GroupLabels.alertname }}'
        text: '{{ .CommonAnnotations.description }}'
```

---

## Grafana Dashboards

### Recommended Panels

#### Proof Latency Heatmap

```json
{
  "type": "heatmap",
  "targets": [
    {
      "expr": "sum(rate(olympus_proof_generation_seconds_bucket[5m])) by (le, operation)"
    }
  ],
  "yAxis": {
    "format": "s"
  }
}
```

#### Ledger Height by Shard

```json
{
  "type": "graph",
  "targets": [
    {
      "expr": "olympus_ledger_height",
      "legendFormat": "{{ shard_id }}"
    }
  ],
  "yAxes": [{
    "format": "short",
    "label": "Entry Count"
  }]
}
```

#### Ingestion Rate by Outcome

```json
{
  "type": "graph",
  "targets": [
    {
      "expr": "rate(olympus_ingest_operations_total[5m])",
      "legendFormat": "{{ outcome }}"
    }
  ],
  "yAxes": [{
    "format": "ops",
    "label": "Operations/sec"
  }]
}
```

---

## Testing Alerts

### Simulate SMT Divergence

```python
from protocol.telemetry import record_smt_divergence

record_smt_divergence(
    shard_id="test-shard",
    local_root="abc123...",
    remote_root="def456...",
    remote_node="node-2"
)
```

Expected behavior:
- Prometheus counter increments
- Alert fires within 30 seconds
- Alertmanager routes to critical receiver

### Inject High Latency

```python
import time
from protocol.telemetry import PROOF_LATENCY

for _ in range(100):
    # Simulate slow proof generation
    PROOF_LATENCY.labels(operation="commit").observe(3.5)
    time.sleep(0.1)
```

Expected behavior:
- p95 latency crosses 2.5s threshold
- Alert fires after 5-minute `for` duration
- Alertmanager routes to high receiver

---

## Runbooks

### SMT Root Divergence Response

1. **Immediate:** Stop accepting new commits to affected shard
2. **Investigate:**
   - Check logs for `smt_root_divergence_detected` entries
   - Compare `/shards/{id}/header/latest` across all nodes
   - Verify federation quorum certificate signatures
3. **Remediate:**
   - If replication bug: restore from backup, replay ledger entries
   - If tampering: revoke compromised node key, re-sign headers with superseding signature
4. **Post-incident:** Update threat model, add regression test

### Proof Generation Failure Response

1. **Check database connectivity:** `psql $DATABASE_URL -c "SELECT 1"`
2. **Review error logs:** `grep "exception" /var/log/olympus/api.log`
3. **Verify disk space:** `df -h`
4. **Restart API service if connection pool exhausted:** `systemctl restart olympus-api`

---

## Integration with Chaos Tests

Olympus includes automated fault injection tests that validate observable failure modes:

| Fault | Chaos Test | Expected Metric Behavior |
|-------|------------|--------------------------|
| Disk full | `tests/chaos/test_disk_full.py` | `olympus_ingest_operations_total{outcome="error"}` increases |
| Network partition | `tests/chaos/test_network_partition.py` | No immediate alert (local commit succeeds) |
| Clock skew | `tests/chaos/test_clock_skew.py` | No alert (timestamps are accepted) |
| DB connection loss | `tests/chaos/test_db_connection_loss.py` | `olympus_ingest_operations_total{outcome="error"}` spikes |

Run chaos tests: `pytest tests/chaos/ -v`

See [`tests/chaos/README.md`](../tests/chaos/README.md) for detailed expected system behavior.

---

## Production Checklist

- [ ] Prometheus scraping Olympus `/metrics` endpoint every 15s
- [ ] Alerting rules deployed and active
- [ ] Alertmanager routing configured with PagerDuty + Slack
- [ ] Grafana dashboards imported and accessible
- [ ] Alert runbooks linked from annotations
- [ ] On-call rotation includes Olympus responders
- [ ] SMT divergence alerts tested with synthetic events
- [ ] Backup Prometheus instance for high-availability

---

## References

- Metrics Implementation: [`protocol/telemetry.py`](../protocol/telemetry.py)
- Threat Model: [`docs/threat-model-mitigations.md`](threat-model-mitigations.md)
- Chaos Tests: [`tests/chaos/README.md`](../tests/chaos/README.md)
- Prometheus Docs: https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/
- Alertmanager Docs: https://prometheus.io/docs/alerting/latest/configuration/
