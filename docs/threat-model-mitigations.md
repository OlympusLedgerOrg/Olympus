# Threat Model to Mitigations Mapping

*This document maps each threat identified in the Olympus threat model to its implemented mitigations with evidence links.*

---

## Overview

The Olympus threat model identifies adversaries capable of:
- Attempting ledger rewriting or history tampering
- Evidence suppression through record deletion
- Sybil attacks via fake federation nodes
- Spam submissions to degrade availability
- Malicious redaction claims
- Compromising signing keys
- Network-level attacks (replay, fork isolation)

Each threat is mitigated through a combination of cryptographic primitives, protocol design, monitoring, and operational controls.

---

## Threat → Mitigation Matrix

### 1. Ledger Rewriting Attack

**Threat:** A compromised operator or federation node attempts to alter historical commits after they were observed by verifiers.

**Adversary Type:** Malicious node, compromised ledger operator

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Hash chain linkage via `previous_hash` | [`protocol/ledger.py:52-104`](../protocol/ledger.py#L52-L104) | ✅ Implemented |
| Deterministic BLAKE3 hashing with domain separation | [`protocol/hashes.py:19-35`](../protocol/hashes.py#L19-L35) | ✅ Implemented |
| Append-only ledger verification | [`protocol/ledger.py:160-195`](../protocol/ledger.py#L160-L195) | ✅ Implemented |
| Federation quorum signatures on shard headers | [`protocol/federation.py:182-254`](../protocol/federation.py#L182-L254) | ✅ Implemented |
| RFC 3161 external timestamp anchoring | [`protocol/rfc3161.py:33-167`](../protocol/rfc3161.py#L33-L167) | ✅ Implemented |
| Prometheus SMT root divergence alerting | [`protocol/telemetry.py:248-287`](../protocol/telemetry.py#L248-L287) | ✅ Implemented |

**Detection:** Any modification changes the hash chain, causing `Ledger.verify_chain()` to fail. SMT root divergence between replicas triggers `record_smt_divergence()` and increments the `olympus_smt_root_divergence_total` Prometheus counter.

**Security Property:** Tamper evidence — mutations are cryptographically detectable.

---

### 2. Evidence Suppression

**Threat:** An authority pressures one node to delete or hide prior commits.

**Adversary Type:** Government actor, state-level coercion

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Federation replication across independent nodes | [`protocol/federation.py:1-41`](../protocol/federation.py#L1-L41) | ✅ Implemented (Phase 1+) |
| Public proof verification (Merkle inclusion proofs) | [`protocol/merkle.py:158-193`](../protocol/merkle.py#L158-L193) | ✅ Implemented |
| Auditor comparison of shard headers and ledger tails | [`docs/threat_model.md:55-61`](../docs/threat_model.md#L55-L61) | 📄 Documented |
| Sparse Merkle Tree (SMT) anchoring for shard state | [`storage/postgres.py:1015-1181`](../storage/postgres.py#L1015-L1181) | ✅ Implemented |

**Detection:** Deletion on one node does not erase the commitment from other replicas. Verifiers can independently check Merkle proofs against published roots.

**Residual Risk:** If all federation nodes collude to delete a record, the deletion is undetectable without external archival copies.

**Security Property:** Availability under partial failure — replication prevents silent gaps.

---

### 3. Sybil Node Attack

**Threat:** An attacker spins up many fake nodes to outvote honest operators in the federation quorum.

**Adversary Type:** Network attacker, malicious actor

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Controlled federation registry (static whitelist) | [`protocol/federation.py:8-41`](../protocol/federation.py#L8-L41) | ✅ Implemented |
| Ed25519 public key pinning per node | [`protocol/federation.py:22-96`](../protocol/federation.py#L22-L96) | ✅ Implemented |
| Quorum threshold (≥ 2/3 of registered nodes) | [`protocol/federation.py:182-205`](../protocol/federation.py#L182-L205) | ✅ Implemented |
| Institutional node operator vetting | [`docs/threat_model.md:77-82`](../docs/threat_model.md#L77-L82) | 📄 Operational control |

**Detection:** Signature verification rejects any signature from a node not present in the federation registry.

**Security Property:** Fork detection — conflicting shard headers or ledger tails are detectable via public comparison.

---

### 4. Spam Submissions

**Threat:** An attacker floods the ledger with junk commits to degrade service or drown out meaningful records.

**Adversary Type:** Spam attacker

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| API rate limiting per client | [`api/ingest.py:386-389`](../api/ingest.py#L386-L389) | ✅ Implemented |
| Batch ingestion size limits (max 1000 records/batch) | [`api/ingest.py:62-64`](../api/ingest.py#L62-L64) | ✅ Implemented |
| Request body size limits (enforced by web server) | [`docs/pentest-scope.md:106`](../docs/pentest-scope.md#L106) | 📄 Deployment concern |
| Prometheus ingestion metrics for monitoring | [`protocol/telemetry.py:160-166`](../protocol/telemetry.py#L160-L166) | ✅ Implemented |

**Detection:** Prometheus `olympus_ingest_operations_total` counter tracks ingestion volume by outcome. Spikes indicate potential abuse.

**Residual Risk:** Spam is primarily an availability and operations problem, not a cryptographic integrity failure.

**Security Property:** Graceful degradation under load.

---

### 5. Malicious Redaction Claim

**Threat:** An agency publishes a redacted artifact and falsely claims it corresponds to an earlier committed document.

**Adversary Type:** Government actor, insider

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Canonical document hashing (deterministic BLAKE3) | [`protocol/canonical.py:33-71`](../protocol/canonical.py#L33-L71) | ✅ Implemented |
| Merkle inclusion proof verification | [`protocol/redaction.py:188-249`](../protocol/redaction.py#L188-L249) | ✅ Implemented |
| SMT existence proofs for Poseidon roots | [`protocol/ssmf.py:358-401`](../protocol/ssmf.py#L358-L401) | ✅ Implemented |
| Zero-knowledge redaction proofs (Groth16) | [`protocol/redaction_ledger.py:187-223`](../protocol/redaction_ledger.py#L187-L223) | ✅ Implemented |
| OpenTelemetry tracing of redaction flows | [`protocol/redaction.py:139-145,168-186,212-249`](../protocol/redaction.py#L139-L249) | ✅ Implemented |

**Detection:** Redaction proof verification fails if the revealed content does not hash to the committed leaf hashes.

**Residual Risk:** Olympus can show that a redaction claim matches a real commitment, but it cannot force an agency to commit every document in the first place.

**Security Property:** Non-repudiation — Merkle proofs bind revealed content to committed roots.

---

### 6. Key Compromise / Node Impersonation

**Threat:** An attacker exfiltrates one node's signing key and tries to impersonate it or sign conflicting shard headers.

**Adversary Type:** Key thief, insider

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Ed25519 signature verification on all shard headers | [`protocol/federation.py:274-304`](../protocol/federation.py#L274-L304) | ✅ Implemented |
| Key rotation with validity windows | [`protocol/federation.py:97-108`](../protocol/federation.py#L97-L108) | ✅ Implemented |
| Historical key acceptance only up to header timestamp | [`protocol/federation.py:293-304`](../protocol/federation.py#L293-L304) | ✅ Implemented |
| Revocation records in governance log | [`protocol/shards.py:248-267`](../protocol/shards.py#L248-L267) | ✅ Implemented |
| Superseding signatures for post-compromise re-signing | [`protocol/shards.py:318-366`](../protocol/shards.py#L318-L366) | ✅ Implemented |

**Detection:** Any header signed after a revocation timestamp is rejected. Superseding signatures allow re-signing with a new key while preserving audit trail.

**Security Property:** Key compromise does not allow silent rewriting of history prior to the compromise timestamp.

---

### 7. Hash-Length Extension Attack

**Threat:** An attacker attempts to forge a Merkle commitment or ledger entry hash using a hash-length extension attack.

**Adversary Type:** Cryptographic attacker

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| BLAKE3 hash function (not vulnerable to length-extension) | [`protocol/hashes.py:48-72`](../protocol/hashes.py#L48-L72) | ✅ Implemented |
| Domain separation prefixes (`OLY:LEDGER:V1`, etc.) | [`protocol/hashes.py:19-33`](../protocol/hashes.py#L19-L33) | ✅ Implemented |
| Explicit protocol version in all hashes | [`protocol/hashes.py:23-35`](../protocol/hashes.py#L23-L35) | ✅ Implemented |

**Detection:** BLAKE3 provides collision and preimage resistance without length-extension vulnerability.

**Security Property:** Hash preimage resistance.

---

### 8. Canonicalization Drift / Unicode Normalization Attacks

**Threat:** An attacker submits documents that canonicalize to the same byte sequence as a different document, or exploits parser differentials between canonicalization and hashing.

**Adversary Type:** Malicious submitter

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Unicode NFC normalization | [`protocol/canonical.py:29-48`](../protocol/canonical.py#L29-L48) | ✅ Implemented |
| Duplicate JSON key rejection | [`protocol/canonical.py:56-71`](../protocol/canonical.py#L56-L71) | ✅ Implemented |
| JSON canonical encoding (RFC 8785 subset) | [`protocol/canonical_json.py:1-196`](../protocol/canonical_json.py) | ✅ Implemented |
| Version pinning and golden test vectors | [`verifiers/test_vectors/canonicalizer_vectors.tsv`](../verifiers/test_vectors/canonicalizer_vectors.tsv) | ✅ Implemented |
| Cross-language conformance tests | [`verifiers/cli/test_conformance.py`](../verifiers/cli/test_conformance.py) | ✅ Implemented |

**Detection:** Golden vectors in `verifiers/test_vectors/` prevent silent behavioral changes. Cross-language conformance tests ensure consistent hashing.

**Security Property:** Determinism — re-running canonicalization and hashing yields identical results.

---

### 9. SQL Injection / Storage Layer Attacks

**Threat:** An attacker exploits SQL injection vulnerabilities to bypass storage integrity checks or extract sensitive data.

**Adversary Type:** Network attacker, malicious submitter

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Parameterized queries (psycopg3) | [`storage/postgres.py:65-206`](../storage/postgres.py#L65-L206) | ✅ Implemented |
| Connection pooling with retry and circuit breaker | [`storage/postgres.py:65-206`](../storage/postgres.py#L65-L206) | ✅ Implemented |
| Database connection loss chaos testing | [`tests/chaos/test_db_connection_loss.py`](../tests/chaos/test_db_connection_loss.py) | ✅ Tested |
| Input validation on all API endpoints | [`api/ingest.py:49-86`](../api/ingest.py#L49-L86) | ✅ Implemented |

**Detection:** Parameterized queries prevent SQL injection. Chaos tests validate graceful degradation under database failures.

**Security Property:** Storage layer queries are injection-resistant.

---

### 10. Denial of Service / Resource Exhaustion

**Threat:** An attacker submits oversized payloads, degenerate Merkle inputs, or floods the API to exhaust system resources.

**Adversary Type:** Spam attacker, network attacker

**Mitigations:**

| Mitigation | Evidence | Status |
|------------|----------|--------|
| Request body size limits | [`docs/pentest-scope.md:106`](../docs/pentest-scope.md#L106) | 📄 Deployment concern |
| Batch size limits (max 1000 records) | [`api/ingest.py:62-64`](../api/ingest.py#L62-L64) | ✅ Implemented |
| Disk full chaos testing | [`tests/chaos/test_disk_full.py`](../tests/chaos/test_disk_full.py) | ✅ Tested |
| Network partition chaos testing | [`tests/chaos/test_network_partition.py`](../tests/chaos/test_network_partition.py) | ✅ Tested |
| Prometheus latency metrics for alerting | [`protocol/telemetry.py:136-143`](../protocol/telemetry.py#L136-L143) | ✅ Implemented |

**Detection:** Prometheus `olympus_proof_generation_seconds` histogram tracks proof latency. Spikes indicate resource exhaustion.

**Expected Behavior:** See [`tests/chaos/README.md`](../tests/chaos/README.md) for documented system behavior under each failure mode.

**Security Property:** Graceful degradation under resource exhaustion.

---

## Chaos Engineering Coverage

Olympus includes automated fault injection tests for the following failure modes:

| Fault | Test File | Expected Behavior | Status |
|-------|-----------|-------------------|--------|
| Disk full | [`tests/chaos/test_disk_full.py`](../tests/chaos/test_disk_full.py) | Write fails with clear error; no partial entries | ✅ 3 tests |
| Network partition | [`tests/chaos/test_network_partition.py`](../tests/chaos/test_network_partition.py) | Local commit succeeds; RFC 3161 degrades gracefully | ✅ 4 tests |
| Clock skew | [`tests/chaos/test_clock_skew.py`](../tests/chaos/test_clock_skew.py) | Timestamps accepted; chain ordering via hash linkage | ✅ 5 tests |
| DB connection loss | [`tests/chaos/test_db_connection_loss.py`](../tests/chaos/test_db_connection_loss.py) | HTTP 503 with structured error; retry with backoff | ✅ 5 tests |

Run the chaos suite with: `pytest tests/chaos/ -v`

See [`tests/chaos/README.md`](../tests/chaos/README.md) for detailed expected system behavior under each fault condition.

---

## CodeQL Security Analysis

The repository runs GitHub CodeQL with the extended security-and-quality query suite, covering:
- Injection flaws (SQL, command, path traversal)
- Weak cryptography
- Insecure deserialization
- Code quality patterns

**Configuration:** [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)

**Status:** ✅ Enabled on push, pull request, and weekly schedule

---

## Observability and Monitoring

### OpenTelemetry Traces

Structured traces are instrumented across key cryptographic flows:

| Operation | Span Name | Attributes | Evidence |
|-----------|-----------|------------|----------|
| Commit | `olympus.commit` | `shard_id`, `record_count` | [`api/ingest.py:404`](../api/ingest.py#L404) |
| Verify | `olympus.verify` | `content_hash` | [`api/ingest.py:554`](../api/ingest.py#L554) |
| Redaction commit | `redaction.commit_document` | `document_parts_count`, `merkle_root` | [`protocol/redaction.py:139-146`](../protocol/redaction.py#L139-L146) |
| Redaction proof creation | `redaction.create_proof` | `revealed_indices_count`, `original_root` | [`protocol/redaction.py:168-186`](../protocol/redaction.py#L168-L186) |
| Redaction proof verification | `redaction.verify_proof` | `revealed_indices_count`, `original_root`, `verification_result` | [`protocol/redaction.py:212-249`](../protocol/redaction.py#L212-L249) |

**See:** [`docs/observability-deployment.md`](observability-deployment.md) for exporter configuration.

### Prometheus Metrics

| Metric | Type | Labels | Purpose | Evidence |
|--------|------|--------|---------|----------|
| `olympus_proof_generation_seconds` | Histogram | `operation` | Proof latency tracking | [`protocol/telemetry.py:138-143`](../protocol/telemetry.py#L138-L143) |
| `olympus_ledger_height` | Gauge | `shard_id` | Current ledger height | [`protocol/telemetry.py:146-150`](../protocol/telemetry.py#L146-L150) |
| `olympus_smt_root_divergence_total` | Counter | `shard_id` | SMT root mismatches | [`protocol/telemetry.py:154-158`](../protocol/telemetry.py#L154-L158) |
| `olympus_ingest_operations_total` | Counter | `outcome` | Ingestion outcomes | [`protocol/telemetry.py:161-165`](../protocol/telemetry.py#L161-L165) |

**See:** [`docs/prometheus-alerting.md`](prometheus-alerting.md) for alerting rule examples.

---

## Responsible Disclosure

If you discover a security vulnerability, please follow the coordinated disclosure process:

1. **Do not** open a public GitHub issue.
2. Email `security@olympus-ledger.example` (or use GitHub's "Report a vulnerability" button).
3. Include: vulnerability class, reproduction steps, affected components, severity estimate.

**Timeline:**
- Acknowledgment: ≤ 2 business days
- Triage: ≤ 5 business days
- Patch: ≤ 30 days (critical), ≤ 90 days (others)

**See:** [`SECURITY.md`](../SECURITY.md) for full disclosure policy and penetration test scope.

---

## References

- Threat Model: [`docs/threat_model.md`](threat_model.md), [`docs/01_threat_model.md`](01_threat_model.md)
- Penetration Test Scope: [`docs/pentest-scope.md`](pentest-scope.md)
- Security Policy: [`SECURITY.md`](../SECURITY.md)
- Chaos Engineering: [`tests/chaos/README.md`](../tests/chaos/README.md)
- Observability: [`protocol/telemetry.py`](../protocol/telemetry.py)
