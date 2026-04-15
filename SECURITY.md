# Security Policy

Olympus is a civic integrity primitive: it stores cryptographic proofs for
government documents. We treat security reports with the same urgency as any
production outage. Thank you for helping keep the audit trail trustworthy.

---

## Supported Versions

Only the current `main` branch receives security patches during the Phase 0.5
protocol-hardening period.

| Version / Branch | Supported          |
| ---------------- | ------------------ |
| `main` (0.x)     | :white_check_mark: |
| Older tags       | :x:                |

---

## Responsible Disclosure Policy

We follow a **coordinated disclosure** model:

1. **Report privately** — Do **not** open a public GitHub issue for security
   vulnerabilities. Instead, use the GitHub **"Report a vulnerability"** button
   in the Security tab of this repository (GitHub Private Security Advisory).

2. **Include in your report:**
   - A short description of the class of vulnerability (e.g. hash-length
     extension, chain-linkage bypass, SMT root forgery).
   - Steps to reproduce or a proof-of-concept (even a sketch is helpful).
   - The affected component(s): `protocol/`, `api/`, `storage/`, or `tools/`.
   - Your estimate of severity (CVSS score appreciated but not required).

3. **Expected response timeline:**

   | Stage | Target SLA |
   |-------|-----------|
   | Acknowledgment | ≤ 2 business days |
   | Triage / severity assessment | ≤ 5 business days |
   | Patch or mitigation plan | ≤ 30 days for critical; ≤ 90 days for others |
   | Public disclosure | Coordinated with reporter; default 90-day window |

4. **What to expect:**
   - We will not pursue legal action against researchers acting in good faith.
   - Credit will be given in the release notes and commit history (with your
     consent).
   - We aim to maintain a public advisory once patched.
   - If we cannot reproduce the issue we will ask for clarification before
     closing.

5. **Scope** — see the threat model (`docs/threat-model.md`) for the audit perimeter; a dedicated pentest scope document is planned.

### Contact + PGP

- **Email:** `security@olympus.dev`
- For sensitive reports, attach details to the GitHub Security Advisory.

---

## External Audits and Bug Bounty

We welcome independent audits of Olympus protocol and implementation layers
(`protocol/`, `proofs/`, `api/`, `storage/`).

- **Audit coordination:** Open a private GitHub Security Advisory first so we
  can share test vectors and scope details safely.
- **Bug bounty intake (HackerOne):** <https://hackerone.com/olympus>
- **Audit scope baseline:** `docs/pentest-scope.md` (planned)

Post-audit remediations are tracked as regular pull requests so fixes remain
publicly reviewable and reproducible.

---

## Threat Model Summary

The threat model is described in detail in:
- [`docs/threat-model.md`](docs/threat-model.md) — Adversary model, security goals, and threat-to-mitigation mapping

Key properties Olympus aims to protect:

- **Chain integrity** — An attacker who can write to the database cannot
  silently reorder or delete ledger entries.
- **Hash preimage resistance** — BLAKE3 hashes are one-way; committed content
  cannot be reverse-engineered from its hash alone.
- **Merkle inclusion proof soundness** — A presented proof cannot be forged
  for a leaf that was never committed to the tree.
- **Redaction proof binding** — A revealed portion cannot be made to look
  like it came from a different original document.

---

## Security Hardening in CI

| Control | Where |
|---------|-------|
| Static analysis (Bandit) | `.github/workflows/ci.yml` — `lint` job |
| CodeQL extended query suite | `.github/workflows/codeql.yml` |
| Dependency vulnerability audit (pip-audit) | `.github/workflows/ci.yml` — `supply-chain` job |
| SBOM generation (CycloneDX) | `.github/workflows/ci.yml` — `supply-chain` job |
| Type checking (mypy strict) | `.github/workflows/ci.yml` — `typecheck` job |
| Chaos engineering tests | `tests/chaos/` — disk full, network partition, clock skew, DB connection loss |

---

## Observability and Monitoring

Olympus implements structured observability for detecting security and integrity issues:

| Component | Purpose | Documentation |
|-----------|---------|---------------|
| OpenTelemetry traces | End-to-end flow tracing (commit/verify/redact) | `docs/observability-deployment.md` (planned) |
| Prometheus metrics | Proof latency, ledger height, SMT divergence alerts | `docs/prometheus-alerting.md` (planned) |
| SMT root divergence alerting | Detects tampering or replication bugs | [`protocol/telemetry.py`](protocol/telemetry.py) — `record_smt_divergence()` |
| Chaos engineering tests | Automated fault injection with documented behaviors | [`tests/chaos/README.md`](tests/chaos/README.md) |

**Critical Alert:** Any increase in `olympus_smt_root_divergence_total` metric indicates potential tampering or integrity violation and requires immediate investigation.

---

## Known Limitations (Non-Goals)

The following are **by design** outside the current threat model:

- **Key management** — Signing key rotation, HSM integration, and revocation
  are future work.
- **Completeness guarantees** — Olympus cannot force submission of all records.
- **Content confidentiality** — Documents are stored as hashes; access control
  to the raw content is a deployment concern.
- **Single-operator availability** — Guardian replication (Phase 1) is not yet
  implemented; a single operator deletion of the only copy destroys history.

---

## Deployment Security Requirements

The following operational security practices are **required** for production deployments:

### Signing Key Protection

The `OLYMPUS_INGEST_SIGNING_KEY` environment variable contains the Ed25519 private key
for signing shard headers. **This key must be protected with the following controls:**

1. **Never commit to source control** — Use secret managers (HashiCorp Vault, AWS
   Secrets Manager, Azure Key Vault, or GCP Secret Manager).
2. **Rotate periodically** — Generate new keys at least annually or immediately
   after any potential compromise. Use the key history mechanism in
   `protocol/federation/identity.py` to maintain historical key acceptance.
3. **Restrict process access** — Run the Olympus API in a container or VM with
   restricted process listing (`hidepid=2` for procfs) to prevent key extraction
   from `/proc/PID/environ`.
4. **Audit access** — Log all access to the secret manager containing the key.
5. **Hardware security modules (HSM)** — For high-assurance deployments, consider
   using an HSM or cloud KMS for key material (integration is future work).

### API Key Management

API keys for the `/ingest/*` endpoints must be:

1. **Pre-hashed** — Store only BLAKE3 hashes of API keys in `OLYMPUS_API_KEYS_JSON`.
   Never store raw API key values.
2. **Scoped** — Assign minimal required scopes (`ingest`, `commit`, `verify`) per key.
3. **Expiring** — Set realistic `expires_at` timestamps and rotate before expiry.
4. **Audited** — All key registrations are logged to the security audit ledger.

### Request Size Limits

Deploy Olympus behind a reverse proxy (nginx, HAProxy, AWS ALB) configured with:

- **Maximum request body size:** 10 MB (prevents payload-based DoS)
- **Connection timeouts:** 30-60 seconds (prevents slowloris attacks)
- **Rate limiting at network layer:** Additional protection against distributed DoS

### Database Security

- **TLS required** — Use `?sslmode=require` or `?sslmode=verify-full` in `DATABASE_URL`.
- **Least privilege** — The Olympus service account needs only INSERT and SELECT
  permissions (no UPDATE, DELETE, or DDL).
- **Connection encryption** — Ensure all connections are encrypted in transit.

### CORS Configuration

If the API is accessed from browser-based clients, configure CORS via your reverse
proxy or add the `CORSMiddleware` to the FastAPI application. The default configuration
does not include CORS headers to prevent unintended cross-origin access.

### Trigger Gate Secret

The `OLYMPUS_NODE_REHASH_GATE_SECRET` environment variable provides a deployment-specific
secret mixed into the SMT trigger gate value. **This secret must be set in production.**

Without this secret, the trigger gate value is deterministic and derivable from source code
alone. An attacker with direct database access could compute the gate value and bypass
PostgreSQL trigger protection to insert or modify SMT nodes directly.

1. **Generate a strong random value:**
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Set via environment variable or secret manager** — treat with the same
   confidentiality as database credentials.
3. **Rotate periodically** — generate a new secret and restart the service.
   Existing SMT data is not affected by rotation since the gate is a session-level
   control, not a persisted value.
4. **Development/test environments** — the secret is recommended but not required.
   A warning is logged when operating without it. Set `OLYMPUS_ENV=development`
   or `OLYMPUS_ENV=test` to allow the deterministic fallback.
