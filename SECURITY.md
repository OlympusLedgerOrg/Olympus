# Security Policy

Olympus is a civic integrity primitive: it stores cryptographic proofs for
government documents. We treat security reports with the same urgency as any
production outage. Thank you for helping keep the audit trail trustworthy.

---

## Supported Versions

Only the current `main` branch receives security patches.

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
   - The affected component(s): `crates/olympus-crypto/`, `src-tauri/` (Axum API, SMT, ZK, anchoring), `proofs/`, or `verifiers/`.
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

- **Preferred:** the GitHub Private Security Advisory ("Report a vulnerability"
  button in the Security tab), which is always available.
- **Email:** `olympusledgerorg@gmail.com` (use the GitHub advisory for sensitive
  details).

---

## External Audits and Bug Bounty

We welcome independent audits of Olympus protocol and implementation layers
(`crates/olympus-crypto/`, `src-tauri/`, `proofs/`, `verifiers/`).

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
| CodeQL extended query suite (rust, javascript-typescript, python) | `.github/workflows/codeql.yml` |
| Rust dependency audit (cargo-audit) | `.github/workflows/ci.yml` — `supply-chain` job |
| Rust dependency review baseline (cargo-vet) | `.github/workflows/ci.yml` — `supply-chain` job |
| Node.js dependency audit (npm audit) | `.github/workflows/ci.yml` — `supply-chain` job |
| SBOM generation (CycloneDX, Rust + Node) | `.github/workflows/ci.yml` — `supply-chain` job |
| Dependabot version updates | `.github/dependabot.yml` — cargo, npm, github-actions |
| Mutation testing / differential fuzzing | `.github/workflows/mutation-testing.yml`, `fuzz/` |

---

## Observability and Monitoring

Olympus implements structured observability for detecting security and integrity issues:

| Component | Purpose | Documentation |
|-----------|---------|---------------|
| OpenTelemetry traces | End-to-end flow tracing (commit/verify/redact) | `docs/observability-deployment.md` (planned) |
| Prometheus metrics | Proof latency, ledger height, SMT divergence alerts | `docs/prometheus-alerting.md` (planned) |
| SMT root divergence alerting | Detects tampering or replication bugs | Federation checkpoint gossip + offline verifiers (`verifiers/`) compare signed roots; dedicated metric is planned |
| Federation checkpoint comparison | Cross-operator root agreement | `src-tauri/src/federation/` (feature-gated) |

> The Python telemetry module and `tests/chaos/` fault-injection suite from the
> pre-v0.9.0 stack were retired with the FastAPI server. Integrity divergence is
> currently surfaced through signed-root comparison in the offline verifiers and
> federation checkpoint gossip; a first-class Prometheus divergence metric is on
> the observability roadmap above.

---

## Known Limitations (Non-Goals)

The following are **by design** outside the current threat model:

- **Key management** — Signing key rotation, HSM integration, and revocation
  are future work.
- **Completeness guarantees** — Olympus cannot force submission of all records.
- **Content confidentiality** — Documents are stored as hashes; access control
  to the raw content is a deployment concern.
- **Single-operator availability** — Multi-node Guardian replication is a planned future enhancement; a single operator deletion of the only copy destroys history.

---

## Deployment Security Requirements

The following operational security practices are **required** for production deployments:

### Signing Key Protection

The `OLYMPUS_INGEST_SIGNING_KEY` environment variable contains the Ed25519 private key
for signing shard headers. **This key must be protected with the following controls:**

1. **Never commit to source control** — Use secret managers (HashiCorp Vault, AWS
   Secrets Manager, Azure Key Vault, or GCP Secret Manager).
2. **Persist, then rotate carefully** — The signing key **must be persisted**:
   ephemeral keys make historical signed roots unverifiable. Rotate only with a
   documented procedure (and immediately on suspected compromise), keeping the
   old public key trusted for verification of historical roots. For BJJ
   issuer/SBT keys, historical acceptance is configured through the
   trusted-issuer set (`OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`,
   `src-tauri/src/api/trusted_issuers.rs`).
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

### Ed25519 Signing Keys

Ed25519 signing keys are operator/account signing identities and are separate
from Olympus API keys. API keys authenticate HTTP callers; Ed25519 keys sign
ledger, dataset, witness, or federation payloads.

Current provisioning:

- Shard/header signing uses `OLYMPUS_INGEST_SIGNING_KEY` from the operator
  environment. It is blocked outside development when the dev-signing-key flag
  is enabled.
- Account signing keys are registered as public keys via `POST /key/signing`.
  The database stores only public key material plus account binding and audit
  metadata.
- `tools/signing_key_cli.py` can generate an Ed25519 keypair locally. The
  private key remains with the operator/user and must not be sent to Olympus.
- `POST /key/signing/dev-generate` is a first-boot convenience path that returns
  private key material once. It is gated behind the **opt-in `dev-signing-route`
  Cargo feature, which is OFF by default** — production builds (and ordinary
  `cargo tauri dev`) do not register the route at all. When the feature is
  enabled it is additionally gated at runtime to `OLYMPUS_ENV=development` +
  `OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP=1`, and it enforces the same
  label/purpose validation as `POST /key/signing`.

Password recovery must never create, rotate, revoke, or expose Ed25519 signing
keys. Recovery changes account credentials/API keys only; registered signing-key
public records remain unchanged.

Signing-key rotation is explicit: register the replacement key, then revoke the
old key with `/key/signing/{key_id}` and optional `replaced_by_key_id`. Revoked
registered signing keys cannot be used for dataset commits.

### Account Recovery

The preferred recovery path is tokenized:

- `POST /auth/recovery/request` accepts an email address and always returns the
  same generic 202 response. If the account exists, a single-use recovery token
  is created and stored as a hash.
- `POST /auth/recovery/complete` consumes the token, resets the account password,
  and issues a recovered API key.

Recovery tokens are account-bound, expire after a short TTL, and are marked used
on successful completion so they cannot be replayed. Production responses never
include the raw token; local development and tests may set
`OLYMPUS_RETURN_RECOVERY_TOKEN=1` with `OLYMPUS_ENV=development` to return it in
the response when no email delivery service is configured.

Recovery key issuance is intentionally scoped:

1. **No scope escalation** — Recovered keys may only request scopes already present
   on the account's active, unexpired API keys. Accounts with no active keys can
   recover `read`/`verify` only.
2. **No account overwrite** — Token completion derives the account from the stored
   token record and does not accept caller-supplied user IDs.
3. **Existing keys are revoked by default** — Tokenized recovery revokes active
   API keys before issuing the recovered key unless the caller explicitly opts
   out with `revoke_existing_keys=false`.
4. **Abuse control** — The endpoint uses the shared per-IP `RateLimit`
   dependency. Deployments should also apply network-layer rate limits for
   distributed attacks.

The legacy password-based `POST /auth/reissue-key` endpoint remains available
for users who know their current password. It is also scope-capped and does not
reset passwords or revoke existing keys.

### Request Size Limits

Deploy Olympus behind a reverse proxy (nginx, HAProxy, AWS ALB) configured with:

- **Maximum request body size:** 10 MB (prevents payload-based DoS)
- **Connection timeouts:** 30-60 seconds (prevents slowloris attacks)
- **Rate limiting at network layer:** Additional protection against distributed DoS

### Database Security

- **TLS required** — Set `?sslmode=verify-full` (or `?sslmode=verify-ca`) in `DATABASE_URL`.
- **Least privilege** — The Olympus service account needs only INSERT and SELECT
  permissions (no UPDATE, DELETE, or DDL).
- **Connection encryption** — Ensure all connections are encrypted in transit.

### CORS Configuration

The embedded Axum server emits CORS headers only for the origins listed in the
`CORS_ORIGINS` environment variable (explicit, comma-separated; **no
wildcards**). If unset, no cross-origin headers are sent. For browser-based
clients, set `CORS_ORIGINS` (or terminate CORS at a reverse proxy) rather than
relaxing the server default.

### API Authentication & Authorization Model

Authentication and authorization are enforced in
`src-tauri/src/api/middleware/auth.rs`, not by a separate sequencer service (the
Go sequencer and its `X-Sequencer-Token` were retired in v0.9.0).

- **API keys** — Requests authenticate with an API key. Keys can be derived from
  the Baby Jubjub authority key via `derive_api_key_from_bjj`; the bootstrap key
  + initial API key are surfaced once on first launch.
- **SBT-driven scopes** — Authorization is resolved from the caller's
  Soul-Bound Tokens. The `credential_type → scopes` mapping is **hardcoded and
  fail-closed**: an unknown credential type grants no scopes. Treat the mapping
  as security policy, not configuration.
- **Admin surface** — `x-admin-key` (`OLYMPUS_ADMIN_KEY`) gates
  `/key/admin/generate`, `/key/admin/reload-keys`, and shard registration
  (`POST /admin/shards`); an `admin`-role + `admin`-scope API key is also
  accepted via `require_admin_auth`.
- **First-boot registration** — on a fresh database the first non-system
  `POST /auth/register` receives the `admin` role and all requested scopes, so a
  single-operator desktop is usable immediately. A transaction advisory lock
  serializes the decision, so two concurrent first registrations cannot both
  become admin. As the API is loopback-only, the residual boundary is *local*: a
  hostile local process that registers before the operator would gain admin. To
  close that window, set `OLYMPUS_ADMIN_KEY` and create accounts via the
  admin-gated `POST /auth/admin/users` (bootstrap also surfaces an admin-scoped
  `system-bootstrap` API key once on first launch).
- **Shard-write authorization** — `POST /ingest/files` calls
  `api::shards::authorize_write` unconditionally (fail-closed): a `shard_id`
  absent or inactive in the `shards` registry is rejected `403`, and a shard
  bound to an owner accepts writes only from that account or an `admin` key.
  This closes the historical gap where any token holder could attribute leaves
  to any `shard_id`.
- **Rate limiting** — the `RateLimit` middleware enforces per-key limits in
  process; network-layer limits at a reverse proxy remain a recommended defense
  in depth.

**Trust assumption:** the cryptographic chain proves *what* was appended and *in
what order* under a given signed root. Per-shard authorization is now enforced by
the shard registry, but a compromised `admin`/owner key can still append or
backdate leaves up to the next signed root; once included in a signed root, a
leaf is permanently part of the ledger. Multi-operator trust distribution is the
role of federation checkpoint gossip / quorum credentials.

### Database-Tier Integrity

> **Note (v0.9.x):** Earlier releases described an `OLYMPUS_NODE_REHASH_GATE_SECRET`
> environment variable and PostgreSQL "trigger gates" (`olympus.allow_smt_insert`,
> `olympus.allow_node_rehash`). Those were part of the **retired Python
> (`storage/postgres.py`, `storage/gates.py`) backend** and **do not exist in the
> current Rust/Tauri app.** The variable is read by no code; do not set it.

SMT writes are serialized — not gated by a session secret — through
`NodeBackend::acquire_write_lock` (`pg_advisory_lock` against the embedded
PostgreSQL, or an in-memory `tokio::Mutex`), held across the read-modify-write
in `update_batch`. This is a **concurrency** control (it prevents stale-cache
stomp between concurrent writers), **not** an authorization control against an
attacker with direct database access.

**Threat model for a database-tier attacker.** The application does not, and
cannot, defend ledger rows against an adversary who already has direct write
access to the PostgreSQL data files or socket. Integrity at that tier relies on:

1. **Infrastructure access controls** — the embedded PostgreSQL listens on
   loopback only; restrict OS-level access to the data directory and the
   process. Do not expose the database socket off-host.
2. **Disk encryption** — encrypt the volume holding the data directory (e.g.
   LUKS, AWS EBS encryption, FileVault). This protects the at-rest signing-key
   material and ledger contents from offline/storage-layer compromise.
3. **The signed-root chain** — tampering that is not reflected in a validly
   signed checkpoint root is detectable by any verifier (the cryptographic
   chain proves *what* was appended and *in what order* under a given signed
   root). Federation checkpoint gossip / quorum credentials distribute that
   trust across operators so a single compromised host cannot silently rewrite
   accepted history.

### ZK Verifier Security

ZK proving and verification run **in-process in Rust** (arkworks / ark-circom),
not via a snarkjs subprocess. A swapped verification key or proving key on disk
is detected by the **ceremony-integrity** checks rather than a single env-var
hash pin. See [`proofs/CEREMONY_INTEGRITY.md`](proofs/CEREMONY_INTEGRITY.md) for
the full protocol; the three runtime checks are:

1. **Compile-time vkey pin** (`src-tauri/build.rs`) — asserts
   `blake3(<circuit>_vkey.json) == manifest.artifacts.vkey.blake3`. `cargo build`
   fails on mismatch, so a tampered vkey cannot be compiled in.
2. **Proving-key pin on load** (`load_proving_key_with_manifest`) — re-hashes the
   `.ark.zkey` from disk and asserts it matches the manifest before
   deserialization, returning `ZkeyError::ManifestMismatch` on tamper. This is
   the filesystem-swap defense the old `OLYMPUS_ZK_VKEY_HASH` pin provided.
3. **Startup manifest verification** (`main.rs::verify_ceremony_manifests`) —
   recomputes the contribution-chain hash and verifies the coordinator
   BJJ-EdDSA signature against `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`. With
   `OLYMPUS_ENV=production`, any failure (or any remaining `PLACEHOLDER` artifact)
   is `exit(2)`; in dev it logs and continues.

**Operator setup:** set `OLYMPUS_CEREMONY_COORDINATOR_KEY` when running the setup
scripts, and add the coordinator pubkey to consumer machines'
`OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`. Never hand-edit
`proofs/keys/manifests/*.json` — any vkey change requires regenerating its
manifest in the same commit (re-run `setup_circuits.sh`).

**Sole sanctioned proving path:** `CircomProvingKey` /
`prove_circom` (`src-tauri/src/zk/zkey.rs`) seals the proving-key type so callers
cannot bypass `CircomReduction` and fall back to `LibsnarkReduction`.
