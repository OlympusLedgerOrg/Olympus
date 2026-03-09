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
   vulnerabilities. Instead, e-mail the security team at:

   ```
   security@olympus-ledger.example   (replace with real address before launch)
   ```

   Alternatively, use the GitHub **"Report a vulnerability"** button in the
   Security tab of this repository (GitHub Private Security Advisory).

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

5. **Scope** — See [`docs/pentest-scope.md`](docs/pentest-scope.md) for the
   full penetration-test scope and out-of-scope areas.

---

## Threat Model Summary

The threat model is described in detail in [`threat-model.md`](threat-model.md).
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
