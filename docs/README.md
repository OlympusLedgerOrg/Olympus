# Olympus Documentation

Welcome to the Olympus docs. Start here based on your role.

---

## 🚀 Quick Navigation

### I'm new to Olympus
1. **[Executive Summary](executive-summary.md)** (5 min) — What Olympus is and why it exists
2. **[Quick Start](quickstart.md)** (15 min) — Install or build from source
3. **[Threat Model](threat-model.md)** (20 min) — What we protect against, in plain language

### I need to verify proofs in court
**[Evidence Pack](court-evidence.md)** — How to independently verify Olympus bundles without trusting any operator. Written for lawyers and expert witnesses.

### I'm running a federation node
1. **[Quick Start](quickstart.md)** — Install the binary
2. **[Federation Runbook](federation.md)** — How to join a multi-node federation over Tor
3. **[SBT Deployment](sbt-deployment.md)** — How to issue and verify credentials
4. **[Governance](governance.md)** — Decision-making and security response

### I'm contributing code
1. **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — How to submit PRs (DCO sign-off required)
2. **[Governance](governance.md)** — How Olympus makes decisions
3. **[../MAINTAINERS.md](../MAINTAINERS.md)** — Roles and the contributor ladder
4. **[Coverage](coverage.md)** — Test coverage expectations (85% gate)

### I'm auditing the protocol
1. **[Threat Model](threat-model.md)** — What we claim to protect
2. **[Evidence Pack](court-evidence.md)** (§§5-9) — Ceremony integrity and cryptographic assumptions
3. **[Architecture Decision Records](adr/)** — Why we made each design choice
4. **[../CLAUDE.md](../CLAUDE.md)** — Critical Invariants (the safety constraints we never break)

---

## 📖 Architecture Decision Records (ADRs)

All protocol decisions are recorded in [adr/](adr/). Key ones:

| ADR | Topic | Status |
|-----|-------|--------|
| [ADR-0003](adr/0003-parser-version-leaf-domain-separator.md) | Parser version binding in leaf hash | **Accepted** |
| [ADR-0004](adr/0004-model-hash-leaf-domain-separator.md) | Model hash binding in leaf hash | **Accepted** |
| [ADR-0005](adr/ADR-0005-structured-leaf-prefix-shard-binding.md) | Shard-ID binding + structured leaf prefix | **Accepted** |
| [ADR-0022](adr/ADR-0022-smt-lazy-deep-node-storage.md) | Lazy node storage for the persistent SMT | **Accepted** |
| [ADR-0025](adr/ADR-0025-pdf-object-level-redaction.md) | PDF object-level redaction commitment | **Accepted** |
| [ADR-0026](adr/ADR-0026-multiformat-object-redaction-producer.md) | Multi-format object redaction producer | **Proposed** |
| [ADR-0027](adr/ADR-0027-dataset-manifest-commitments.md) | Dataset-manifest commitments + CLI/SDK | **Accepted** |
| [ADR-0031](adr/ADR-0031-transition-attestations-insert-only-ledger.md) | Transition attestations + insert-only ledger | **Proposed** |
| [ADR-0032](adr/ADR-0032-retire-witness-over-root-cosignature.md) | Retire witness-over-root cosignature | **Accepted** |
| [ADR-0033](adr/ADR-0033-checkpoint-quorum-cosignatures.md) | Checkpoint-quorum co-signatures | **Accepted** |

See [adr/README.md](adr/README.md) for the full index.

---

## 🔐 Understanding the Protocol

### How it works (architecture)
- **[Executive Summary](executive-summary.md)** — High level: one global tree, shard headers, ledger chains
- **[Threat Model](threat-model.md)** — What adversaries we assume; what we prove
- **[Evidence Pack](court-evidence.md)** — Verification in adversarial settings (Daubert / Frye admissibility)

### Operational guides
- **[Federation Runbook](federation.md)** — Multi-node setup, Tor hidden services, audit status
- **[SBT Deployment](sbt-deployment.md)** — Native Soulbound Tokens, issuance, verification
- **[Governance](governance.md)** — Decision-making, roles, security response

### Development & maintenance
- **[Coverage](coverage.md)** — Test coverage tracking (Rust + frontend)
- **[Release provenance](release-provenance.md)** — checksums, attestations, SBOMs, and verification levels
- **[Supply-chain vetting](supply-chain-vetting.md)** — `cargo-vet` baseline and follow-up scope
- **[C2PA bridge guardrails](c2pa-bridge.md)** — supplemental provenance import/export boundaries
- **[RFCs](rfcs/)** — proposed changes before they become ADRs
- **[../CLAUDE.md](../CLAUDE.md)** — Critical Invariants (read before modifying crypto)
- **[../SECURITY.md](../SECURITY.md)** — Coordinated vulnerability disclosure

---

## 🚀 Getting Started

**First time?** Start with [Executive Summary](executive-summary.md), then [Quick Start](quickstart.md).

**Auditor?** Read [Threat Model](threat-model.md), then [Evidence Pack](court-evidence.md).

**Operator?** Read [Quick Start](quickstart.md), then [Federation Runbook](federation.md) or [SBT Deployment](sbt-deployment.md).

**Contributor?** Read [../CONTRIBUTING.md](../CONTRIBUTING.md), then pick an [ADR](adr/) that touches the code you want to change.

---

## 🔗 Common Questions

**Q: How do I know this is tamper-proof?**  
A: [Threat Model](threat-model.md) (mitigations) + [Evidence Pack](court-evidence.md) (cryptographic proof).

**Q: Why are there so many docs?**  
A: Olympus is designed for high-stakes use (court, journalism, investigation). The docs prove that every design choice is intentional and auditable. See [Governance](governance.md) for why transparency matters.

**Q: Where's the code?**  
A: `../src-tauri/` (Tauri desktop app), `../crates/` (Rust crypto & prover), `../app/` (React frontend), `../proofs/` (Circom circuits).

**Q: How do I run the tests?**  
A: [Coverage](coverage.md) explains the test suite and how to run it locally.

**Q: I found a security issue.**  
A: See [../SECURITY.md](../SECURITY.md) for coordinated disclosure.

---

## 📚 Document Index

| Document | Audience | Time | Purpose |
|----------|----------|------|---------|
| [executive-summary.md](executive-summary.md) | Everyone | 5 min | What Olympus is and why |
| [quickstart.md](quickstart.md) | Users, developers | 15 min | Install or build |
| [threat-model.md](threat-model.md) | Auditors, security | 20 min | Adversaries and mitigations |
| [governance.md](governance.md) | Contributors, maintainers | 10 min | Decision-making and roles |
| [court-evidence.md](court-evidence.md) | Lawyers, judges, experts | 30 min | Verification for litigation |
| [federation.md](federation.md) | Operators | 20 min | Multi-node setup on Tor |
| [sbt-deployment.md](sbt-deployment.md) | Operators | 15 min | Credential issuance |
| [coverage.md](coverage.md) | Developers | 10 min | Test coverage gates |
| [supply-chain-vetting.md](supply-chain-vetting.md) | Maintainers, auditors | 10 min | Dependency review baseline |
| [adr/](adr/) | Architects, crypto experts | varies | Protocol design decisions |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Contributors | 10 min | How to submit PRs |
| [../MAINTAINERS.md](../MAINTAINERS.md) | Contributors | 5 min | Roles and ladder |
| [../CLAUDE.md](../CLAUDE.md) | Developers | 5 min | Critical invariants |
| [../SECURITY.md](../SECURITY.md) | Security researchers | 5 min | Coordinated disclosure |

---

## v1.0 Release Status

See [../issues/1079](https://github.com/OlympusLedgerOrg/Olympus/issues/1079) for the full v1.0 release-readiness checklist.

**Hard gates (must-fix before v1.0):**
- Production Groth16 Phase 2 ceremony (3+ independent contributors)
- Anchoring hardening (RFC 3161 parsing, Rekor key pinning, OpenTimestamps upgrade)

**Quality gaps (should-fix):**
- Frontend coverage ratchet (coverage is measured; merge-blocking ratchet pending)
- ADRs for leaf hash, redaction, and quorum (all accepted ✅)

---

Last updated: 2026-06-22. For the latest, see [`docs/adr/README.md`](adr/README.md).
