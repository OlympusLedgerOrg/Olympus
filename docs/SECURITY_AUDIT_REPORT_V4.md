# Olympus Security Audit Report — V4 (Consolidated)

**Version:** 4.0 (in progress)
**Audit Date:** June 2026
**Auditors:** Internal review
**Classification:** Public
**Status:** 🟡 **In progress** — this is the current, authoritative audit. It
supersedes V1–V3 and consolidates the `docs/audits/` component audits.

---

## Status & supersession

This V4 report is the single current security-audit artifact for Olympus. All
prior reports are retained for historical reference only and are marked
**OUTDATED — SUPERSEDED BY V4** at their head:

| Prior report | Date | Status |
|---|---|---|
| [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md) (V1) | Apr 2026 | Superseded — predates the v0.9.x Rust/Tauri rewrite |
| [`SECURITY_AUDIT_REPORT_V2.md`](SECURITY_AUDIT_REPORT_V2.md) (V2) | Apr 2026 | Superseded |
| [`SECURITY_AUDIT_REPORT_V3.md`](SECURITY_AUDIT_REPORT_V3.md) (V3) | May 2026 | Superseded |
| [`docs/audits/`](audits/) component audits | May 2026 | To be folded into V4 (round 5) |

> **Note for reviewers:** Olympus migrated from a Python/Go stack to an
> all-Rust Tauri 2 desktop in v0.9.0. V1–V3 contain findings against the
> retired Python API / Go sequencer that no longer exist. V4 audits only the
> current first-party Rust/TypeScript surface.

---

## Scope

First-party, audit-worthy surface (~36k Rust LOC + frontend):

- **Cryptographic core** — `crates/olympus-crypto` (domain prefixes, ADR-0005
  `leaf_hash`, JCS canonicalization, Poseidon), `crates/babyjubjub-permissive`
- **SMT** — `src-tauri/src/smt/` (lazy-deep-node ADR-0022, write serialization)
- **ZK** — `src-tauri/src/zk/`, the five Circom circuits, ceremony integrity
- **API & access control** — `src-tauri/src/api/` (auth, shards gate,
  credentials/quorum, ingest/ledger/redaction)
- **Trust surfaces** — `src-tauri/src/federation/`, `src-tauri/src/anchoring/`
- **Build/release & startup gates** — `build.rs`, `main.rs`, ceremony scripts
- **Frontend** — `app/public-ui/`

Vendored crates (`light-poseidon`, `glib-0.18.5-patched`,
`ppv-lite86-patched`) are reviewed **delta-only** (patch diffs vs upstream).

## Audit plan & progress

| Round | Area | Status |
|---|---|---|
| 0 | Recon / triage (monoliths, dead-code candidates, doc overlap) | ⬜ Not started |
| 1 | Correctness & security — crypto core + SMT | ⬜ Not started |
| 2 | Correctness & security — ZK + ceremony integrity | ⬜ Not started |
| 3 | Correctness & security — API auth, shards, credentials | ⬜ Not started |
| 4 | Dead-code removal (cargo/clippy/machete sweep) | ⬜ Not started |
| 5 | Documentation consolidation (fold V1–V3 + `docs/audits/`) | ⬜ Not started |
| 6 | Monolith report (flag-only split recommendations) | ⬜ Not started |

## Findings

_Severity-ranked findings from rounds 1–3 will be recorded here. Each finding:
ID, severity, component, description, evidence (`file:line`), recommendation,
and remediation status._

| ID | Severity | Component | Summary | Status |
|----|----------|-----------|---------|--------|
| _TBD_ | | | | |

## Maintainability observations

_From rounds 4–6: dead-code removed, docs consolidated, and the monolith
shortlist flagged for future decomposition._
