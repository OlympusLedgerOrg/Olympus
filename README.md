# Olympus

Olympus is a verifiable ledger for sensitive documents.

It helps organizations prove three things about a record:

1. the document existed at a specific time,
2. the document was not altered, and
3. any redactions were made honestly.

The file stays on your machine. Olympus publishes cryptographic proof, not the original document. That makes it useful when the record may be leaked, disputed, or challenged later in court, by auditors, or by outside reviewers.

If you want the short version: Olympus is built for situations where "trust me" is not enough.

If you want it without the README: **<https://olympusledgerorg.github.io/Olympus/>** — the same four claims on one page, written for people evaluating Olympus rather than building it.

---

## Why Olympus

Four things have to be true before a document holds up under challenge. You can show it existed at a given time. You can show it has not been edited since. You can show that whatever was blacked out was blacked out honestly. And someone else can check all of that for themselves — years later, on their own computer, without asking you or anyone else for permission.

Most tools deliver one of the four.

| Tool | What it covers | What it leaves out |
|------|----------------|--------------------|
| **SecureDrop** | Receives leaked documents | Does not prove authenticity, timing, or tamper status |
| **OpenTimestamps** | Proves a document existed at a point in time | No redaction proof; no proof the record belongs to an official set; no independent operators |
| **Sigstore / Rekor** | Public transparency log | Built for software, not documents; requires network access |
| **C2PA** | Captures provenance at creation time | Does not help with documents that already exist |
| **Arweave / Filecoin** | Distributed storage | Cannot be checked without going online; not redaction-aware |

Olympus covers all four in one workflow. It also writes its proofs into Bitcoin and into public, append-only logs, so the timestamps do not rest on Olympus being trusted — those systems become part of the proof chain rather than a substitute for it.

---

## Who it's for

Olympus is most useful if you are one of these:

| I am a... | Start with |
|-----------|-----------|
| Journalist or investigator | [`docs/court-evidence.md`](docs/court-evidence.md) |
| Lawyer or expert witness | [`docs/court-evidence.md`](docs/court-evidence.md) → [`verifiers/`](verifiers/) |
| Grant reviewer or outside evaluator | [`GRANTS.md`](docs/GRANTS.md) → [`DEMO.md`](docs/DEMO.md) |
| Security auditor | [`docs/audits/2026-07-26-security-audit-report-v6.md`](docs/audits/2026-07-26-security-audit-report-v6.md) → [`docs/threat-model.md`](docs/threat-model.md) |
| Developer or contributor | [`docs/quickstart.md`](docs/quickstart.md) → [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| ZK or circuit reviewer | [`proofs/circuits/`](proofs/circuits/) → [`src-tauri/src/zk/`](src-tauri/src/zk/) |

---

## What Olympus does

- **Proves a document existed** at a specific moment in time, anchored to Bitcoin, to a public transparency log, and to timestamps from accredited third-party services
- **Proves the document was not altered** because any change produces a different cryptographic proof
- **Proves redactions were honest** without revealing the redacted content
- **Keeps the original document local** so only the proof leaves your machine
- **Runs without a trusted server** so there is no single operator that can quietly rewrite history
- **Works offline for verification** so third parties can check evidence later without needing a live service
- **Fits court-oriented workflows** where the verification path matters as much as the record itself
- **Lets anyone run a node** — the more independent operators there are, the harder the system is to pressure

You don't have to trust us. You can be us.

---

## Current status

Olympus is in active development at `v0.10`.

- The desktop app is live, and downloadable as a **preview build** (see [Download](#download) below).
- The core ledger and cryptographic proof system are live.
- The remaining pre-launch milestone is a trusted-setup ceremony — a one-time step carried out by several independent parties so that no single one of them, including us, keeps the ability to forge proofs. Production builds are gated on it.

This repository is intentionally **pre-v1**. In practice, that means development and review are active, but the system is still gated until the ceremony work is complete. See [`ROADMAP.md`](docs/ROADMAP.md).

---

## Download

Preview builds are available for Windows, macOS, and Linux:

**[Download the latest preview →](https://github.com/OlympusLedgerOrg/Olympus/releases)**

> **Preview builds are not production software.** They are built from a
> single-contributor development trusted setup, so proofs from them carry no
> soundness guarantee, and they are unsigned — expect a SmartScreen warning on
> Windows and a Gatekeeper block on macOS. The release page has the exact
> commands. Records committed with a preview build are disposable.

A preview installs as **Olympus Ledger Preview**, with its own data directory,
so it will not collide with a production build you install later. Production
builds ship after the multi-party trusted-setup ceremony described above.

Prefer to build it yourself? See [`docs/quickstart.md`](docs/quickstart.md).

---

## OpenAI Build Week 2026

Olympus predates the July 13, 2026 submission window. What was added during Build Week, and how to run it, is in [`BUILD_WEEK.md`](docs/BUILD_WEEK.md).

---

## Trust & threat model

Olympus is honest about what it protects and what it doesn't.

It defends against: malicious record alteration, tampered timestamps, and operators who can't be fully trusted.

It does not promise: that all relevant records were submitted, that submitted content is confidential, or that the system remains available if the operator goes offline.

Full details: [`docs/threat-model.md`](docs/threat-model.md)

---

## Licensing

Apache 2.0. Everything is open source — the protocol, the cryptographic circuits, the storage layer, the verification tools, and the desktop application. See [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

---

## For developers, auditors, and contributors

Olympus is designed to be audit-friendly, and external review is encouraged.

| What you want | Where to go |
|------|------|
| Build and run it from source | [`docs/quickstart.md`](docs/quickstart.md) |
| Day-to-day development workflows | [`docs/development.md`](docs/development.md) |
| How Olympus is architected | [`docs/architecture.md`](docs/architecture.md) |
| Threat model, for auditors and policymakers | [`docs/threat-model.md`](docs/threat-model.md) |
| Latest security audit (July–August 2026 — V6) | [`docs/audits/2026-07-26-security-audit-report-v6.md`](docs/audits/2026-07-26-security-audit-report-v6.md) |
| Prior audit rounds | [`V5`](docs/SECURITY_AUDIT_REPORT_V5.md) · archived: [`V1`](docs/audits/archive/SECURITY_AUDIT_REPORT.md), [`V2`](docs/audits/archive/SECURITY_AUDIT_REPORT_V2.md), [`V3`](docs/audits/archive/SECURITY_AUDIT_REPORT_V3.md), [`V4`](docs/audits/archive/SECURITY_AUDIT_REPORT_V4.md) |
| Reporting a vulnerability | [`SECURITY.md`](SECURITY.md) |
| Court and evidence workflows | [`docs/court-evidence.md`](docs/court-evidence.md) |
| ZK circuits and the trusted setup | [`proofs/README.md`](proofs/README.md) |
| Offline verification in Rust and JavaScript | [`verifiers/`](verifiers/) |

---

## Community & Governance

Olympus is open to contributors and is actively growing its maintainer pool.

| Topic | Document |
|-------|----------|
| How to contribute (DCO sign-off) | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Expected behavior & enforcement | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Who maintains what & the contributor ladder | [`MAINTAINERS.md`](docs/MAINTAINERS.md) |
| How decisions are made, voted, and released | [`docs/governance.md`](docs/governance.md) |
| Proposing substantial changes | [`docs/rfcs/README.md`](docs/rfcs/README.md) |
| Where the project is headed | [`ROADMAP.md`](docs/ROADMAP.md) |
| Reporting a vulnerability | [`SECURITY.md`](SECURITY.md) |

Interested in a maintainer role? See
[Becoming a maintainer](docs/MAINTAINERS.md#becoming-a-maintainer).
