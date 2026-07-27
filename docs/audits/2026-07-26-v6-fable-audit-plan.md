# Olympus Security Audit — V6 ("Fable audit") Plan

**Status:** Planned (not yet run)
**Baseline:** post-V5, v0.10.0. V5 authoritative report: [`../SECURITY_AUDIT_REPORT_V5.md`](../SECURITY_AUDIT_REPORT_V5.md)
**Scope mode:** delta-focused — the ~169 files / ~16.7k insertions changed since the V5 medium fixes (`ed782e44`), plus a full re-verification of the CLAUDE.md pinned invariants.
**Fleet model:** Fable (`claude-fable-5`), run as a multi-agent Workflow.

---

## Where Olympus is now

V5 (baseline `40ea3817`) landed **0 Critical / 0 High / 3 Medium / 4 Low**; all three Mediums
(A1-01 admin-lockout, A1-02 PDF decompression-bomb, A1-03 federation equivocation) were
remediated in `ed782e44` (#1305). Since then a large security-relevant delta has landed that
no published audit covers, clustered around five new ADRs.

## New attack surface (audit targets)

| # | Surface | Files | Why high-value |
|---|---|---|---|
| 1 | Crypto-agility signature envelopes (ADR-0035) | `crates/olympus-crypto/src/signature_envelope.rs` | alg downgrade / unsigned-alg acceptance / cross-envelope replay |
| 2 | Signed request envelopes + network (ADR-0036) | `crates/olympus-crypto/src/request_envelope.rs`, `src-tauri/src/api/middleware/signed_request.rs` | replay window, canonicalization-vs-verify mismatch, verify-bypass |
| 3 | Length-hiding + word-level redaction (ADR-0034/0029) | `src-tauri/src/zk/segment/pdf_textrun.rs`, fixed-width tokens, `verifiers/rust/src/redaction.rs` | untrusted-PDF DoS, over/under-redaction, token-width info leak, verifier parity |
| 4 | Anchoring | `src-tauri/src/anchoring/{api,mod,rekor}.rs` | V5 L-01 error reflection, L-02 redirect SSRF, Rekor payload trust |
| 5 | Federation | `src-tauri/src/federation/{api,peer,tor}.rs` | equivocation TOCTOU/re-flag, `.onion` validation, peer trust |

Plus a full re-verification of the pinned invariants (leaf_hash/ADR-0005, ceremony integrity,
write-once ledger, quorum domain separation, `treeSize=0`, shard `authorize_write`, lazy-node parity).

---

## Coverage from open PRs (what's already being fixed)

The following in-flight PRs (all authored by the `OlympusLedgerOrg` bot) already remediate part
of the delta. Audit hunt agents should treat these as **in-progress / do-not-re-report**, and
instead *verify the fix* rather than re-discover the finding.

| PR | State | What it fixes | Audit surface |
|---|---|---|---|
| [#1441](https://github.com/OlympusLedgerOrg/Olympus/pull/1441) | Ready | Null `expires_at` credential hidden from listing/scope aggregation (valid-but-invisible key) | Auth |
| [#1442](https://github.com/OlympusLedgerOrg/Olympus/pull/1442) | Ready | `system` role unrecognized at admin gate (fail-closed alignment) | Auth |
| [#1448](https://github.com/OlympusLedgerOrg/Olympus/pull/1448) | Draft | Stale bearer key retains/recreates `admin` scope after demotion | Auth |
| [#1449](https://github.com/OlympusLedgerOrg/Olympus/pull/1449) | Draft | Replayable `x-admin-registration-approval` HMAC bootstrap path removed | Auth |
| [#1446](https://github.com/OlympusLedgerOrg/Olympus/pull/1446) | Ready | Renderer-selected keychain account (IPC) pinned to fixed `api_key` account | IPC |
| [#1444](https://github.com/OlympusLedgerOrg/Olympus/pull/1444) | Ready | Embedded PG durability pinned (fsync/synchronous_commit/SCRAM/loopback) | DB |
| [#1443](https://github.com/OlympusLedgerOrg/Olympus/pull/1443) | Draft | Redacts `DATABASE_URL`/cluster paths/creds from startup diagnostics (info leak) | DB |
| [#1451](https://github.com/OlympusLedgerOrg/Olympus/pull/1451) | Draft | Requires `sslmode=verify-full` for prod external Postgres (downgrade/MITM) | DB/Net |
| [#1445](https://github.com/OlympusLedgerOrg/Olympus/pull/1445) | Draft | Canonical Groth16 encoding enforcement (reject non-canonical field/point aliases) | ZK |
| [#1447](https://github.com/OlympusLedgerOrg/Olympus/pull/1447) | Ready (stacked on #1445) | Bounds `/zk/verify` requests before dispatch (DoS) | ZK |
| [#1450](https://github.com/OlympusLedgerOrg/Olympus/pull/1450) | Draft | Persist quorum signatures atomically (no advertise-without-durable-sigs) | Credentials/Quorum |
| [#1440](https://github.com/OlympusLedgerOrg/Olympus/pull/1440) | Ready, CI green | Pins CI action SHAs + Node/Rust toolchains (supply chain) | CI/Build |
| [#1453](https://github.com/OlympusLedgerOrg/Olympus/pull/1453) | Draft, CI fully green | RFC 3161 verify without OpenSSL/Perl on Windows (RustCrypto+WebPKI) | Anchoring/Build |
| [#1454](https://github.com/OlympusLedgerOrg/Olympus/pull/1454) | Draft | Test-only: isolate equivocation peer identities | Federation (tests) |

**Merge-ordering note:** #1453 removes `openssl-sys` from the Windows graph and is the only
draft with a fully green CI run; nearly every other PR is blocked from local Windows verification
by that same `openssl-sys` wall. Suggested order: **#1453 → #1445 → #1447 → rest.**

### Gap analysis — what the open PRs do NOT cover (audit's highest-value targets)

The open PRs cover auth / DB / ZK-parsing / quorum-persistence. They leave the **new post-V5
crypto surface untouched** — this is where the Fable audit should concentrate:

- **Surface 1 — signature-agility envelopes** (`signature_envelope.rs`) — no open PR.
- **Surface 2 — signed request envelopes** (`request_envelope.rs` / `signed_request.rs`) — no open PR (#1451 is TLS transport only; #1440 is CI).
- **Surface 3 — redaction `pdf_textrun.rs` + fixed-width tokens** — no open PR.
- **Surface 4 — anchoring L-01 error reflection / L-02 redirect SSRF** — not covered (#1453 reworks the RFC 3161 *verifier*, not these two surfaces).
- **Surface 5 — federation equivocation logic** — only a test-isolation PR (#1454), no logic fix.

---

## Workflow structure

**Phase 1 — Recon (3 agents, parallel).** (a) stack/trust-boundary/threat-model refresh vs the
loopback-desktop model; (b) exhaustive input-surface inventory of the new envelope/middleware/
anchoring routes; (c) invariant map — every CLAUDE.md invariant → the exact enforcing code site.

**Phase 2 — Hunt (7 agents, one per surface; each must produce a concrete exploit, not a theory):**
1. `signature_envelope.rs` — alg downgrade, unsigned-alg acceptance, cross-envelope replay
2. `request_envelope.rs` + `signed_request.rs` — replay window, canonicalization mismatch, nonce/timestamp, verify-bypass
3. `pdf_textrun.rs` + fixed-width tokens — untrusted-PDF DoS, over/under-redaction, token-width leak
4. anchoring — SSRF/redirect (L-02), error reflection (L-01), Rekor payload trust
5. federation — equivocation TOCTOU/re-flag (L-03/L-04), `.onion` validation, peer trust
6. crypto core — `canonical.rs`/`poseidon.rs`/`lib.rs` diffs vs verifier parity (Rust + JS)
7. invariant-regression sweep — did any of the 169 changed files quietly weaken a pinned invariant?

**Phase 3 — Adversarial verify (fan-out per finding).** Each candidate → 3 independent Fable
skeptics prompted to *refute* it (default false-positive if uncertain); majority-refute kills it.

**Phase 4 — Synthesize.** Merge survivors, dedupe, rank, draft `docs/SECURITY_AUDIT_REPORT_V6.md`
in the house format; archive V5.

---

## Operational notes

- **Federation** can't build/test on the Windows host (`LNK1181` via arti→rusqlite). Surface-5
  findings are read-only-verified unless run in the Linux audit container.
- **V5 residue in scope:** L-01 (anchoring error reflection) and L-02 (anchoring redirect SSRF)
  were still Open in V5 — confirm whether post-V5 commits closed them.
- **Sizing:** ~13 core recon/hunt agents + per-finding verify fan-out; within the medium
  workflow guideline. Launch trigger: "use a workflow" / "ultracode".
