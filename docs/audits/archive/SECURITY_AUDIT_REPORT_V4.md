# Olympus Security Audit Report — V4 (Consolidated)

**Version:** 4.0
**Audit Date:** June 2026
**Auditors:** Internal review
**Classification:** Public
**Status:** 🔴 **OUTDATED — SUPERSEDED BY V5**
([`../../SECURITY_AUDIT_REPORT_V5.md`](../../SECURITY_AUDIT_REPORT_V5.md)). Retained for
historical reference. V4's Medium R3-01 and Lows R1-01/R3-02 were verified resolved in V5
(see the V5 "V4 findings re-verified" table). Original V4 status follows.

**Original status:** 🟢 **Findings rounds complete (0–3).** This was the current,
authoritative audit. It supersedes V1–V3 and consolidates the `docs/audits/`
component audits. Cleanup rounds (4–6) are tracked below.

---

## Headline result

Across the full first-party surface: **0 Critical · 0 High · 1 Medium · 5 Low ·
several Informational.** No issue is remotely exploitable through the network/IPC
boundary — the single Medium requires a database-tier compromise. Every
hard invariant pinned in `CLAUDE.md` (domain prefixes, ADR-0005 `leaf_hash`,
JCS/RFC-8785 canonicalization, ADR-0022 lazy-node parity, H-4 write-lock
serialization, M-5 prove seal, the three ceremony-integrity checks, H-2
`treeSize=0`, fail-closed SBT scopes, the shard `authorize_write` gate, and
quorum domain separation) was verified against both code and tests.

---

## Status & supersession

This V4 report is the single current security-audit artifact for Olympus. All
prior reports are retained for historical reference only and are marked
**OUTDATED — SUPERSEDED BY V4** at their head:

| Prior report | Date | Status |
|---|---|---|
| [`audits/archive/SECURITY_AUDIT_REPORT.md`](audits/archive/SECURITY_AUDIT_REPORT.md) (V1) | Apr 2026 | Superseded — predates the v0.9.x Rust/Tauri rewrite |
| [`audits/archive/SECURITY_AUDIT_REPORT_V2.md`](audits/archive/SECURITY_AUDIT_REPORT_V2.md) (V2) | Apr 2026 | Superseded |
| [`audits/archive/SECURITY_AUDIT_REPORT_V3.md`](audits/archive/SECURITY_AUDIT_REPORT_V3.md) (V3) | May 2026 | Superseded |
| [`docs/audits/`](audits/) component audits | May 2026 | Retained as point-in-time records; consolidation plan in round 5 |

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

> **Environment caveat (rounds 0/1):** the `olympus-desktop` (`src-tauri`)
> crate could not be compiled in the audit sandbox (missing GTK3/webkit2gtk
> system libraries). The `olympus-crypto` and `babyjubjub-permissive` crates
> compiled and tested clean; `src-tauri` findings were reviewed statically and,
> for dead code, derived from grep + `cargo-machete`. Items marked
> *(needs host confirmation)* should be re-checked with `cargo check`/`clippy`
> on a GTK-enabled host before any code change.

## Audit plan & progress

| Round | Area | Status |
|---|---|---|
| 0 | Recon / triage (monoliths, dead-code candidates, doc overlap) | ✅ Complete |
| 1 | Correctness & security — crypto core + SMT | ✅ Complete |
| 2 | Correctness & security — ZK + ceremony integrity | ✅ Complete |
| 3 | Correctness & security — API auth, shards, credentials | ✅ Complete |
| 4 | Dead-code removal (cargo/clippy/machete sweep) | ✅ Complete — 4 unused deps removed |
| 5 | Documentation consolidation (fold V1–V3 + `docs/audits/`) | ✅ Complete |
| 6 | Monolith report (flag-only split recommendations) | ✅ Recorded (§Maintainability) |

## Findings

| ID | Severity | Component | Summary | Status |
|----|----------|-----------|---------|--------|
| R3-01 | **Medium** | credentials/quorum | Quorum `threshold`/`signers` pinned on the row but not bound by any authority signature → DB-tamper M-of-N downgrade | Open |
| R1-01 | Low | olympus-crypto/poseidon | `compute_redaction_commitments` panics (release `assert`/`[0]`) on empty input; unreachable today but inconsistent with the hardened sibling fn | Open |
| R2-01 | Low | zk/circuits | Misleading domain-tag docstring in the unified circuit (code uses NODE=1, comment says NODE=2); cosmetic, no soundness impact | Open |
| R3-02 | Low | api/auth | `AuthenticatedKey` extractor reflects raw `sqlx` error text to the client, unlike the generic-error pattern used elsewhere | Open |
| R3-03 | Low | credentials/quorum | Verify-time quorum `threshold` not re-clamped against pinned signer-set size (defensive; fails closed today) | Open |
| R3-04 | Low | api/user_auth | First-user bootstrap-admin auto-grant is a documented local-process race (by design for loopback desktop) | Accepted |
| R1-02 | Info | babyjubjub/eddsa | Bare `verify()` omits subgroup/canonical-`s` checks by design; **confirmed** all production paths route through the hardened wrappers (cross-checked in R3) | Mitigated |
| R2-02 | Info | zk/circuits | `unified_…_root_sign` performs no in-circuit signature (off-circuit BJJ verify); intentional, documented as C-1 | Accepted |
| R2-03 | Info | zk/prove | `non_existence` proofs carry no replay binding; relies on app-layer freshness (documented) | Accepted |
| R3-05..08 | Info | api | Trusted-issuer window enforcement, dev-signing double-gating, BJJ key zeroization, loopback rate-limit model — all confirmed sound | Confirmed |

### R3-01 — Medium — Quorum parameters are not cryptographically bound

The single-issuer BJJ signature covers `commit_id`, which binds
`holder_key / credential_type / issued_at / details` but **not**
`quorum_threshold` or `quorum_signers`
(`src-tauri/src/api/credentials/crypto.rs:31-83`). Verify reads both straight
from the row (`credentials/mod.rs:1044-1058`) and `verify_quorum` trusts them
(`quorum/mod.rs:131-175`). An adversary with write access to `key_credentials`
could set `quorum_threshold = 1` or shrink `quorum_signers` to a single
attacker-controlled signer (with a matching co-signature) without breaking
`issued_signature_valid` or `commit_id_matches` — so the offline verifier would
report `quorum.satisfied = true` for a credential that never reached its
intended M-of-N. Pinning in an unsigned column is not cryptographic binding.
Not reachable via the HTTP surface (requires DB write), hence Medium, not High.
**Fix:** fold `quorum_threshold` + the canonicalized (sorted) `quorum_signers`
set into the signed message — a quorum-bound `commit_id` the authority signs and
each co-signer signs — so a tampered threshold/set breaks `commit_id_matches`.

### R3-02 — Low — Raw DB error text leaked from the auth extractor

`src-tauri/src/api/middleware/auth.rs:485` returns
`format!("Database error: {e}")` to the caller, whereas every other handler on
this surface (`require_admin_auth`, `credentials::db_err`, `shards::db_err`, …)
logs the detail and returns a generic message (per prior audit TOB-OLY-07). On a
DB hiccup this leaks `sqlx::Error` Display text to an unauthenticated caller.
**Fix:** return a generic `"Database error."` and keep the `tracing::error!`.

### R1-01 — Low — `compute_redaction_commitments` empty-input panic

`crates/olympus-crypto/src/poseidon.rs:425,437,445` use a release `assert_eq!`
and unchecked `[0]` indexing. The sibling `compute_poseidon_commitment_root`
was deliberately hardened (`:402-408`, `debug_assert!` + fail-soft) with a
comment anticipating a future trust-boundary caller; this function was not.
Currently unreachable — the only caller enforces exactly `MAX_LEAVES = 64`
entries (`src-tauri/src/api/redaction.rs:89,98,207`) — so Low. **Fix:** mirror
the sibling's hardening (return a `Result`/deterministic value on
empty/length-mismatch).

### R2-01 — Low — Misleading domain-tag docstring (unified circuit)

`proofs/circuits/unified_canonicalization_inclusion_root_sign.circom:20-22` (and
`lib/merkleProof.circom:5`) document `NODE = 2`, but the node hasher actually
uses tag **1** (`lib/merkleProof.circom:13`), matching the Rust oracle
(`zk/poseidon.rs:7-9`, `1 = Merkle node`). Comment-only inconsistency — the
implementation is internally consistent and the parity oracle agrees, so no
soundness impact; risk is future-maintainer error. **Fix:** correct the
docstring to the single tag scheme in use (NODE=1, COMMITMENT=3).

### R3-03 / R3-04 and Informational items

- **R3-03 (Low):** verify-time quorum threshold is not re-clamped against
  `signers.len()` (`credentials/mod.rs:1054-1057`); benign because a too-large
  threshold yields `satisfied = false` (fails closed). Subsumed by the R3-01 fix.
- **R3-04 (Low, accepted):** the first registrant becomes admin
  (`user_auth/mod.rs:613-649`); the concurrent TOCTOU is closed by an advisory
  lock, and this is documented as accepted for the loopback-only desktop trust
  boundary. Mitigation: operators should set `OLYMPUS_ADMIN_KEY`.
- **R1-02 (Info, mitigated):** the bare `eddsa.rs::verify` omits subgroup /
  canonical-`s` checks for `babyjubjub-rs` parity; Round 3 confirmed every
  production path (SBT verify, ceremony coordinator, federation co-sign) routes
  through the hardened `zk/witness/baby_jubjub.rs` wrappers.
- **R2-02 / R2-03 (Info, accepted):** the unified circuit has no in-circuit
  signature (off-circuit BJJ verify, audit C-1); existence/non-existence proofs
  rely on app-layer replay protection. Both documented.
- **R3-05..08 (Info, confirmed sound):** trusted-issuer validity windows,
  double-gated dev signing route, BJJ private-key zeroization, and the loopback
  rate-limit model were all reviewed and confirmed correct.

## Maintainability observations

### Dead code (round 4 — `cargo-machete` + host `cargo check`/test) — ✅ removed

The codebase is tidy: **no** live `todo!`/`unimplemented!` and every
first-party `#[allow(dead_code)]` is a required sqlx `FromRow` column-shape
(not removable). The actionable items were unused **direct** dependencies, all
removed after a host compile + test confirmed each is unreferenced or only
reachable transitively (so removing the direct edge is a build-time no-op):

| Dependency | Location | Status |
|---|---|---|
| `ed25519-dalek` | `crates/olympus-crypto` | ✅ removed — optional, legacy, no feature wiring (the active `ed25519-dalek` in `src-tauri` is a separate, retained dep) |
| `ecdsa` | `src-tauri` | ✅ removed — ECDSA goes through `p256::ecdsa`; the `der` feature is supplied by `p256` |
| `unicode-normalization` | `src-tauri` | ✅ removed — unreferenced (the olympus-crypto `canonical` feature uses its own separate dep) |
| `ark-serialize` | `crates/babyjubjub-permissive` | ✅ removed — unreferenced direct edge; still reachable via the arkworks stack |
| `tauri-build` | `src-tauri/Cargo.toml:75` | **Kept** — build-dep false positive (`build.rs:203`) |

### Documentation consolidation (round 5) — ✅ done

- V1–V3 archived under `docs/audits/archive/`; V4 stays at top level as the live
  security doc, and every inbound pointer (README, `threat-model.md`,
  `court-evidence.md`) now resolves to V4 instead of the stale V3.
- The 2026-05-26 federation-quorum design/gating note was folded into the live
  `docs/federation-quorum-credentials.md` as a Design Rationale appendix and the
  standalone copy removed.
- The stale `federation-ingest-verifiers-audit.md` (Apr 19) was relocated to
  `docs/audits/2026-04-19-federation-ingest-verifiers.md`.
- ADRs kept (append-only). The cosmetic ADR filename-numbering inconsistency is
  noted but intentionally left unchanged.

### Monolith shortlist (round 6 — flag-only, no refactor)

Files > 600 lines, with suggested split axis. Per the agreed plan these are
**flagged, not refactored** — the security-critical ones especially.

| Lines | File | Note |
|---|---|---|
| 1466 | `src-tauri/src/smt/tree.rs` | ⚠️ ADR-0022 invariant hotspot — split *carefully* (extract `canopy.rs` + `write.rs`) |
| 1257 | `src-tauri/src/api/user_auth/mod.rs` | Clean split candidate (handlers / rows / tokens) |
| 1117 | `src-tauri/src/api/credentials/mod.rs` | Split by op (issue/revoke/verify/quorum) aids audit |
| 851 | `src-tauri/src/api/keys.rs` | Separate admin-gated handlers from user key ops |
| 749 | `src-tauri/src/api/middleware/auth.rs` | ⚠️ Security-policy scope map — isolating `scopes.rs` sharpens the boundary, but touch carefully |
| 853 | `crates/olympus-crypto/src/smt.rs` | Borderline; ~40% tests — size largely justified |
| 802 | `src-tauri/src/anchoring/rekor.rs` | Justified (external-protocol client); low priority |
| 756 | `crates/olympus-crypto/src/poseidon.rs` | **Do not split** — cohesive crypto primitive |
| 677 | `app/public-ui/src/components/StartupGate.tsx` | Only FE file > 600; extract readiness hook + sub-views |
