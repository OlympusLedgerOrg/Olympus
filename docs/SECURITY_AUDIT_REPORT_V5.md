# Olympus Security Audit Report — V5 (Consolidated)

**Version:** 5.0
**Audit Date:** June 2026
**Auditors:** Internal review + multi-agent adversarial pass (Cloudflare `security-audit` skill methodology), cross-checked with Ghost Security static scans (secrets/deps/code) and Trail of Bits constant-time + zeroize analyses
**Classification:** Public
**Status:** 🟢 **Current, authoritative audit.** Supersedes V1–V4. V4 is archived under
[`audits/archive/SECURITY_AUDIT_REPORT_V4.md`](audits/archive/SECURITY_AUDIT_REPORT_V4.md).

---

## Headline Result

Across the full first-party surface at commit `40ea3817` (v0.10.0):
**0 Critical · 0 High · 3 Medium · 4 Low · several Informational.**

No issue is remotely exploitable through the network/IPC boundary in the default
configuration. The three Mediums are (1) an admin-lockout logic asymmetry reachable
only by an already-admin caller, (2) a decompression-bomb OOM DoS in the modern-PDF
segmenter reachable by any ingest-scoped loopback caller, and (3) a federation
equivocation-detection bypass behind the off-by-default `federation` feature.

**Follow-up hardening status (current tree):** all V5 findings listed in this
report are resolved in code. The current tree also centralises `OLYMPUS_ENV`
parsing so explicit malformed values fail closed to production behavior, while
leaving the historical unset local-dev default unchanged.

Every hard invariant pinned in `CLAUDE.md` (domain prefixes, ADR-0005 `leaf_hash`,
JCS/RFC-8785 canonicalization, ADR-0022 lazy-node parity, H-4 write-lock
serialization, M-5 prove seal, the ceremony-integrity checks, H-2 `treeSize=0`,
fail-closed SBT scopes, the shard `authorize_write` gate, and quorum domain
separation) was re-verified against code this round and holds.

### Methodology this round

V5 adds a multi-agent **adversarial** pass to the static review that produced V4:

- **Recon (3 agents):** application/stack/baseline, trust boundaries & access control,
  exhaustive input-surface inventory.
- **Hunt (6 parallel agents):** access control, business logic, injection, crypto &
  secrets, resource/file-handling & SSRF, and an "obvious + wildcard" sweep — each
  required to produce a concrete exploit, not a theoretical concern.
- **Validation:** every reported finding independently re-read against source; the
  headline admin-lockout finding was confirmed line-by-line.
- **Supporting tool passes (clean / informational):** Ghost secrets scan (40 candidates,
  0 real), Ghost SCA (35 advisories, 0 exploitable — all unmaintained-crate notices or
  build/dev-only npm), Ghost SAST (0 findings), ToB constant-time (EdDSA signing is not
  constant-time but has no remote timing oracle — server-side single signer), ToB
  zeroize (systemic `AppState` secret-wrapping gaps — hardening, tracked separately).

---

## Status & supersession

| Prior report | Date | Status |
|---|---|---|
| [`audits/archive/SECURITY_AUDIT_REPORT.md`](audits/archive/SECURITY_AUDIT_REPORT.md) (V1) | Apr 2026 | Superseded — predates the v0.9.x Rust/Tauri rewrite |
| [`audits/archive/SECURITY_AUDIT_REPORT_V2.md`](audits/archive/SECURITY_AUDIT_REPORT_V2.md) (V2) | Apr 2026 | Superseded |
| [`audits/archive/SECURITY_AUDIT_REPORT_V3.md`](audits/archive/SECURITY_AUDIT_REPORT_V3.md) (V3) | May 2026 | Superseded |
| [`audits/archive/SECURITY_AUDIT_REPORT_V4.md`](audits/archive/SECURITY_AUDIT_REPORT_V4.md) (V4) | Jun 2026 | Superseded — Medium R3-01 + Lows R1-01/R3-02 verified resolved (see below) |

### V4 findings re-verified this round

| V4 ID | V4 severity | V5 status |
|---|---|---|
| R3-01 | Medium | ✅ **Resolved** — `quorum_threshold` + canonical signer set are now folded into the co-sign digest and re-derived at verify; tampering a pinned threshold/signer breaks the signature. |
| R1-01 | Low | ✅ **Resolved** — `compute_redaction_commitments` empty-input path hardened. |
| R3-02 | Low | ⚠️ **Fixed at the original site** (auth extractor) **but the same class re-appears** on the anchoring read surface → tracked as V5 **L-01**. |
| R2-01, R3-03, R3-04, Info | Low/Info | Unchanged (cosmetic / fail-closed / accepted-by-design). |

---

## Scope

First-party Rust/TypeScript surface (~36k Rust LOC + frontend): cryptographic core
(`crates/olympus-crypto`, `crates/babyjubjub-permissive`), SMT (`src-tauri/src/smt/`),
ZK + ceremony integrity (`src-tauri/src/zk/`, Circom circuits), API & access control
(`src-tauri/src/api/`), trust surfaces (`src-tauri/src/federation/`, `src-tauri/src/anchoring/`),
build/release & startup gates, and the frontend (`app/public-ui/`). Vendored crates are
delta-reviewed only.

**Trust model.** Loopback-only Tauri desktop. The primary attacker is a local process
(possibly holding a low-privilege API key) or a federation peer over Tor. An operator with
shell/env/DB access is fully trusted by design — findings that require operator/DB-tier
control are rated accordingly.

---

## Findings

| ID | Severity | Component | Summary | Status |
|----|----------|-----------|---------|--------|
| A1-01 | **Medium** | api/admin_users | Last-admin lockout — only `update_user_role` has the last-admin guard; `update_key_scopes` + `revoke_key` don't | Resolved |
| A1-02 | **Medium** | zk/segment/pdf_xref | Modern-PDF inflate cap is per-stream, not cumulative → decompression-bomb OOM DoS | Resolved |
| A1-03 | **Medium** | federation | Equivocation detection TOCTOU + timestamp-keying lets a forking peer evade detection (feature off by default) | Resolved |
| L-01 | Low | anchoring/api | `GET /anchors*` reflect raw `sqlx` error text (V4 R3-02 class, missed surface) | Resolved |
| L-02 | Low | anchoring/mod | Anchoring HTTP client follows redirects without re-validating targets → SSRF (env-only URLs) | Resolved |
| L-03 | Low | federation/peer | `add_peer` doesn't validate `onion_address` is a v3 `.onion` host | Resolved |
| L-04 | Low | federation/equivocation | Re-flag suppression on already-flagged timestamp (sub-item of A1-03) | Resolved |

### A1-01 — Medium — Last-admin lockout via scope-strip / key-revoke

The admin gate requires **both** `role == 'admin'` **and** the `admin` scope
(`src-tauri/src/api/middleware/auth.rs:436`). `update_user_role` carefully guards
last-admin **demotion** (FOR UPDATE + transactional re-check,
`src-tauri/src/api/admin_users.rs:362-400`), but the sibling paths
`update_key_scopes` (`admin_users.rs:286`, unconditional `UPDATE api_keys SET scopes=$1`)
and `revoke_key` (`:316`, `UPDATE api_keys SET revoked_at = NOW()`) have **no last-admin
check and no transaction**. An admin (or a single stolen admin key) issues
`PATCH /admin/keys/{K}/scopes {"scopes":["read"]}` or `DELETE /admin/keys/{K}` against the
only admin-scoped key → no key satisfies `is_admin_role && has_admin_scope` → every
`/admin/*` route 403s, including the role/keys endpoints needed to recover.

**Impact:** irrecoverable loss of DB-backed admin; recovery only via the optional
`OLYMPUS_ADMIN_KEY` env var (`auth.rs:335` `unwrap_or_default()`) or direct DB surgery.
The module docstring already claims "demotion **or key revocation** drops admin access" as
intended — but the *last-admin* protection is asymmetric, present only on role demotion.
Rated **Medium** because the trigger requires admin privilege (sabotage / stolen-key, not
escalation); the irrecoverability argues toward High.

**Fix:** extend the locked, transactional last-effective-admin invariant from
`update_user_role` to `update_key_scopes`, `revoke_key`, `admin_delete_user`, and
`delete_own_account`, where "effective admin" = `role=='admin'` holding an active key with
the `admin` scope.

### A1-02 — Medium — Modern-PDF decompression-bomb OOM DoS

`src-tauri/src/zk/segment/pdf_xref.rs` caps FlateDecode inflation **per stream**
(`:79-88`, `MAX_INFLATE = 64 MiB`) but `logical_objects` (`:507-569`) decodes every
referenced ObjStm container into `objstm_cache` and retains them all for the function's
lifetime, with no cumulative budget (the OOXML segmenter's `read_parts`, by contrast, has
one). `extract`'s `bodies.len() > MAX_REDACTION_SEGMENTS` check runs *after* everything is
decoded. Reachable synchronously from `POST /ingest/files` (`api/ingest/files/snapshot.rs:79`)
by any `write`/`ingest`-scope loopback caller, on bytes capped at 100 MB.

**Attack:** upload a ~100 MB modern (xref-stream) PDF with ~1000–2000 small FlateDecode
ObjStm streams each crafted to inflate to ~64 MiB (DEFLATE on zero-fill ≈ 1000:1, so each
is ~64 KiB compressed). Resident memory → tens of GB → OOM crash of the embedded node.

**Fix:** thread a shared cumulative inflate budget through
`logical_objects`/`inflate`/`decode_objstm` (mirror OOXML `read_parts`), and enforce
`bodies.len()`/byte limits incrementally during the walk.

### A1-03 — Medium — Federation equivocation detection bypass

(Behind the off-by-default `federation` feature; `OLYMPUS_FEDERATION_AUTO_BLOCK` is also
off by default, so detection is the only consequence — and these defeat it.)

Detection (`check_and_flag`, step 3, `src-tauri/src/federation/verify.rs:138`) commits its
own transaction **before** the checkpoint is stored (step 5, `:156`), with no
`pg_advisory_lock` on `peer_id`. A trusted/pinned but Byzantine peer pushes two
correctly-signed, proof-valid checkpoints with the same `checkpoint_timestamp` but
different `ledger_root` **concurrently**: each detect sees no conflict (neither stored yet)
→ both persist with `equivocation_detected=false, verified=true`. Separately, detection
keys on the peer-chosen `checkpoint_timestamp` and `ledger_root`, never on `tree_size` —
so two roots at the **same height but different timestamps** (the canonical equivocation)
are never flagged (`equivocation.rs:21-34`).

**Impact:** a provable fork from a single peer is persisted unflagged; the sole defense
against a forking peer fails under attacker timing or timestamp choice.

**Fix:** take a `pg_advisory_xact_lock` keyed on `peer_id` and run detection + storage in
one transaction; also detect conflicts on `(peer_id, tree_size)` with differing
`ledger_root`.

### L-01 — Low — Anchoring endpoints leak raw DB error text

`GET /anchors`, `/anchors/{id}`, `/anchors/{id}/receipt`
(`src-tauri/src/anchoring/api.rs:71,110,144`) map DB errors with
`err(.., &e.to_string())`, placing raw `sqlx::Error` text in the response — unlike the
`db_err()` helper used everywhere else (e.g. `api/ledger/mod.rs:70`). A `read`-scope caller
who induces a query error learns schema/driver detail. Same class as V4 R3-02 and the
`/health` fix (#1301), missed on this surface. **Fix:** route through a `db_err`-style
helper (log raw, return generic `"Database error."`).

### L-02 — Low — Anchoring client follows redirects without re-validating targets (SSRF)

`build_http_client` (`src-tauri/src/anchoring/mod.rs:323-331`) sets no redirect policy, so
reqwest follows up to 10 redirects; `validate_anchor_url` (`:172-211`) runs once on the
env URL, accepts any `https` host, and is **not** re-applied to redirect `Location`
targets. A malicious configured TSA/Rekor/calendar can 30x-redirect the node to
`http://169.254.169.254/...` or an internal host. **Low** because the three anchor URLs are
**env-only** (no API path sets them), the operator is trusted, and responses are size-capped.
**Fix:** set `reqwest::redirect::Policy::none()` on the anchoring client, or re-run the
host/scheme allow-list on each redirect and block RFC1918/link-local/loopback literals.

### L-03 / L-04 — Low — Federation hardening

- **L-03:** `federation::add_peer` (`peer.rs:66`) stores `onion_address` as an arbitrary
  string (only the BJJ pubkey is subgroup-checked); gossip builds
  `http://{onion_address}/...`. Admin-only (trusted) and cannot reach loopback services, so
  defense-in-depth — but reject non-`.onion` v3 hosts at registration.
- **L-04:** the equivocation detection SELECT filters `AND equivocation_detected = false`
  (`equivocation.rs:26`), so continued equivocation at an already-flagged timestamp is
  recorded silently. Folded into the A1-03 fix.

---

## Informational / hardening (not findings)

- **RFC 3161 TSA CMS signature is not verified at ingest** (`anchoring/tstinfo.rs`,
  `rfc3161.rs`) — only the message-imprint binding is enforced (so a receipt can't be
  swapped to attest a *different* root), with full signature verification deferred to
  offline `openssl ts -verify` by design. The stored `tst_info_verified: true` metadata
  flag could mislead an operator; consider a production fail-closed gate analogous to
  Rekor's, or rename the flag.
- **Rekor SET verification is optional outside production** (`rekor.rs`) — fail-closed in
  prod; the operator-pasted pubkey is acceptable.
- **Checkpoint digest** `Poseidon(ledger_root, ts)` omits `chain_id`/epoch
  (`federation/verify.rs`) — sound under the one-authority-key-per-ledger model; document
  the assumption or bind a `chain_id` if that ever changes.
- **`OLYMPUS_ENV` is read ad-hoc in ~6 sites** with case-insensitive but **un-trimmed**
  compares; a deployment typo (`"production "`, `OLYMPUS_ENVIRONMENT=…`, `"prod"`) silently
  fails *open* across multiple production gates at once (ceremony `exit(2)`, `keys_dir`
  override, CORS, Rekor enforcement). Resolve `OLYMPUS_ENV` once at startup into a canonical
  enum; treat unknown/empty as a hard error (or default-to-production); log the resolved mode.
- **CSV export writes `users.id` unescaped** (`admin.rs`) — safe today (server-generated
  UUID); route through `escape_csv_field` defensively.
- **Scope-list drift:** `user_auth/helpers.rs` `VALID_SCOPES` omits `prove` while
  `admin_users.rs` includes it (restrictive/fail-closed; unify to one canonical list).
- **Two admin-gate implementations** (`require_admin_auth` dual-path vs `keys/admin.rs`
  env-only) — the latter is stricter; consolidate to remove drift risk.
- **OOXML segmenter** pushes part names before the count cap is checked; break early on
  `> MAX_REDACTION_SEGMENTS`.
- **Cross-tool informational (tracked separately):** ToB constant-time — EdDSA signing in
  `babyjubjub-permissive/src/eddsa.rs` is variable-time (no remote timing oracle: single
  server-side signer). ToB zeroize — `AppState` stores long-lived secrets as bare
  `Option<[u8;32]>` and is `#[derive(Clone)]`; wrap in `Arc<Zeroizing<[u8;32]>>`. Docs —
  ADR-0025 still describes the removed `redaction_validity` SNARK (ADR-0030 "the flip");
  re-head it as superseded.

---

## What held under attack (builds trust in the above)

- **Access control:** SBT scope forgery/replay is blocked (issuer-trust + window +
  commit_id recompute + unforgeable BJJ-EdDSA, malleability-closed); the dual-path admin
  gate is correct on every edge (empty header, unset env, role AND scope, constant-time
  compare); shard `authorize_write` is fail-closed; "new scopes ⊆ caller scopes" holds on
  every key-creation path; the first-user bootstrap race is closed by an advisory lock; no
  BOLA on per-user resources.
- **Injection:** uniformly parameterized SQL (no `QueryBuilder`/`format!` into query text,
  clamped+bound pagination, no dynamic identifiers); validate-point == use-point for
  `shard_id`; server-recomputed content hashes; no jsonpath in the backend; no
  command/path/log/header injection.
- **Crypto:** BJJ EdDSA verifier enforces subgroup + canonical-S; domain separation across
  SBT/quorum/revoke/checkpoint/snapshot is disjoint; OsRng randomness throughout; scrypt
  with constant-time compare + email-enumeration defense; one-shot secrets via
  `Option::take` + `Zeroizing`, never persisted in prod; dev secret-leak routes
  triple-gated; quorum threshold + signer set cryptographically bound (V4 R3-01 fixed).
- **Integrity invariants:** write-once ledger (no delete/tombstone path), redaction
  signed-fold binds the redacted flag + format + count + recipient, `treeSize=0` invariant,
  ceremony-manifest coordinator-signature + blake3 checks — all enforced and fail-closed.
- **Resource handling:** no zip-slip (in-memory OOXML repackage), no request-reachable path
  traversal, zero filesystem writes on ingest, TOCTOU-safe Tauri IPC file reads.

---

## Coverage note

A single adversarial run finds roughly half of all discoverable issues. This is **run-1**.
A re-run weighted toward business logic, the wildcard agent, and the federation subsystem
(the densest finding area this round) is recommended before any external-audit milestone.
