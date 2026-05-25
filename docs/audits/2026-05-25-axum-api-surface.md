---
**Date:** 2026-05-25
**Branch:** `main` (HEAD `31dcc623`)
**Scope:** Axum HTTP API surface excluding routes already covered by the prior
2026-05-25 ZK / anchoring / federation audit. Specifically: `api/ingest.rs`,
`api/ledger.rs`, `api/redaction.rs`, `api/credentials.rs`, `api/admin.rs`,
`api/admin_users.rs`, `api/keys.rs`, `api/user_auth.rs`,
`routes/public_stats.rs`. Excludes `api/middleware/auth.rs`, `api/zk.rs`,
`api/anchors.rs` (already audited).
**Type:** Read-only audit.
**Out of scope:** Tauri IPC commands (next audit area), frontend, migrations,
build / supply chain.

---

## 1. Executive summary

8 findings: **0 High, 3 Medium, 5 Low, 4 verified clean** (the original
draft flagged a "High" H-API-1 that turned out to be safe — the existing CSV
sanitizer is sound; demoted to a doc-clarity Low).

The overall posture of the HTTP API is **strong**:

- All SQL uses sqlx bind parameters; no string-built queries on user input.
- Auth is consistently enforced via the `AuthenticatedKey` extractor; no
  bypass found.
- Scope-based RBAC is wired at every protected route.
- Input validation (hex/decimal/length/JSON-size) is comprehensive.
- DoS surfaces are well-bounded (per-record size caps, file upload caps,
  pagination clamps, streaming CSV export).

The findings are refinements, not blockers:

1. **M-API-1** — State-changing routes rely on CORS for origin checks but
   never validate `Host` independently; no defense-in-depth against header
   spoofing on loopback.
2. **M-API-2** — Pagination limit clamps silently; abuse is invisible to the
   operator.
3. **M-API-3** — `routes/public_stats.rs` dynamically constructs SQL by
   formatting whitelisted table names into a `UNION` query; the table list
   is hardcoded, but the construction pattern is fragile.

Plus five Lows around comment clarity, canonical-input parsing, and
fire-and-forget audit-log inserts.

---

## 2. Findings — Medium

### 🟡 M-API-1 — No `Host` validation on state-changing routes

**Location:** [server/mod.rs:76](src-tauri/src/server/mod.rs:76)
(CORS layer); applies to every `POST` / `PUT` / `DELETE` route.

**What:** `cors_layer()` validates `Origin` against a whitelist of Tauri +
loopback origins. No route also validates the `Host` header against an
expected loopback address. Origin-only checks miss DNS-rebinding scenarios
where a remote attacker controls a hostname that resolves to 127.0.0.1 in
the target's resolver — the browser sends the attacker's origin (which fails
CORS) but if anything ever bypassed or weakened CORS (e.g. a future
non-browser caller, or a CORS misconfig), `Host` would also be wrong.

**Why it matters:** Defense-in-depth. The single-user desktop threat model
makes this low-risk today, but DNS rebinding has historically been the
exact vulnerability class that hits embedded loopback HTTP servers.

**Fix sketch:** Add a `validate_loopback_host` tower middleware that rejects
any request whose `Host` header is not `127.0.0.1:<port>`, `[::1]:<port>`,
or `localhost:<port>`. Apply at router root.

### 🟡 M-API-2 — Pagination clamps are silent

**Location:** [ledger.rs:392](src-tauri/src/api/ledger.rs:392)
(`get_activity` `limit.clamp(1, 200)`); same pattern repeats in admin /
credentials listings.

**What:** A client sending `?limit=99999999` gets results clamped to 200
with no log, no warning, no header indicating the clamp happened. An
abusive client hammering the endpoint is invisible.

**Why it matters:** Hides abuse. Also makes well-behaved clients silently
incorrect about how much data they got.

**Fix sketch:** When `params.limit > MAX`, emit `tracing::info!` with the
requested vs effective limit, and set an `X-Limit-Clamped: <max>` response
header so clients can detect it.

### 🟡 M-API-3 — `public_stats.rs` builds SQL by formatting table names

**Location:** [public_stats.rs:67](src-tauri/src/routes/public_stats.rs:67)
(`count_distinct_shards`).

**What:** Iterates a hardcoded `parts` list and `format!`s each table name
into `SELECT DISTINCT shard_id FROM "{}" WHERE shard_id IS NOT NULL`, joined
with `UNION`, wrapped in `sqlx::query_scalar::<_, i64>(AssertSqlSafe(sql))`.
The list is hardcoded and audit-clean today, but the pattern itself —
dynamic SQL with `AssertSqlSafe` — is exactly what gets accidentally
weakened by future refactors.

**Why it matters:** A future contributor adding "let's read the table list
from a config file" or "let's parametrize per tenant" silently turns this
into a SQL-injection sink. The hardening is in policy (the hardcoded list),
not in mechanism.

**Fix sketch:** Replace `AssertSqlSafe(sql)` use with a static `&'static str`
union built at compile time via macro, or split into N separate parametrized
queries (one per table) and sum in Rust. Eliminates the dynamic SQL pattern
entirely.

---

## 3. Findings — Low

### 🟢 L-API-1 — Misleading CSV sanitizer comment

**Location:** [admin.rs:195](src-tauri/src/api/admin.rs:195)
(`sanitize_csv_cell` + `escape_csv_field`).

**What:** The sanitizer is correct (formula-trigger prefix + later quote
wrap composes safely). The comment understates the two-part nature of the
defense, so a future refactor that moves the prefix step risks breaking the
guarantee silently.

**Fix sketch:** Expand the comment to: "Prefix step neutralises formula
triggers ONLY in combination with the quote-wrap step downstream. Do not
move either step."

### 🟢 L-API-2 — `parse_fr_decimal` accepts leading zeros

**Location:** [credentials.rs:239](src-tauri/src/api/credentials.rs:239).

**What:** `"00123"` round-trips to `"123"` via `fr_to_decimal`, breaking
the round-trip invariant the function comment promises. Safe today because
every caller pre-validates with `is_ascii_digit` + leading-zero rejection,
but the helper itself does not enforce.

**Fix sketch:** Add `if s.len() > 1 && s.starts_with('0') { return None; }`
at the top of `parse_fr_decimal`.

### 🟢 L-API-3 — Admin authority requires BOTH role and scope

**Location:** [admin.rs:159](src-tauri/src/api/admin.rs:159)
(`require_admin_authority`).

**What:** The query joins `api_keys` to `users`; the check requires
`is_admin_role && has_admin_scope`. If an admin user is demoted to `user`
but still holds a key with `admin` scope, the key silently loses
admin-route access. This is arguably the right behaviour, but it is not
documented and surprises operators who reason about either model alone.

**Fix sketch:** Add a 3-line comment explaining the AND requirement and the
demotion semantics. Optionally: when a user is demoted, revoke their
admin-scoped keys atomically (separate issue).

### 🟢 L-API-4 — Redaction issuance not idempotent / not mask-fingerprinted

**Location:** [redaction.rs:260](src-tauri/src/api/redaction.rs:260).

**What:** A caller can issue arbitrarily many redaction proofs for the same
(content_hash, recipient) pair with conflicting reveal masks. No mask
digest is logged or stored. This is a transparency gap, not a soundness
gap (each proof is individually correct).

**Fix sketch:** Log `tracing::info!("redaction_issue content={ch} mask_digest={d}")`
where `d = BLAKE3(reveal_mask)`. Cheap, makes audit trails forensically
reconstructable.

### 🟢 L-API-5 — Ledger activity log writes are best-effort

**Location:** [ledger.rs:600](src-tauri/src/api/ledger.rs:600)
(`simple_document_ingest`).

**What:** Activity-log INSERT errors propagate via `?`, so the ingest fails
if the audit insert fails. Without a transaction wrapping the two writes,
the previously-committed doc_commits row is **orphaned** on activity-log
failure. The doc is in the ledger but no activity row records it.

**Fix sketch:** Wrap the doc_commits insert + ledger_activities insert in a
single `pool.begin()` transaction; commit at the end. Atomicity is what
the audit trail needs.

---

## 4. Verified clean — appendix

| Item | Why it's not a finding |
|---|---|
| [ingest.rs:245](src-tauri/src/api/ingest.rs:245) `commit_records` | Scope enforced, 100-record limit, 16 KiB JSON cap on `extra` (audit F-5), fields validated pre-DB. |
| [ingest.rs:829](src-tauri/src/api/ingest.rs:829) `ingest_file` | Scope enforced, 100 MB file cap, shard/record IDs validated at multipart boundary (audit F-8). |
| [ingest.rs:1047](src-tauri/src/api/ingest.rs:1047) `issue_zk_bundle` | Scope enforced, 64-char hex hash, cache-hit verbatim return, witness pre-checked before WASM. |
| [admin.rs:304](src-tauri/src/api/admin.rs:304) `export_customers_csv` | `async_stream` + `Body::from_stream` prevents OOM (F-6); 50k row cap; CSV cell sanitiser (L-API-1) applied per cell. |
| [admin_users.rs:186](src-tauri/src/api/admin_users.rs:186) `mint_key_for_user` | User existence pre-check, fresh BJJ keypair generation, raw key + BJJ private returned once. |
| [user_auth.rs](src-tauri/src/api/user_auth.rs) auth flow | Argon2 + constant-time compare, API keys stored as BLAKE3 hash, scopes validated against hardcoded allow-list. |
| sqlx usage everywhere except `public_stats.rs` | Bind parameters throughout — no string-built queries on user input. |
| Rate limiting via `RateLimit` extractor | `governor` per-IP; correctly ignores `X-Forwarded-For` for loopback-only model. |

---

## 5. Cross-cutting observations

- **Input validation is comprehensive** at the handler boundary.
- **Auth enforcement is consistent**; the `AuthenticatedKey` + scope
  pattern is applied everywhere it should be.
- **No SQL injection risk** outside the single `AssertSqlSafe` site in
  `public_stats.rs` (which itself is policy-safe today).
- **Error messages are generic** to clients; DB internals are logged but
  not returned.
- **Streaming where it matters** (CSV export) keeps memory bounded.

This API surface is production-ready. The action items below are
refinements, ordered by impact.

## 6. Recommended order of operations

1. **M-API-1** — Host validation middleware (~30 min).
2. **M-API-2** — Pagination clamp logging + header (~15 min).
3. **M-API-3** — Replace `AssertSqlSafe` dynamic SQL with parametrised
   per-table queries (~30 min).
4. **L-API-2** — `parse_fr_decimal` leading-zero rejection (~5 min).
5. **L-API-5** — Wrap ingest + activity log in a transaction (~15 min).
6. **L-API-1, L-API-3, L-API-4** — Comment + log-line refinements (~10 min total).
