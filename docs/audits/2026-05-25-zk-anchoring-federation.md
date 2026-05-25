# Audit — ZK / Pedersen / SBT + Anchoring + Federation

**Date:** 2026-05-25
**Branch:** `main` (HEAD `872274d6`)
**Scope:** ZK / Pedersen / SBT crypto hot path (baseline re-verify of recent
fixes), plus the anchoring (`src-tauri/src/anchoring/`) and federation
(`src-tauri/src/federation/`) modules.
**Type:** Read-only audit — no code changes proposed inline; fixes are
sketched per finding.
**Out of scope:** Axum API surface beyond the routes named, sqlx migrations
beyond anchor/peer tables, frontend, the Tauri shell.

---

## 1. Executive summary

Out of 17 candidate findings investigated, **2 High, 5 Medium (incl. 3 "v1.0
roadmap"), 4 Low, 6 verified clean**.

The headline issues are not subtle bugs in the crypto — that layer is
unusually well-built. They are **integration gaps** between modules and their
own documentation:

1. **🔴 H-A1 — The entire anchoring stack is unreachable at runtime.**
   `crate::anchoring::anchor_all` is wired, the DB schema is wired, the
   `/anchors` list/fetch routes are wired, but the only function that
   submits to RFC 3161 / Rekor / OTS — `federation::checkpoint::anchor_checkpoint`
   — is **never called from anywhere in the codebase.** Setting
   `OLYMPUS_ANCHOR_RFC3161_URL` etc. has zero observable effect. The
   `docs/court-evidence.md` three-layer claim is currently aspirational.
2. **🔴 H-F1 — The federation module is dead code in shipping builds.**
   `mod federation` is declared and the router merges federation endpoints
   under `#[cfg(feature = "federation")]`, but `start_hidden_service()` and
   `gossip::spawn()` are never invoked from [main.rs](src-tauri/src/main.rs)
   or [bootstrap.rs](src-tauri/src/bootstrap.rs). Even with
   `--features federation`, the Tor HS never starts, no gossip ever runs.
3. **🟡 M-D1 — `docs/court-evidence.md` tells courts to run `ots verify`
   against shipped receipts, but v0.9 only produces *pending* OTS receipts**
   that fail the `ots verify` command. Documented as a known limitation
   inside the code, but the court-facing doc doesn't say so.

The crypto baseline (Pedersen, SBT verify, CircomReduction, scope mapping)
is genuinely solid — all five reviewed fixes hold up.

---

## 2. Baseline verification

| Fix | Status | Notes |
|---|---|---|
| #992 — Pedersen commits on BJJ for SBT privacy | ✅ Clean | Generator pinned by golden test ([pedersen.rs:689](src-tauri/src/zk/pedersen.rs:689)); subgroup-scalar guard rejects `m,r ≥ l` with explicit test of the binding-break attack ([pedersen.rs:633](src-tauri/src/zk/pedersen.rs:633)). |
| #1011 — `CircomReduction` for snarkjs zkeys | ✅ Clean | Sole call site is `prove_circom` ([prove.rs:237](src-tauri/src/zk/prove.rs:237)); `Groth16::prove` banned via clippy.toml; grep confirms no other reduction is used anywhere in the workspace. |
| #1050 H-7 — SBT scope path verifies signature | ✅ Clean | [auth.rs:98-223](src-tauri/src/api/middleware/auth.rs:98) skips unsigned rows, checks trusted issuer, recomputes commit_id, verifies BJJ-EdDSA. |
| #1050 H-12 / F-3 — Equivocation auto-block default-off + gated on sig | ✅ Clean | [verify.rs:130](src-tauri/src/federation/verify.rs:130) fires only on `sig_verified && equivocated && config_flag`; default `false` ([mod.rs:47](src-tauri/src/federation/mod.rs:47)). |
| #1050 M-1 / M-8 — BJJ R8/pubkey subgroup checks | ✅ Clean | `verify_signature` enforces; `add_peer` validates at registration ([peer.rs:69](src-tauri/src/federation/peer.rs:69)). |
| #1053 — `decompress_checked` + Pedersen doc caveats | ⚠ Mostly clean — see [L-Z1](#L-Z1) | Subgroup-enforcing decompress is correct; test coverage thin (no cofactor-coset rejection case). |

---

## 3. Findings — Anchoring

### 🔴 H-A1 — `anchor_checkpoint` is never called → anchors never fire

**Location:** [federation/checkpoint.rs:140](src-tauri/src/federation/checkpoint.rs:140)
(`anchor_checkpoint`), [anchoring/mod.rs:150](src-tauri/src/anchoring/mod.rs:150)
(`anchor_all`).

**What:** `anchor_checkpoint` is the only function that calls
`crate::anchoring::anchor_all`, which is the only function that submits to
the three external anchors. A workspace-wide grep for `anchor_checkpoint`
returns exactly one definition and zero call sites. `anchor_all` likewise
has one caller (anchor_checkpoint). The `/anchors`, `/anchors/{id}`, and
`/anchors/{id}/receipt` routes can list and fetch rows, but nothing in the
codebase ever inserts one.

**Why it matters:** the entire promise in
[docs/court-evidence.md §1-§4](docs/court-evidence.md) — "registered the
existence of that signed state with three independent third-party services"
— is unfulfilled. An operator who sets `OLYMPUS_ANCHOR_RFC3161_URL`,
`OLYMPUS_ANCHOR_REKOR_URL`, `OLYMPUS_ANCHOR_OTS_CALENDARS` will get no
errors, no logs, and no receipts. The chain-of-custody claim collapses to
"Olympus signed it" — which is exactly what the anchors exist to escape.

**Threat model:** an adversary disputing an Olympus-attested timestamp in
court today only needs to point out that the database table is empty. No
external receipts can be produced for any checkpoint, because none were
ever requested. Operator self-deception is the immediate risk —
"anchoring is enabled" is the kind of thing you only verify by reading
the DB, and the code path that *would* fail loudly never executes.

**Fix sketch:** add a call to `anchor_checkpoint` immediately after every
`store_peer_checkpoint` (in [verify.rs:141](src-tauri/src/federation/verify.rs:141))
and after every successful `build_own_checkpoint` (currently only built
inside [gossip.rs:53](src-tauri/src/federation/gossip.rs:53) — which itself
never runs; see [H-F1](#-h-f1--federation-module-is-dead-code)).
Independently of the federation fix, **anchoring should not depend on
federation being enabled** — the act of producing a local checkpoint is
worth anchoring on its own. Plumb `anchor_all` into the ingest path or a
periodic checkpoint cron in the always-built code.

### 🟡 M-A1 (roadmap) — RFC 3161: response nonce never compared to request nonce

**Location:** [anchoring/rfc3161.rs:151-162](src-tauri/src/anchoring/rfc3161.rs:151).

**What:** We send a 63-bit random nonce in the `TimeStampReq`
([rfc3161.rs:125-130](src-tauri/src/anchoring/rfc3161.rs:125)), persist it
in `metadata.request_nonce`, and store the raw response bytes. We do not
parse the `TimeStampResp` to confirm the nonce returned by the TSA
matches the one we sent — the only sanity check is "starts with `0x30`
and is at least 8 bytes long."

**Why it matters:** documented as deferred to `openssl ts -verify` in the
court-evidence packet, which is a defensible v0.9 choice — but a TSA (or
MITM) could splice in any old `TimeStampResp` they already had and our
ingestion would accept it as a fresh anchor. The mismatch surfaces later
in offline verification, by which point an operator may have published a
bundle claiming the wrong timestamp.

**Fix sketch (v1.0):** parse the inner `TSTInfo` enough to extract the
nonce (RFC 3161 §2.4.2) and reject on mismatch. Verifying the TSA cert
chain can stay deferred; the nonce check is ~15 lines of DER walking and
closes the replay window.

### 🟡 M-A2 (roadmap) — Rekor `signedEntryTimestamp` never verified against log key

**Location:** [anchoring/rekor.rs:142-149](src-tauri/src/anchoring/rekor.rs:142).

**What:** Rekor returns a `verification.signedEntryTimestamp` (SET) — the
log's signature over the entry — which we copy into metadata and persist
the raw envelope. We never fetch Rekor's public key and verify the SET.

**Why it matters:** without that check, a forged or replayed Rekor
response could be accepted as proof. Like M-A1, this is "deferred to
offline tooling" by design — but `docs/court-evidence.md §3 step 5` tells
the verifier to run `rekor-cli get --uuid <UUID>`, which queries the
*live* Rekor service. If the log is later rebuilt or the entry rotates
out, the saved receipt is the only evidence and it carries no
independently verifiable signature.

**Fix sketch (v1.0):** Sigstore's TUF root publishes Rekor's signing key;
ship the key bytes embedded in the binary (~32 bytes) and verify the SET
with `ed25519_dalek::VerifyingKey::verify` against
`Base64(canonical_body)`. Refuse to persist the receipt on mismatch.

### 🟡 M-A3 (roadmap) — OTS upgrade pipeline missing; court-evidence doc instructs `ots verify` on pending receipts

**Location:** [anchoring/ots.rs:101](src-tauri/src/anchoring/ots.rs:101),
[docs/court-evidence.md §2 row 4 + §3 step 6](docs/court-evidence.md).

**What:** `try_upgrade()` exists but is never invoked anywhere. v0.9 only
ever ships *pending* OTS receipts. `docs/court-evidence.md` tells courts
to run `ots verify <receipt> -f <file>`, but that command **fails** on a
pending receipt because no Bitcoin commitment exists yet.

**Why it matters:** this is a documentation/code coherence bug, not a
cryptographic one. The doc claims "OpenTimestamps + Bitcoin (no Olympus
code involved, no Sigstore, no TSA — just Bitcoin's public chain)" but
the artifact courts are handed cannot be verified that way until upgrade
runs.

**Fix sketch (v1.0):** add a periodic "upgrade pass" — every 6 hours,
walk `anchor_receipts WHERE kind='ots' AND metadata->>'phase' = 'pending'`,
call `try_upgrade`, replace the blob and flip metadata to `phase: 'upgraded'`
on success. Until that lands, **update court-evidence.md** to say
"OTS receipts ship pending; verification requires running
`ots upgrade <receipt>` first (manual until v1.0)."

### 🟢 L-A1 — Silent fallback `OLYMPUS_ANCHOR_SIGN_KEY` → `OLYMPUS_INGEST_SIGNING_KEY`

**Location:** [anchoring/rekor.rs:88-95](src-tauri/src/anchoring/rekor.rs:88).

**What:** if `OLYMPUS_ANCHOR_SIGN_KEY` is unset, Rekor signs with the
ingest key. No log line says "using fallback."

**Why it matters:** an operator who wanted anchor-signing isolated from
ingest-signing won't notice they're conflated until they inspect a
receipt by hand.

**Fix:** one `tracing::info!` at first use noting which env var was
chosen. Trivial.

### 🟢 L-A2 — TSA / Rekor / calendar URLs accepted verbatim from env

**Location:** [anchoring/mod.rs:94-107](src-tauri/src/anchoring/mod.rs:94).

**What:** the three URLs are read from env vars and passed straight to
`reqwest`. No scheme check (http://… is accepted), no hostname pinning.

**Why it matters:** a misconfigured operator could anchor to
`http://anything.local/`. Limited blast radius because the receipts are
opaque, but pollutes the audit trail.

**Fix:** require `https://` (or `http://localhost`/`127.0.0.1` for dev)
in `AnchoringConfig::from_env`; reject otherwise with a startup warning.

---

## 4. Findings — Federation

### 🔴 H-F1 — Federation module is dead code

**Location:** [main.rs:15-16](src-tauri/src/main.rs:15) (declares `mod federation`),
[server/mod.rs:64-67](src-tauri/src/server/mod.rs:64) (merges routers),
[bootstrap.rs](src-tauri/src/bootstrap.rs) (no federation calls).

**What:** grep for `start_hidden_service|gossip::spawn|federation::` outside
the federation module returns only the router merges and one
`federation_config: Option<…>` field on `AppState`. Nothing initialises
`federation_config` to `Some(…)`, nothing bootstraps Tor, nothing spawns
the gossip loop. With `--features federation`:

- `tor_router()` is merged onto the local 127.0.0.1 Axum listener, so
  `POST /federation/checkpoint` is reachable from localhost — but only
  there; no `.onion` exists.
- `get_identity` and `federation_status` both error 503 with
  "Federation not enabled" because `state.federation_config` is `None`.
- `gossip::spawn` is never called.

So the entire module is, today, code that compiles and ships in a
feature-flagged binary but cannot ever run.

**Why it matters:** beyond the wasted security surface, this means:
- The `/federation/checkpoint` push route IS reachable locally with no
  API key (the tor_router has no auth — see api.rs:288-293). Today that's
  fine because nobody from outside the host can reach 127.0.0.1, but it
  is a foot-gun the moment someone exposes the Axum port. The "no auth
  needed because Tor + sig verification" assumption only holds if Tor is
  actually the only way in.
- All of [H-F1](#-h-f1--federation-module-is-dead-code)'s downstream
  hardening (verify-then-store, equivocation, auto-block) is unreachable
  in practice. Audit findings #1050 land in a code path that never
  executes.
- [H-A1](#-h-a1--anchor_checkpoint-is-never-called--anchors-never-fire)
  is doubly unreachable because the federation gossip loop that *would*
  call anchor_checkpoint also never runs.

**Fix sketch:** decide whether v0.9 is supposed to ship working federation
or not. If not — `#[cfg(feature = "federation")]` the router merge to be
honest, and add a `compile_error!` if the feature is enabled without the
wiring landing. If yes — initialise `FederationConfig`, call
`tor::start_hidden_service`, spawn `gossip::spawn` in
[main.rs:330](src-tauri/src/main.rs:330)'s tokio block, and gate the
local-only admin router behind `AuthenticatedKey` even more tightly.

### 🟡 M-F1 — Zero unit tests in `src-tauri/src/federation/`

**Location:** module-wide. Grep for `#[test]` or `#[tokio::test]` in
`src-tauri/src/federation/` returns nothing.

**What:** every other crypto-adjacent module in the repo has fairly
comprehensive tests (pedersen.rs has 20+, credentials.rs has 15+,
auth.rs has 6). Federation has zero. `verify_checkpoint_signature`,
`check_and_flag`, `validate_pubkey_subgroup` rejection of small-order
points, `peer_matches_authority_hash`, `auto_block_peer` gating — all
untested.

**Why it matters:** the audit-driven hardening in #1050 (H-5, H-11, H-12,
M-1, M-8) lives entirely inside this untested code. Any future refactor
can silently regress those fixes.

**Fix sketch:** at minimum add three tests:
1. `verify_checkpoint_signature_rejects_tampered_root` — flip one bit of
   ledger_root, sig must fail.
2. `verify_and_store_does_not_store_on_invalid_sig` — assert DB unchanged
   after fail-closed path.
3. `check_and_flag_detects_conflicting_root` — use sqlite-in-memory or
   test pgembed to insert two conflicting checkpoints, assert both rows
   get flagged.
None of these need Tor.

### 🟡 M-F2 — Hidden-service key has no rotation API and no documented backup

**Location:** [federation/tor.rs:53-94](src-tauri/src/federation/tor.rs:53).

**What:** arti persists HS keys under `{app_data_dir}/tor/state/`. The
onion address is deterministic across restarts only because that
directory survives. No code path rotates the key; no docs tell operators
to back the directory up. If a user wipes app data (a normal
troubleshooting step on Windows), the node silently changes onion
address — every peer's pinned `bjj_pubkey + onion_address` row in
`peer_nodes` now points to an unreachable address, and there's no
heartbeat to warn either side.

**Why it matters:** denial-of-availability bug. Recovery story is "ask
every peer to re-add you under your new onion." For a small federation
this is annoying; for a larger one, it's a downtime event.

**Fix sketch:** (1) document the back-up procedure for the `tor/state`
dir in `docs/federation.md` (file doesn't exist yet — create it); (2)
add `POST /federation/identity/rotate` (admin scope) that wipes the dir,
restarts the HS, and emits a tracing warning; (3) on startup, log the
onion address always so operators can compare against expectations.

### 🟢 L-F1 — `PeerCheckpoint` wire format carries no version field

**Location:** [federation/checkpoint.rs:13-22](src-tauri/src/federation/checkpoint.rs:13).

**What:** the JSON shape exchanged between peers has no `version`. Any
future field rename or hash-input change is a wire break with no
negotiation.

**Why it matters:** mostly forward-compatibility hygiene; today there's
exactly one wire shape so nothing to negotiate. Cost of adding it now
is one line.

**Fix:** add `pub wire_version: u8` with `#[serde(default = "default_wire_version")]`
defaulting to `1`. Reject anything that isn't `1`.

### 🟢 L-F2 — Gossip pull/push errors logged at debug, never persisted

**Location:** [federation/gossip.rs:55-80](src-tauri/src/federation/gossip.rs:55).

**What:** `push_checkpoint` / `pull_checkpoint` failures `tracing::debug!`
and move on. There is no `peer_health` or `gossip_metric` table.

**Why it matters:** when federation actually starts running, an operator
won't have any way to answer "has peer X been reachable lately?" except
by tailing logs.

**Fix:** add a `last_pull_error_at`, `last_pull_error_msg` pair to
`peer_nodes` and update on each failure. The existing `touch_last_seen`
gives you the success side already.

---

## 5. Findings — ZK baseline

<a id="L-Z1"></a>

### 🟢 L-Z1 — `decompress_checked` test coverage misses cofactor-coset case

**Location:** [pedersen.rs:543-559](src-tauri/src/zk/pedersen.rs:543).

**What:** the only "bad" input tested is `[0xFF; 32]` (overwhelmingly not
decompressible). There is no test that constructs a valid on-curve but
**not in prime-order subgroup** point (a cofactor-coset coordinate) and
asserts `decompress_checked` rejects it.

**Why it matters:** `is_in_prime_subgroup` is the entire reason
`decompress_checked` exists. Today the function obviously works because
its definition just chains `decompress` + the subgroup check, but the
test wouldn't catch a future refactor that conflated them.

**Fix:** add `decompress_checked_rejects_cofactor_coset_point` — construct
`P = pedersen_h() + small_order_point` (any of the 8 cofactor reps),
compress, call `decompress_checked`, assert `Err(NotInSubgroup)`. ~10
lines.

### 🟡 M-Z1 — Unified-circuit prover has no Rust pre-checks

**Location:** [prove.rs:382-396](src-tauri/src/zk/prove.rs:389).

**What:** `prove_existence` / `prove_non_existence` / `prove_redaction` all
run a witness pre-check (re-derive Merkle root in native Rust) before
invoking the WASM witness generator. `prove_unified` does not — the TODO
on line 387 acknowledges this. An invalid witness surfaces as an opaque
WASM failure deep inside `ark-circom`, not as a clean `WitnessInvalid`.

**Why it matters:** the WASM witness generator owns a precious resource
([`WASM_SEM`](src-tauri/src/zk/prove.rs:162) — 4 slots) and a slow
failure path locks one of those slots for up to ~5s of futile witness
construction. A malicious caller can submit 4 bad witnesses in parallel
and lock the prover for 120s (the semaphore timeout) without any
authentication-tier limit catching it sooner.

**Fix sketch:** port the SMT / Merkle / EdDSA pre-checks from
`witness/unified.rs` to a `verify_inputs` method on `UnifiedWitness`,
call it from `prove_unified`. Defer EdDSA-Poseidon verification check
specifically (that's heavy) but at least re-derive the canonicalization
hash and Merkle root cheaply.

### 🟢 L-Z2 — `client_ip` always returns loopback — comment promises future plumbing that hasn't happened

**Location:** [auth.rs:516](src-tauri/src/api/middleware/auth.rs:516).

**What:** comment says "when we plumb `axum::extract::ConnectInfo<SocketAddr>`
through the router for multi-tenant deployments, slots in here." The
plumbing has not happened, but the comment is now ~6 months old and the
function signature still takes `_parts` for the future. Worth either
deleting the aspirational comment or filing a tracking ticket.

**Why it matters:** informational — the current loopback behaviour is
correct for a single-user desktop. But a future contributor reading this
might assume the multi-tenant work is imminent and design code that
relies on it.

**Fix:** delete the second paragraph of the comment, leave just the
"single-user desktop is the model" rationale.

---

## 6. Documentation gap (cross-cutting)

### 🟡 M-D1 — `docs/court-evidence.md` overstates v0.9's verification story

This is one finding with several anchors:

- §1 promises "registered the existence … with three independent
  third-party services" → **anchors never fire** (see [H-A1](#-h-a1--anchor_checkpoint-is-never-called--anchors-never-fire)).
- §3 step 6 (`ots verify <receipt>`) → **fails on pending receipts**
  (see [M-A3](#-m-a3-roadmap--ots-upgrade-pipeline-missing-court-evidence-doc-instructs-ots-verify-on-pending-receipts)).
- §3 step 5 (`rekor-cli get --uuid`) → **assumes the live Rekor server
  is reachable**, with no warning that the saved receipt has no
  independently verifiable signature (see [M-A2](#-m-a2-roadmap--rekor-signedentrytimestamp-never-verified-against-log-key)).

**Fix:** add a "v0.9 verification status" callout at the top of
court-evidence.md that says, plainly, which of the three anchor types
actually works end-to-end at this version. Better: bring the code up
to match the doc.

---

## 7. Verified clean — appendix

Things checked and intentionally NOT flagged, with reason. The point is
to save next audit's time.

| Item | Why it's not a finding |
|---|---|
| [pedersen.rs](src-tauri/src/zk/pedersen.rs) module docs accurately describe hiding/binding/side-channel posture | Reviewed cover-to-cover; comments match code. |
| [pedersen.rs:374-381](src-tauri/src/zk/pedersen.rs:374) `random_blinding` uses 64-byte sample → mod-l reduction | Bias < 2⁻²⁵⁶, correct. |
| [credentials.rs:805](src-tauri/src/api/credentials.rs:805) defensive subgroup re-check on stored commitment | Belt-and-suspenders against DB-tier tamper. Good. |
| [credentials.rs:239](src-tauri/src/api/credentials.rs:239) `parse_fr_decimal` strict (rejects ≥ modulus) | Audit M-3 fix; comprehensive tests. |
| [credentials.rs:107](src-tauri/src/api/credentials.rs:107) `compute_commit_id` length-prefixes every variable field | No field-boundary collision possible. |
| [credentials.rs:140](src-tauri/src/api/credentials.rs:140) `compute_commit_id_for_commitment` uses disjoint domain tag from plaintext path | Confirmed by `commit_ids_have_disjoint_domains` test. |
| [auth.rs:516](src-tauri/src/api/middleware/auth.rs:516) `client_ip` ignores `X-Forwarded-For` | Audit M-6 fix; regression test in place. (Minor doc nit in [L-Z2](#-l-z2--client_ip-always-returns-loopback--comment-promises-future-plumbing-that-hasnt-happened) only.) |
| [auth.rs:66-74](src-tauri/src/api/middleware/auth.rs:66) hardcoded scope mapping, unknown types grant nothing | Intentional security policy. Test pinned. |
| [equivocation.rs:21-49](src-tauri/src/federation/equivocation.rs:21) uses `FOR UPDATE` row lock within transaction | Race-condition-free; in-memory cache from Python era ([memory: project_h6_fix](.claude/memory/project_h6_fix.md)) is not needed in Rust. |
| [verify.rs:195-200](src-tauri/src/federation/verify.rs:195) rejects negative `checkpoint_timestamp` instead of wrapping `as u64` | Honest error class. Good. |
| [api.rs:288-293](src-tauri/src/federation/api.rs:288) `tor_router` has no API-key auth | Correct given the intended deployment (Tor-only, sig-gated). Becomes a foot-gun if federation is ever exposed locally — see [H-F1](#-h-f1--federation-module-is-dead-code). |
| [prove.rs:236-238](src-tauri/src/zk/prove.rs:236) `#[allow(clippy::disallowed_methods)]` on the only sanctioned `Groth16::prove` site | Correct localization; clippy.toml ban is the regression guard. |

---

## 8. Recommended order of operations

If only some of these get fixed this cycle, this is the highest-value order:

1. **[H-A1](#-h-a1--anchor_checkpoint-is-never-called--anchors-never-fire) + [H-F1](#-h-f1--federation-module-is-dead-code) together** — decide what v0.9 actually
   ships. Either wire up both, or honestly disable federation routes and
   move anchoring to the always-built ingest path. Court-evidence claims
   stand or fall here.
2. **[M-D1](#-m-d1--docscourt-evidencemd-overstates-v09s-verification-story)** — even before code changes land, update court-evidence.md so we
   don't ship a binary whose docs misrepresent it.
3. **[M-F1](#-m-f1--zero-unit-tests-in-src-tauri-srcfederation)** — write the three federation tests. ~2 hours.
   Stops future regressions of the hardening that already landed.
4. **[M-Z1](#-m-z1--unified-circuit-prover-has-no-rust-pre-checks)** — port unified-witness pre-check. Frees the WASM
   semaphore from being a DoS lever.
5. The roadmap items (M-A1, M-A2, M-A3), Low-severity items, and L-Z1
   test addition can land opportunistically.
