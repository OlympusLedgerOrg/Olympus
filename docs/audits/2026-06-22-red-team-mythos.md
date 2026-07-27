# Olympus — Mythos-Class Adversarial Security Audit

**Date:** 2026-06-22 · **Target:** Olympus verifiable ledger (v0.10.0, Tauri 2 desktop) · **Branch:** `claude/amazing-shannon-14dd32`
**Method:** Two-wave multi-agent red-team (Trail-of-Bits-style): breadth sweep + deep soundness/forgery wave, each with adversarial verification and exploit construction.

---

## 1. Scope & methodology

Two independent multi-agent waves, ~310 subagent invocations, ~16M tokens of analysis (each wave's verification stage was rerun after a mid-run rate-limit; no work was lost — finder results were cached).

**Wave 1 — Breadth.** 26 offensive finder dimensions across the entire surface (crypto core, ZK layer, API/auth, untrusted-input parsers, infra, frontend, verifiers, supply chain) → adversarial skeptic verification of every finding against the real code & invariants → 3-lens pressure-test of every confirmed high/critical → synthesis report + completeness critic.
- 51 raw findings → **40 confirmed after verification** (36 after dedup) → **5 high/critical pressure-tested, all 5 survived**.

**Wave 2 — Depth (soundness & forgery).** 25 bedrock cells: signal-by-signal circuit constraint accounting, cross-implementation differential (Rust hot path vs both offline verifiers vs circuits), domain-separation matrix, field/encoding edges, concurrency/TOCTOU, witness completeness, and dedicated forgery cells that *build the exploit end-to-end*.
- 40 candidates → **12 confirmed** → **4 PoCs constructed** → **3 distinct soundness breaks after dedup**.

**Trust models graded.** Findings are weighed against (a) the primary single-operator `127.0.0.1` desktop (embedded Postgres + Axum bound to loopback), and (b) the **federated / court-evidence** model the project explicitly targets, where a forged proof/root/credential or a redaction downgrade is the highest-stakes class.

**Headline:** the cryptographic primitives and the authoritative Rust hot path are strong and fail-closed. **Every confirmed soundness break lives in the trust-minimizing boundary the project is built to deliver** — the offline/court verifiers and the ceremony trust anchor — not the localhost hot path. Risk posture: **solid-with-gaps.**

---

## 1a. Remediation status — P0 track (2026-06-22)

| ID | Fix | Status | Verification |
|---|---|---|---|
| **OLY-H3** | `treeSize=0` empty-root guard ported into `verifiers/rust` (new `empty_root.rs`, wired into the CLI `run_verify`); the JS verifier delegates Groth16 to this now-fixed CLI | ✅ Landed | `cargo test` green (51 tests, +6 new empty-root tests; the `treeSize=0` forgery now exits 1) |
| **OLY-M2** | `verify.js` BJJ verify now fails closed on `S≥l`, off-curve/off-subgroup/identity `R8` and pubkey, before the (malleability-tolerant) circomlibjs equation; false comment corrected | ✅ Landed | `npm test` green; new `S→S+l` malleation test rejects; BJJ parity (32 vectors) + all suites pass |
| **OLY-L03** | In-process Groth16 verifier (`zk/verify.rs::verify_proof`) now enforces the GRV-1 public-signal arity gate, matching the court verifier | ✅ Landed | `cargo check -p olympus-desktop` clean; confirmed compatible with `run_full_battery` / soundness test assertions |
| **OLY-H2** | `/zk/verify` `non_existence` arm fails closed (`501`, "not an authenticated absence claim") — stop-gap pending the anchored redesign | ✅ Landed (stop-gap) | `cargo check` clean; crypto-layer round-trip tests unaffected (only the HTTP arm changed) |
| **OLY-L16** | Offline V3 redaction verifier bounds check uses `checked_add` + `get` (was overflow-pronе `off+len`) | ✅ Landed | `cargo test` green (redaction suite + JS redaction 22 checks) |
| **OLY-H1** | Fold `blake3(vkey‖r1cs‖wasm)` into the BJJ-signed ceremony chain (`generate_manifest.rs` + `manifest.rs` in lockstep) + runtime vkey re-hash | ⏳ **Blocked on artifact regen** | Code change is atomic with a manifest regeneration via the docker `zk-setup` path (Windows host can't run `setup_circuits.sh`); landing the chain change without regenerating the 2 committed manifests would fail their coordinator-sig check at startup. Sequenced as the next step. |

**Net:** 5 of 6 P0 fixes landed and verified on this host. OLY-H1 (the highest-leverage single finding) is code-ready but must be applied *atomically with* a ceremony-manifest regeneration (`proofs/setup_circuits.sh` / `generate_manifest`, run in the Linux/docker `zk-setup` container per `docs`/the repo's ZK-artifact workflow), so it is staged rather than half-applied.

---

## 2. Severity summary

| ID | Sev | Finding | Surface |
|---|---|---|---|
| **OLY-H1** | **High** | Ceremony coordinator signature binds only the contribution chain, **not** the `ark_zkey`/`vkey` artifact hashes it is documented to protect — a swapped proving **or** verifying key + one edited manifest hex field passes all integrity checks | Ceremony trust anchor (federation) |
| **OLY-H2** | **High** | `non_existence` proofs are **unanchorable by construction**: the circuit commits a Poseidon/leaf=0 SMT structurally disjoint from the signed BLAKE3 ledger, so absence is forgeable for *any* key against a self-chosen root | ZK ↔ ledger binding (court-evidence) |
| **OLY-H3** | **High** | Independent court verifiers (Rust CLI + JS) omit the `treeSize=0` empty-root invariant the server enforces — accept a `document_existence` proof against an attacker-chosen root | Offline/court verifier |
| **OLY-H4** | **High** | Patched `ppv-lite86` generic `u64x4` lane shuffles are swapped vs upstream — corrupts BLAKE-512 and thus **all Baby Jubjub key/signature derivation on aarch64** (Apple Silicon / ARM) | Supply chain / platform correctness |
| **OLY-H5** | **High** | Federation equivocation detection is trivially bypassed by varying the attacker-controlled `checkpoint_timestamp` | Federation |
| OLY-M1 | Med | Two definitions of "admin" (role+scope gate vs scope-only gates) — a `role=user` key holding the `admin` scope reaches the scope-only admin surface (full credential-table disclosure) | Auth |
| OLY-M2 | Med | JS court verifier omits the BJJ-EdDSA `S<l` / R8 subgroup malleability checks the Rust path enforces | Offline verifier |
| OLY-M3 | Med | Anchor HTTP client follows redirects, bypassing the `validate_anchor_url` HTTPS/loopback SSRF & MITM guard | Anchoring (SSRF) |
| OLY-M4 | Med | Keychain-persisted admin API key is readable by any in-realm JS via the unrestricted `keychain_get` IPC | Frontend / IPC |
| OLY-M5 | Med | `federation_quorum` circuit double-counts a padding-repeated signer — one signature can satisfy an inflated M-of-N threshold | ZK circuit (gated) |
| OLY-M6 | Med | Modern-PDF ObjStm decompression has no cumulative budget — accumulated 64-MiB inflations OOM the operator process | Untrusted parser (DoS) |
| OLY-L01 | Low | RFC 3161 receipt stored `tst_info_verified:true` though the CMS signature over the token is never verified | Anchoring |
| OLY-L02 | Low | DB-tier quorum credential silently downgradeable to single-issuer by nulling `quorum_threshold`, still verifies | Credentials |
| OLY-L03 | Low | In-process Groth16 verifier performs no public-signal arity check (diverges from court verifier's GRV-1 gate) | ZK verify |
| OLY-L04 | Low | Identity-squatting denial-of-ingest: pre-bind a victim's content-hash `record_id` in the shared unowned `files` shard → 409 the victim's later commit | Ingest |
| OLY-L05 | Low | Registration/login rate-limit 15× weaker than documented (30/min vs 2/min), no per-account lockout | Auth |
| OLY-L06 | Low | `canonical_details_bytes` fails **open**: on canonicalization error it signs/commits the non-canonical raw serde bytes | Credentials |
| OLY-L07 | Low | OOXML segmenter parses + sorts an unbounded central-directory entry count before the segment cap applies (zip amplification) | Untrusted parser |
| OLY-L08 | Low | Unbounded `peer_checkpoints` growth: one valid proof yields unlimited rows via re-signed distinct timestamps | Federation |
| OLY-L09 | Low | `OLYMPUS_DEV_SIGNING_KEY` honored in production with top precedence | Config (fail-open) |
| OLY-L10 | Low | Unset `OLYMPUS_ENV` runs every startup security gate in permissive dev mode (fail-open default) | Config (fail-open) |
| OLY-L11 | Low | `non_existence` verify root never bound to a trusted/anchored root (surface view of OLY-H2) | ZK verify |
| OLY-L12 | Low | `federation_quorum` pinned pubkeys never on-curve / prime-subgroup checked (reconstruction or in-circuit) | ZK circuit (gated) |
| OLY-L13 | Low | BJJ authority key silently persisted to / reloaded from the OS keychain in production (contradicts env-only model) | Secrets |
| OLY-L14 | Low | API client interpolates caller path params into URLs without `encodeURIComponent` (path-injection, defense-in-depth) | Frontend |
| OLY-L15 | Low | Checkpoint-quorum message construction diverges Rust-vs-JS on a non-canonical pinned signer (silent-drop vs hard-abort) | Verifier conformance |
| OLY-L16 | Low | Offline V3 redaction verifier panics on attacker-controlled offset/length (integer-overflow bypasses the bounds check) | Offline verifier (DoS) |
| OLY-L17 | Low | Detected equivocation does not quarantine conflicting checkpoints — both persist `verified=true` | Federation |
| OLY-I01 | Info | Recovery endpoint: timing-oracle account enumeration + unbounded/uncapped recovery tokens + no per-account lockout | Auth |
| OLY-I02 | Info | `verify.js` `BigInt(decimal)` accepts non-canonical field elements (≥ q) the Rust `parse_fr` choke points reject | Verifier conformance |
| OLY-I03 | Info | `logical_objects` re-parses the entire xref stream twice per redaction (decompression amplification) | Untrusted parser |
| OLY-I04 | Info | Variable-depth redaction fold: a redacted all-zero leaf is indistinguishable from an `Fr(0)` padding leaf (root second-preimage across N) | Redaction crypto |
| OLY-I05 | Info | `pdf-xref-stream` revealed-leaf binding ignores framing whitespace (`content_scalar` over `trim_body` non-injective in whitespace) | Redaction crypto |
| OLY-I06 | Info | `treeSize` public input to the unified circuit is not range-checked (`leafIndex<treeSize` bound semantically prover-chosen) | ZK circuit (gated) |
| OLY-I07 | Info | Stale Poseidon domain-table docstrings contradict the live NODE=2 split (latent regression hazard) | Docs/code drift |

**Counts:** 5 High · 6 Medium · 17 Low · 7 Info.

> Note on cross-wave dedup: OLY-H1 consolidates Wave-1 OLY-002 + OLY-003 (and Wave-2 OLY-D-002). OLY-H2 is the depth wave's structural elevation (Wave-2 OLY-D-001) of what the breadth wave saw only as a Low (OLY-L11 / Wave-1 OLY-023) — a concrete demonstration of why the deep wave was worth running. OLY-H3 == Wave-2 OLY-D-003 (the depth wave rated it Medium, the breadth wave High; the disagreement is over whether the forged root is independently anchored — see §3).

---

## 3. High-severity findings (detail)

### OLY-H1 — The ceremony signature doesn't bind the keys it's the trust anchor for
**`src-tauri/src/zk/manifest.rs:249-328`, `src-tauri/src/bin/generate_manifest.rs:218-230`, `src-tauri/src/startup.rs:329-339`, `src-tauri/build.rs:181-194`**

The coordinator BJJ-EdDSA signature is verified over a chain hash whose **sole input is `blake3(ark_zkey)`**. The `artifacts.{vkey,r1cs,wasm}.blake3` fields are recorded as **unsigned JSON**. At runtime only the `ark_zkey` is re-hashed; the `vkey` actually used by `/zk/verify` is the compile-time `include_str!` constant whose only manifest tie is `build.rs`'s compile-time blake3 equality over two attacker-writable files. So the three documented checks authenticate the *proving* key to the ceremony but leave the *verification* key — the one thing the verifier trusts — authenticated only at the build machine.

**PoC (no coordinator key needed; build/CI/supply-chain write access):** generate a backdoored `(vk', pk')`; leave the legit `ark.zkey`, `contributions[]`, and `coordinator.signature` byte-for-byte intact; overwrite `…_vkey.json` with `vk'`; edit the single field `manifest.artifacts.vkey.blake3 = blake3(LF(vk'))`. `build.rs` self-consistency passes; coordinator signature passes (chain folds only `blake3(legit ark.zkey)`); runtime re-hashes only the unchanged `ark.zkey`. **All green.** `/zk/verify` now uses `vk'` and accepts forged inclusion proofs. This directly defeats `CEREMONY_INTEGRITY.md`'s "post-ceremony backdoored-key swap" guarantee. Moot for single-operator (operator == coordinator); real for federation where the coordinator is a separate party.

**Fix:** fold `blake3(vkey‖r1cs‖wasm)` into the signed chain under a bumped tag (`OLY:CEREMONY:CHAIN:V2`); mirror in `verify_contribution_chain`; regenerate all manifests in the same commit. Add a runtime re-hash of the embedded vkey against the signed manifest field after the signature verifies (the `ArtifactKind::Vkey` arm currently exists only in tests). Adversarial test: edit each manifest hash field → assert startup `exit(2)`.

### OLY-H2 — `non_existence` proves nothing about the ledger (universal absence forgery)
**`proofs/circuits/non_existence.circom:109-115`, `proofs/circuits/lib/merkleProof.circom:10-24`, `src-tauri/src/api/zk/mod.rs:108-116`, vs `crates/olympus-crypto/src/smt.rs:135,266-268,484-488`**

The circuit proves leaf-0 absence in a **Poseidon, empty-sentinel = field 0, depth-256** SMT. The ledger's only key-keyed depth-256 SMT is **BLAKE3 with a domain-separated non-zero empty sentinel** (`empty_leaf()`, explicitly "never all-zeros"); its BLAKE3 root is what gets signed/anchored/checkpointed. A Poseidon field element can never equal that BLAKE3 root, and **nothing in the codebase ever computes, signs, or anchors a Poseidon key-keyed SMT root.** So the proof's public `root` corresponds to no authenticated state, and the verify arm runs only the pairing check — no `enforce_empty_tree_invariant` (contrast the existence arm at `:97`) and no root binding. It is unanchorable *by construction*: even a verifier that wanted to pin `signals[0]` has nothing authenticated to pin to.

**PoC (offline, no credentials):** pick any key K; fold 256 zero siblings over leaf 0 → `R*`; generate the proof with the public `non_existence.ark.zkey`; `POST /zk/verify {circuit:'non_existence', …, publicSignals:[R*, keyHash]}` → `{valid:true}`. The UI (`useAuditProof.ts:9`) renders "key K is **NOT** in root R" with the anchored cross-check gated to `document_existence` only (`:222`). `/zk/verify` is also on the federation `public_router`. Result: a downloadable, shareable "proof of non-existence" for **any** key — including keys that *are* committed.

**Fix (preferred — retire the ZK path):** you already have a sound, ledger-bound primitive — `olympus_crypto::smt::verify_nonexistence_proof(proof, Some(&expected_root))` against the signed BLAKE3 root (`smt/tree.rs:576`). Remove the `non_existence` arms from `api/zk/mod.rs` (verify + prove) and the UI branch; surface non-membership only through a new anchored endpoint that loads the stored snapshot/checkpoint root and verifies its BJJ trusted-issuer signature (mirror `proof_verify.rs:336`). A verify-side check alone cannot fix this. *(Stop-gap until then: make the verify arm fail closed with an "unanchored — not an authenticated absence claim" detail and remove the green verdict in the UI.)*

### OLY-H3 — Court verifiers accept what the server rejects (treeSize=0)
**`verifiers/rust/src/bin/verify.rs:142-167`, `verifiers/javascript/verify.js:271-290`, vs `src-tauri/src/api/zk/mod.rs:97` + `src-tauri/src/zk/verify.rs:176-199`; circuit `proofs/circuits/document_existence.circom:80-101`**

`document_existence` disables its `leafIndex<treeSize` bounds check when `treeSize==0`, and the circuit docstring declares it an **off-chain verifier responsibility** to reject `treeSize=0` unless `root` equals the empty-tree root. The server enforces this (`enforce_empty_tree_invariant`). The **independent Rust CLI verifier — the one `docs/court-evidence.md:174-179` tells a court to run — is a bare pairing check** with no treeSize logic, and the JS verifier delegates Groth16 to that same CLI.

**PoC:** build a private depth-20 tree with your chosen leaf → arbitrary root `R` unrelated to the real ledger; produce an honest proof for `[R, leafIndex, treeSize=0]` (bounds gate vacuous); hand the bundle to opposing counsel with the documented command → "OK: Groth16 proof accepted." The same artifact is rejected by production `/zk/verify`. The *more permissive* verifier is the court's trust root.

> Severity note: the depth wave rated this **Medium** (Groth16 still binds a real path to the supplied `R`, so the forgeable claim is the `treeSize`/position *context*, not membership of a document the prover lacks). The breadth wave rated it **High** (a court has no way to tell `R` from a real anchored root). Net: **High if courts are pointed at the CLI without independently anchoring the root; Medium otherwise.** Fix removes the ambiguity.

**Fix:** port `enforce_empty_tree_invariant` into `verifiers/rust` (and implement it in the JS verifier rather than only printing the cargo invocation): for `document_existence`/`unified`, if `treeSize==0` reject unless `root` equals the published depth-20 empty-tree root (a constant the offline tool ships, pinned by a test against `zk::poseidon::empty_doc_existence_root()`). Add a cross-impl REJECT vector both verifiers must fail.

### OLY-H4 — Patched `ppv-lite86` corrupts BJJ crypto on ARM / Apple Silicon
**`crates/ppv-lite86-patched/src/generic.rs:762-770` (`impl Words4 for u64x4_generic`)**

The patched generic `u64x4` lane-shuffle implementations are swapped relative to upstream. On `aarch64` (no x86 SIMD path), this corrupts BLAKE-512 output, which feeds Baby Jubjub key and signature derivation — i.e. **deterministically wrong BJJ keys/signatures on every ARM build** (Apple Silicon macOS, ARM Linux). This is a correctness break on a shipping target (the project ships Windows + Linux + macOS).

**Fix:** correct the lane shuffles to match upstream `ppv-lite86`. **Add a host-agnostic crypto correctness test (BJJ sign/verify known-answer vector) to the *required* CI on an ARM runner** — not a non-blocking macOS job. Until verified, treat ARM builds as unsound for any signing.

> Recommend empirical reproduction on actual ARM hardware before shipping the fix — this is the one finding whose impact is best confirmed with a known-answer test on-device.

### OLY-H5 — Federation equivocation detection is a no-op
**`src-tauri/src/federation/equivocation.rs:21-34`, `src-tauri/src/federation/verify.rs:138-141`**

Equivocation is keyed on a tuple that includes the attacker-controlled `checkpoint_timestamp`. A malicious peer signs two conflicting checkpoints for the same height with **different timestamps** → they hash to different keys → the detector never fires; both persist `verified=true` (see also OLY-L17: no quarantine even when detected, and OLY-L08: this also enables unbounded `peer_checkpoints` growth). The signature/proof bind `(root, treeSize)` but **not** the timestamp — the classic "the signed thing isn't the thing that matters" gap.

**Fix:** key equivocation detection on `(peer, height/root-domain)` excluding the timestamp; bind `checkpoint_timestamp` into the signed message *and* the dedup key so a peer cannot mint distinct rows for one logical checkpoint; quarantine (don't just log) on conflict.

---

## 4. Fragility map — guards holding the line by a single thread

These are *not* breaks today — each is one architectural decision away from one. Convert each to an explicit invariant + test.

- **In-circuit canonicalization is vacuous.** The unified circuit's `canonicalHash` is a free Poseidon chain over opaque witnesses (`sectionHashes[i]===Poseidon(documentSections[i])`); the JCS byte-binding lives entirely *outside* the circuit. Held only because **no consumer treats `canonicalHash` as proof of canonicalization.** If one ever does → forgery.
- **`federation_quorum` threshold has no in-circuit range constraint** (`GreaterEqThan(8)` soundness assumed on a trusted input). Held only because `threshold` always comes from server-pinned config. (See OLY-M5/OLY-L12.)
- **JS vs Rust canonicalizer diverge on numbers** beyond IEEE-754 round-trip. Held only because **JS is verify-only, never mints a commitment** (`canonicalJsonEncode` is marked non-authoritative and has no caller on a JS verification path).
- **No public-input arity validation in `/zk/verify`** — ark-groth16 0.6 `prepare_inputs` silently zip-truncates surplus signals and accepts short vectors. Held by vkey IC-length integrity (which OLY-H1 attacks from another angle). (See OLY-L03.)
- **Single-issuer checkpoint signs an un-domain-tagged `hash2(ledger_root, timestamp)`** under the shared BJJ key — the thinnest margin in the domain-separation matrix. No break today; **add an `OLY:CHECKPOINT` tag proactively.**

**Domain-separation verdict:** signing-*role* tags (`SBT:QUORUM:V2` / `SBT:REVOKE:V1` / `SNAPSHOT:PERSIST:V1` / `SBT:V1` vs `SBT:COMMIT:V1`) are correctly disjoint and enforced; the NODE=2 Poseidon split is live and consistent. The real defect class is **hash-family / tree confusion** (OLY-H2), not tag collision.

---

## 5. Systemic root causes

Five cross-cutting themes explain almost every finding:

1. **Independent-verifier parity drift (dominant).** The offline/court verifiers have quietly diverged from the hardened server: treeSize (OLY-H3), BJJ malleability (OLY-M2), field canonicality (OLY-I02), Groth16 arity (OLY-L03), checkpoint-quorum non-canonical-signer handling (OLY-L15), redaction bounds panic (OLY-L16). The *entire value* of shipping independent verifiers is trust-minimized evidence; a verifier weaker than the server it cross-checks degrades the guarantee to "whatever the bundle author typed." **Root fix: a shared, language-neutral conformance contract that pins REJECT cases (not just ACCEPT), porting every server fail-closed check into both verifiers behind common vectors.**
2. **Signature / binding scope gaps — "the signed thing isn't the thing that matters."** Ceremony sig doesn't cover artifact hashes (OLY-H1); federation sig/proof omit `checkpoint_timestamp` (OLY-H5, OLY-L08); `commit_id` doesn't bind `quorum_threshold` (OLY-L02); quorum circuit doesn't bind signer distinctness (OLY-M5/OLY-L12). **Every trust-anchoring signature must cover every field a relying party will later trust.**
3. **Split policy definitions.** Two definitions of "admin" (role+scope vs scope-only) leave the M-1-hardened disclosure surface reachable by a `role=user` key (OLY-M1, OLY-L11-class). One canonical predicate everywhere.
4. **Fail-open defaults on security-critical config.** Production is opt-in: unset `OLYMPUS_ENV` runs gates permissively (OLY-L10), dev signing key wins in prod (OLY-L09), BJJ key silently lands in keychain (OLY-L13), canonicalizer falls back to raw bytes on error (OLY-L06), rate limit 15× loose (OLY-L05). **Safe-by-default: treat anything but explicit dev as production; fail closed on canonicalization/secret errors.**
5. **Untrusted-parser budgets are per-unit, not cumulative.** ObjStm has no cumulative inflation budget (OLY-M6, OOM); OOXML applies its cap after parse/sort (OLY-L07); redaction double-decompresses (OLY-I03). **One shared per-document budget (bytes AND entry count) threaded through every segmenter, enforced as admission control during parse.**

---

## 6. What held (verified defenses)

The audit's adversarial pressure refuted many plausible attacks — these are real, working defenses:

- **Write-once + shard gate** held: same-content re-ingest is `is_new=FALSE` (dedup `ON CONFLICT DO NOTHING`), so the value-hash guard is never driven into overwrite; different content → correct 409. The durable-signed-row-behind-409 window is closed by fail-closed pre-checks inside the per-shard advisory lock.
- **Domain-separated commit IDs** are real and enforced (disjoint `OLY:SBT:V1` vs `OLY:SBT:COMMIT:V1` with a non-collision unit test); the Pedersen-SBT scope resolver fails **closed** (zero scopes) on domain mismatch; quorum co-sigs are V2-tagged disjoint from issue/revoke.
- **Trust-anchor secret protection:** the BJJ authority key is guarded where the API key isn't (`guard_keychain_key` blocks the IPC read path; keychain/DB-dev adoption tiers fail closed on pubkey mismatch, defeating key-poisoning/self-healing-clobber takeover). `load_proving_key_with_manifest`'s `blake3(.ark.zkey)==manifest` check runs in **both** dev and prod.
- **Conformance negative-case coverage** is better than feared: both verifiers carry CI-run hand-authored REJECT blocks (tampered/empty shard_id, 255-sibling truncation, tampered model_hash, wrong-message/wrong-blinding Pedersen).
- **H-7 trusted-issuer SBT check, H-2 empty-tree invariant (server/federation), M-6 client_ip loopback collapse, and the placeholder-prefix check** all behaved as designed.

---

## 7. Coverage gaps & residual risk (audit-the-audit)

This audit was structured around static crypto/protocol correctness and **systematically under-weights runtime/operational surface**. Estimated coverage: ~80-85% of the cryptographic/protocol attack surface, ~40-50% of the runtime/operational surface. **Largest blind spots (next engagement targets):**

- **Tauri IPC command surface** (`src-tauri/src/commands.rs`): only `keychain_get` was examined. `save_text_to_disk` / `open_file_dialog` (arbitrary OS paths, no traversal/symlink review) and `commit_file` (forwards renderer-supplied `api_key`/`shard_id`/`record_id`) are unreviewed; capability scoping in `capabilities/default.json` is minimal.
- **Error-body info-leak:** `/health` reflects raw `state.db_error` (can contain `DATABASE_URL`, embedded-PG paths, migration internals) verbatim — and `/health` is mounted on the **Tor-facing router** (`server/mod.rs:256`), so it's exposed to onion clients.
- **Async cancellation / pool exhaustion:** `update_batch` holds `pg_advisory_lock` across multiple `.await`s; client disconnect / 60s timeout dropping the future → best-effort unlock + soft-retry, never adversarially tested for a torn batch / inconsistent canopy. Every concurrent SMT writer `detach`es its `PgConnection` (never returns to the pool) — sustained ingest can drain the pool and deadlock unrelated reads.
- **Background-task lifecycle:** 148 `tokio::spawn` sites (anchor cron, gossip, advisory-unlock) — accumulation/leak/panic-swallowing/graceful-shutdown unaudited.
- **Key-rotation & backup/restore:** behavior of historical signed roots / manifests / trusted-issuer set across rotation; keychain-vs-DB independent restore mismatch; migration idempotency on restore — entirely uncovered.
- **Log injection / secret redaction in `tracing`; JS dependency CVE gating** (CI runs `cargo deny` but **no `pnpm audit`** for `app/public-ui`, which handles secrets); replay/clock-skew across recovery-token/anchor-freshness/SBT-validity windows.

---

## 8. Prioritized remediation plan

**P0 — ceremony & verifier trust roots (highest leverage):**
1. **OLY-H1** — fold `vkey`/`r1cs`/`wasm` hashes into the signed chain + runtime re-hash the embedded vkey. (One attacker who edits a manifest currently defeats *both* the zkey-swap defense and vkey authentication.)
2. **OLY-H3 + OLY-M2 + OLY-L03 + OLY-L16 + OLY-I02** — one **cross-verifier conformance workstream**: drive Rust-in-process, Rust-CLI, and JS from a shared negative/forgery vector corpus (`verifiers/test_vectors/vectors.json`); port `enforce_empty_tree_invariant`, `validate_signature_s/r8/pubkey_subgroup`, `parse_fr` canonicality, and arity into both verifiers; fix the redaction integer-overflow panic with `checked_add`.

**P0 — soundness:**
3. **OLY-H2** — retire the Groth16 `non_existence` path in favor of the BLAKE3 anchored primitive; fail the verify arm closed and remove the green UI verdict in the interim.

**P1 — platform & federation:**
4. **OLY-H4** — fix `ppv-lite86` lane shuffles + add ARM known-answer crypto test to *required* CI.
5. **OLY-H5** (+ OLY-L08, OLY-L17) — bind `checkpoint_timestamp` into the signature & dedup key; quarantine on equivocation; cap `peer_checkpoints`.
6. **OLY-M1** (+ admin-scope SBT) — collapse to a single canonical admin gate; regression-test that `role=user` + `admin` scope is rejected on every admin route.

**P1 — hardening:**
7. **OLY-M3** (no-redirect anchor client), **OLY-M4** (move API key out of renderer-readable keychain / add in-process challenge), **OLY-M6 + OLY-L07 + OLY-I03** (shared per-document parser budget).

**P2 — config & circuit gating:**
8. Fail-safe defaults (OLY-L05/L06/L09/L10/L13); keep `quorum-circuit` gated until OLY-M5/OLY-L12 are fixed (in-circuit signer distinctness + on-curve/subgroup checks); fix the info-class circuit/docs drift (OLY-I06/I07).

**Next engagement:** a runtime/operational wave targeting the §7 blind spots — Tauri IPC, `/health` info-leak on the Tor router, async-cancellation/pool-exhaustion, background-task lifecycle, key-rotation/restore, and JS dependency CVEs.
