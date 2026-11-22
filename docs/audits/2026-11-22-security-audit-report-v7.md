# Olympus Security Audit Report — V7 (Pre-Launch, Read-Only)

**Audited commit:** `8e87af0f9ef94fe5078d7f848d2675637c33cb1f` (`origin/main`, 2026-11-01, "chore(deps-dev): bump eslint-plugin-react-refresh … (#1664)")
**Audit date:** 2026-11-22
**Scope:** read-only audit of the tree at the commit above. No code was modified.
**Evidence grade:** static reading of the committed tree (no `cargo build`, `cargo test`, coverage run, `cargo audit`, or network calls).

## Header facts

| Item                        | Value                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Audited SHA                 | `8e87af0f9ef94fe5078d7f848d2675637c33cb1f`                                                                                                                                                                                                                                                                                                                                                                                              |
| `origin/main` at audit time | same SHA (verified with `git fetch origin && git rev-parse origin/main`)                                                                                                                                                                                                                                                                                                                                                                |
| Working tree state          | **dirty** — 15 tracked files modified, 2 untracked (`context.json`, `docs/proof-bundle-v1.md`). Findings cite the committed (`HEAD`) content; the three security-relevant dirty files (`api/ingest/mod.rs`, `api/ingest/read.rs`, `db/embedded.rs`) were re-checked against `git show HEAD:`                                                                                                                                            |
| wiserepo                    | In-repo MCP server exists (`tools/wiserepo/src/mcp-server.mjs`). It was **not exposed as callable MCP tools** in this session, and the model-backed `repo_qa`/`review_diff` paths need a local Ollama. Its deterministic modules were executed directly: `checkInvariants()` and `getCircuitStatus()` (`tools/wiserepo/src/olympus.mjs`). No structural-drift or blast-radius tool exists in it — see [Coverage gaps](#5-coverage-gaps) |
| Findings                    | **1 P0 · 0 P1 · 9 P2 · 3 P3**                                                                                                                                                                                                                                                                                                                                                                                                           |

### Four premises in the brief that the code falsifies

These are not findings against the repo; they are corrections to the audit brief, and they change what can be concluded.

1. **There is no `federation.py`.** Python is retired (v0.9.0). The only Python left is the verify-only SDK `clients/python/`. Federation is ten Rust modules under `src-tauri/src/federation/` (`api`, `checkpoint`, `checkpoint_cosign`, `cosign`, `equivocation`, `gossip`, `peer`, `tor`, `verify`, `mod`).
2. **There is no `OLYMPUS_REQUIRE_RUST`** anywhere in the tree (grep over `*.rs`, `*.md`, `*.yml`, `*.toml`). The retired-language boundary is enforced socially and by `deny.toml`, not by a runtime flag.
3. **There is no RocksDB and no `_load_tree_state`.** The SMT backends are PostgreSQL, SQLite, and in-memory under `NodeBackend` (ADR-0039). **ADR-0033 is checkpoint quorum co-signatures**, not SMT-over-RocksDB.
4. **There is no Plonky3 and no ML-DSA implementation.** ADR-0032 is "retire witness-over-root cosignature". `MlDsa65` exists only as an enum variant and descriptor; verification returns `UnsupportedAlgorithm` (see [A-P2-1](#a-p2-1--the-hybrid-suite-label-is-not-covered-by-the-signed-digest-latent-downgrade)).

Also: the workflow names in the brief do not all exist. The scope gate is `pr-scope-drift.yml` (not `scope-drift.yml`); there is no `repowise-risk-gate.yml`, `ai-pr-review.yml`, `pre-merge-checks.yml`, or `trufflehog.yml`. Secrets scanning lives in `ci.yml` (gitleaks/trufflehog). Coverage is **measurement-only with an 85% long-term goal**, not a 90% gate. **E2E against real PostgreSQL does run in CI** (`e2e_http` plus six other binaries via `scripts/embedded-postgres-tests.sh`, invoked at `.github/workflows/ci.yml:1815-1830`).

---

## 0. Post-audit remediation status (2026-11-22)

This section was added after the read-only pass above. The findings and counts
are left as recorded; this table is the current status of the code. Changes are
in the working tree (not committed) and were checked with the commands in the
last column.

| Finding                                                                     | Status                    | What changed                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Verification                                                                                                                                         |
| --------------------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **P0-1** — gate executes PR-controlled code                                 | **FIXED**                 | `scripts/check-gate-integrity.mjs` fails a diff that touches the gate's own files unless the `gate-change-approved` label is present. `pr-scope-drift.yml` now runs that checker **and** `check-pr-scope.mjs` from `git show "$BASE_SHA:…"`, so the PR's copy is never the one that decides.                                                                                                                                                                   | `node --test scripts/check-gate-integrity.test.mjs` — 6 pass, including "editing the scope checker without the label fails" and a base-copy CLI path |
| **A-P2-1** — suite label outside the signed digest                          | **FIXED**                 | Envelope bumped to `SignatureEnvelopeV3` (`olympus-signature-envelope/v3`, `OLY:SIGNATURE-ENVELOPE:V3`). The message now binds `lp(suite_wire_name)` and the suite descriptor's canonical algorithm list. Any relabel, leg addition, or leg removal invalidates Ed25519. Tests: `relabelling_a_hybrid_envelope_as_classical_breaks_the_signature`, `adding_a_leg_after_signing_breaks_the_signature`, plus a pinned v3 digest. ADR-0035 updated.               | `cargo test -p olympus-crypto --features signature-envelope signature_envelope` — 12 pass                                                            |
| **C-P2-1** — no fuzz targets for high-risk parsers                          | **PARTIAL**               | Added `fuzz/fuzz_targets/fuzz_signature_envelope.rs` (JSON → `SignatureEnvelopeV3` → both verification modes) and wired it into `fuzz/Cargo.toml`. `segment_document` / `pdf_objects` targets are **not** added: those live in `src-tauri` behind `pub(crate)` and the fuzz crate depends only on `olympus-crypto`, so they need a deliberate API/dep change.                                                                                                  | `cargo check --manifest-path fuzz/Cargo.toml --bins` — pass                                                                                          |
| **D-P2-1** — quorum threshold fails open; quorum not enforced at acceptance | **PARTIAL**               | Fixed the fail-open: `checkpoint_quorum_threshold_config_error()` and an unconditional `run_preflight_checks` gate now refuse startup on an explicitly-set empty, non-integer, zero, or negative value. The acceptance-path enforcement (`verify_checkpoint_quorum(...).satisfied` wired into bundle acceptance with a `2 ≤ M ≤ N` minimum) is **not** done: it needs a bundle/API schema and policy decision, and the quorum block remains evidence metadata. | `cargo test -p olympus-desktop --lib checkpoint_threshold_env_validation` — 1 pass                                                                   |
| **E-P2-1** — arbitrary renderer-supplied path reads                         | **FIXED**                 | `commands/approved_paths.rs` is a bounded session allowlist populated only by native dialog callbacks and the OS `DragDrop` event; there is no approve command. `hash_file_for_manifest`, `read_file_for_render`, `describe_by_path`, and `redact_by_path` canonicalise and require membership. Symlink/`..` aliases resolve to the same canonical entry; the allowlist evicts oldest-first at 256.                                                            | `cargo test -p olympus-desktop --bins approved_paths` — 3 pass; `cargo check -p olympus-desktop` — pass                                              |
| **G-P2-1** — coverage measurement-only                                      | **STILL OPEN**            | No coverage number was measured and no ratchet was added; setting a gate without a `cargo llvm-cov` run would be a guess.                                                                                                                                                                                                                                                                                                                                      | —                                                                                                                                                    |
| **G-P2-2** — hardcoded embedded port / cold-cache download                  | **PARTIAL**               | Added `OLYMPUS_PG_PORT` (default 5433, invalid/zero warns and falls back) and documented it in `AGENTS.md`. The offline cold-cache download is unchanged and still needs a bundled-binary or pre-seeded-cache decision.                                                                                                                                                                                                                                        | `cargo check -p olympus-desktop` — pass                                                                                                              |
| **G-P2-3** — placeholder circuit artifacts                                  | **STILL OPEN**            | Requires the production ceremony; the production gate already refuses placeholders.                                                                                                                                                                                                                                                                                                                                                                            | —                                                                                                                                                    |
| **F-P2-1** — advisory baseline revalidation                                 | **PARTIAL**               | Added a dated 2026-11-22 static revalidation note to `cargo-audit-baseline.txt`, including the unchanged reachability of RUSTSEC-2023-0071. `cargo audit` was not run here.                                                                                                                                                                                                                                                                                    | —                                                                                                                                                    |
| **F-P3** — forked `tauri`/`tao`/`wry` diff                                  | **STILL OPEN (external)** | Requires cloning `OlympusLedgerOrg/tauri` at `1afd9bd8…`, which is outside this workspace.                                                                                                                                                                                                                                                                                                                                                                     | —                                                                                                                                                    |
| **A-P2-2** — no shipped ML-DSA control                                      | **STILL OPEN**            | Unchanged by design: `HybridRequired` still fails closed with `UnsupportedAlgorithm(MlDsa65)`. The v3 binding makes the label honest; it does not implement PQ verification.                                                                                                                                                                                                                                                                                   | `cargo test -p olympus-crypto …` includes the fail-closed test                                                                                       |

**Incidental test-harness fix.** The working tree's `src-tauri/src/api/ingest/mod.rs`
test helper `sample_row()` was missing the five optional columns added by the
in-progress ingest changes, so the desktop lib test target did not compile.
The helper's own comment says it is "all optional columns NULL", so the five
fields were added as `None`. This is not an audit finding; it was required to
run the tests above.

**Bin-target tests.** `commands/` is compiled into the `olympus-desktop` binary,
not `olympus_tauri_lib`, so `cargo test -p olympus-desktop --lib approved_paths`
matches 0 tests. The allowlist tests were run with
`cargo test -p olympus-desktop --bins approved_paths` — 3 passed
(`approves_only_paths_the_native_layer_recorded`,
`a_relative_or_dotdot_alias_resolves_to_the_approved_file`,
`the_allowlist_is_bounded_and_evicts_oldest_first`).

**Full-suite status at remediation time.** `cargo test -p olympus-desktop --no-fail-fast` had one non-`api_db` failure: the v3-envelope regression in `signed_request::tests` (the same test in `--lib` and `--bin olympus-desktop`), which was fixed and re-run green 11/11 in both targets. The `--test api_db` target reported three failures — `authority_rotation::rotate_authority_supersedes_append_only_and_windows_history`, `external_pg_roles::external_role_lifecycle_attests_real_sessions_and_tears_down_migrator`, and `external_pg_roles::external_role_upgrade_retains_populated_public_schema_ledger`. **The evidence proves these three are pre-existing at HEAD `8e87af0`, and nothing more:** with the entire working tree stashed, HEAD fails the same three tests at `authority_rotation.rs:30`, `external_pg_roles.rs:220`, and `external_pg_roles.rs:784`. That reproduction does not establish an environment cause; no environmental claim is made here.

**The `authority_rotation` failure was a real pre-existing code defect — fixed in this set.** On this host the OS keychain holds a `bjj_authority_key.olympus-desktop` entry, so `bootstrap::ensure_bjj_authority` takes the dev keychain tier. On a fresh database that tier called `persist_bjj_pubkey` (UPDATE-only, gated on `bjj_pubkey_x IS NULL`) and returned; with no row the call was a no-op, so no authority row was ever inserted and the test's `active_authority()` got `RowNotFound`. `ensure_authority_registry_row` now owns adoption for all three tiers (env, keychain, generated): it is idempotent, repairs a legacy active row with NULL `bjj_pubkey_x/y` in place, inserts the first row when none exists, and refuses an active row recording a different key. The generated-key path passes its dev-only `bjj_private_dev` secret through the same helper, so a repaired legacy row is stored exactly like a freshly inserted one. Regression tests `authority_rotation::bootstrap_registers_the_authority_key_it_adopts` and `authority_rotation::ensure_authority_registry_row_repairs_legacy_rows_and_is_idempotent` cover the fresh-database, legacy-repair, repeat-call (no-op), and mismatch-error shapes. Verified with the complete `cargo test -p olympus-desktop --no-default-features --test api_db -- --test-threads=1` target — 105 passed, 2 failed (102.57s), the failures being only the two known `external_pg_roles` tests. The two `external_pg_roles` failures still report the post-migration external catalog/privilege probe failing and were not root-caused beyond the HEAD reproduction; they remain open and outside this remediation set.

---

## 1. Launch blockers (P0 and P1)

### P0-1 — The scope-drift gate executes PR-controlled code, so a PR can neutralise the gate that judges it

**Severity:** P0 (the brief's P0 definition explicitly includes "a bypass of the scope-drift or security gates")
**Files:** `.github/workflows/pr-scope-drift.yml:92`, `scripts/check-pr-scope.mjs` (whole file)
**Confidence:** high on the mechanism; medium on practical impact (it still requires a merged PR — see the compensating control).

**Code path.** The workflow triggers on `pull_request` (`pr-scope-drift.yml:29`), which GitHub evaluates against the PR's merge ref — base plus head — so any workflow-file edit in the PR is the version that runs. Its enforcing step is:

```yaml
# .github/workflows/pr-scope-drift.yml:88-97
node scripts/check-pr-scope.mjs \
--body-file "$RUNNER_TEMP/pr-body.md" \
--changed-files-file "$RUNNER_TEMP/changed-files.txt" \
--labels-json "$PR_LABELS" \
--summary-file "$GITHUB_STEP_SUMMARY" \
--require-scope
```

`scripts/check-pr-scope.mjs` is resolved from the PR checkout, not from the base commit. The workflow's own header advertises `pull_request` as the _safe_ choice (correctly, to avoid `pull_request_target`'s write token), but that same choice is what makes the gate's logic PR-authored.

**Repro (not executed — it requires opening a PR, which this engagement forbids):**

```bash
# On a branch whose PR is meant to slip an undeclared change through:
cat > scripts/check-pr-scope.mjs <<'EOF'
process.exit(0); // neutralise the gate
EOF
# Also modify, say, crates/olympus-crypto/src/lib.rs with no "Scope:" block.
# The scope-drift job runs the branch's own checker and reports success.
```

The same trick works by editing `.github/workflows/pr-scope-drift.yml` to drop `--require-scope` or the step entirely, or by changing `if:` to `false`.

**Suggested fix.** Run the gate from pinned base content, not the checkout:

```yaml
- name: Pin the gate implementation to the base commit
  run: |
    git show "$BASE_SHA:scripts/check-pr-scope.mjs" > "$RUNNER_TEMP/gate.mjs"
    git show "$BASE_SHA:.github/workflows/pr-scope-drift.yml" > "$RUNNER_TEMP/base-workflow.yml"
    if ! git diff --quiet "$BASE_SHA...$HEAD_SHA" -- \
         .github/workflows/ .github/CODEOWNERS scripts/check-pr-scope.mjs; then
      echo "::error::PR modifies its own gate; requires gate-change-approved label"
      exit 1
    fi
- run: node "$RUNNER_TEMP/gate.mjs" ... --require-scope
```

and gate the `gate-change-approved` label on a CODEOWNER who is not the PR author. `/.github/` is in `CODEOWNERS:30`, so review is required today; that human review is the only thing preventing this, and the workflow itself neither asserts nor detects it.

**Boundary / why not P1:** the gate is bypassable, but not by an unauthenticated party, and branch protection plus CODEOWNERS still stand between the PR and `main`. If agent PRs are ever auto-merged, or if the check is not a required status check, this becomes directly exploitable. I could not read branch protection from the repository (see coverage gaps).

**Regression coverage:** none. Nothing tests that the gate is run from trusted content.

---

## 2. Status of the known items (ground rule 4)

All rows were checked against `HEAD`, not against the audit documents.

| Item                                                                             | Status                                             | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V5 CT-1/CT-2 — variable-time scalar multiplication in BJJ EdDSA                  | **FIXED**                                          | `crates/babyjubjub-permissive/src/eddsa.rs:193` (`PublicKey` derivation) and `:222` (`R8` in `sign`) both use `mul_scalar_ct`; the CT helper lives in `crates/babyjubjub-permissive/src/ct.rs`. `verify` still uses `mul_bigint` at `:310`, but only over public data (verification), so there is no secret-dependent timing path.                                                                                                                                                                                                                                              |
| V5 zeroize gaps in `AppState`                                                    | **FIXED**                                          | `src-tauri/src/state.rs:40` defines `SharedSecret32 = Arc<Zeroizing<[u8; 32]>>`; the three long-lived secrets use it (`:68` BJJ authority, `:103` ingest signing, `:116` redaction blind). `AppState` has `#[derive(Clone)]` only — no `Debug` derive — so it cannot be formatted into a log. No `tracing!`/`println!`/`dbg!` site formats key material (grep clean). Residual: `InitialSecretsSerde` deliberately serialises the API key and BJJ key to the renderer once (`commands/secrets.rs:40-62`), one-shot via `Option::take` (`:57-62`); that is by design, not a gap. |
| V5 A1-01 — last-admin lockout                                                    | **FIXED**                                          | Four paths now guarded: `update_key_scopes` (`api/admin_users.rs:333-385`), `revoke_key` (`:414-460`), `update_user_role` (`:502-531`), and both delete paths via `guard_last_admin_before_delete` (`api/user_auth/handlers.rs:485-535`, called at `:453` and `:582`). Each takes `FOR UPDATE` on the admin-user set and the effective-admin-key set inside the mutation transaction.                                                                                                                                                                                           |
| V5 A1-02 — modern-PDF decompression bomb                                         | **FIXED**                                          | V6 pass 2 records the fix in `ed782e44`: `MAX_INFLATE` is a document-wide `remaining: &mut usize` threaded through `logical_objects` → `parse_xref_stream` → `/Prev` → `decode_objstm`, with a 6 × 16 MiB regression test. Not re-read line-by-line this pass (medium confidence).                                                                                                                                                                                                                                                                                              |
| V5 A1-03 — federation equivocation TOCTOU                                        | **FIXED**                                          | `federation/verify.rs:251` takes `pg_advisory_xact_lock(hashtext(identity:scope:shard))` inside the single transaction opened at `:172` that runs detection (`:310`), auto-block (`:319`), and storage (`:331`). `federation/equivocation.rs:57-70` conflicts on `ledger_root != $5 AND (checkpoint_timestamp = $6 OR tree_size = $7)` — the timestamp-only keying is gone, and the `equivocation_detected = false` filter is gone (L-04 folded in).                                                                                                                            |
| V5 L-01 — anchoring raw DB error reflection                                      | **FIXED**                                          | `anchoring/api.rs:31-34` `db_err` returns a constant `"Database error."` and logs the raw error.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| V5 L-02 — anchoring redirect SSRF                                                | **FIXED**                                          | `anchoring/mod.rs:331` builds the shared client with `redirect(reqwest::redirect::Policy::none())`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| V5 L-03 — `add_peer` onion validation                                            | **FIXED**                                          | `federation/peer.rs:69-153` validates rend-spec-v3 (base32 length, 35-byte decode, SHA3 checksum, version byte 3).                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ADR-0030 SR-12 — `table_hash` does not fold in `recipient_id` (accepted)         | **Trade-off intact, assumption holds**             | Documented at `docs/adr/ADR-0030-redaction-signed-merkle-drop-groth16.md:693` and the digest description at `:157-158`. `recipient_id` **is** bound in the signed payload (`crates/olympus-crypto/src/redaction.rs:391`) and in the nullifier (`:410`), so a bundle cannot be replayed across recipients; the verifier test at `verifiers/rust/src/redaction.rs:2210-2217` pins that. Not flagged, per instruction.                                                                                                                                                             |
| Audit ID `M1` (→ OLY-M1, two definitions of "admin")                             | **FIXED**                                          | `api/middleware/auth.rs:534` and `:573-579` fold the role into `has_scope("admin")`: admin scope is only held when `user_role ∈ {admin, system}`. The regression test at `auth.rs:956-966` asserts a `role=user` key with `admin` in its scopes does **not** have admin scope and cannot re-mint it.                                                                                                                                                                                                                                                                            |
| Audit ID `M2` (→ OLY-M2, JS verifier BJJ malleability)                           | **FIXED**                                          | V6 records the fix and the `S→S+l` malleation test; the Rust and JS verifiers share the subgroup/`S<l` checks (`verifiers/javascript/verifier.js`, `verifiers/rust/src/lib.rs`). Not re-read line-by-line (medium confidence).                                                                                                                                                                                                                                                                                                                                                  |
| Audit IDs `L2`, `L3` (→ V5 L-02 / L-03)                                          | **FIXED**                                          | Same rows as V5 L-02 and L-03 above.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Audit IDs `L6`, `L7`, `L8`                                                       | **CANNOT CONFIRM — IDs do not exist in this repo** | A repo-wide grep for `OLY-L6`, `OLY-L7`, `OLY-L8` and bare `L6`/`L7`/`L8` in `docs/audits/` returns nothing. The L-series in `docs/audits/2026-06-22-red-team-mythos.md` is not contiguous (it has `OLY-L03`, `OLY-L15`, `OLY-L16`, …). These three cannot be marked closed or open without the source list.                                                                                                                                                                                                                                                                    |
| V6 M-01 — PDF trailer-parser recursion (added because it was the newest blocker) | **FIXED**                                          | `zk/pdf_objects.rs:321-336` now threads `depth` and returns `None` past `MAX_PDF_VALUE_DEPTH = 64` (`:53`); the sole caller maps `None` to `MalformedXref` (`:456`), the fail-closed direction.                                                                                                                                                                                                                                                                                                                                                                                 |
| V6 L-01 — `skip_group` mutual recursion                                          | **FIXED**                                          | `zk/segment.rs:388` now takes `frames` and bails past `MAX_PDF_DICT_DEPTH = 64` (`:253`), returning `None` which the caller maps to `PdfObjectType::Unparseable` rather than "absent `/Type`".                                                                                                                                                                                                                                                                                                                                                                                  |

**Net:** every V5/V6 item that exists in this tree is fixed. The only unverifiable rows are the three IDs that have no referent here.

---

## 3. Findings by area

### A. Cryptographic correctness

**A-P2-1 — The hybrid suite label is not covered by the signed digest (latent downgrade)**

**Severity:** P2 · **Confidence:** high · **File:** `crates/olympus-crypto/src/signature_envelope.rs:182-213`, `:264-273`

`signature_envelope_message` hashes only the prefix, `domain_separator`, and `payload_digest`. `SignatureSuite` and the `signatures[].algorithm` list are **not** in the digest. `validate_shape` (`:215-247`) derives its allowed/required set from `self.suite`, so the suite field is self-describing rather than authenticated.

Consequence, once a real PQ producer exists: take a `HybridEd25519MlDsa65` envelope, set `suite = Ed25519`, drop the `MlDsa65` component, and the untouched Ed25519 signature still verifies under `ClassicalRequired`. `ADR-0038:199` claims the opposite: _"Downgrade attempts fail because a suite that advertises hybrid protection requires both signatures and the signed bytes name every algorithm."_ The signed bytes name only the domain and payload.

Today this is inert: `MlDsa65` verification is unimplemented, so `HybridRequired` returns `UnsupportedAlgorithm` (`:196-204`) and every hybrid envelope is rejected. But the construction, not just the implementation, is what the ADR claims is downgrade-resistant, and it is not.

**Repro (a unit test that would have to be added to `signature_envelope.rs`):**

```rust
#[test]
fn suite_label_is_not_bound_by_the_ed25519_signature() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let ds = DomainSeparator::new("OLY:TEST:V1").unwrap();
    let mut env = SignatureEnvelopeV2::sign_ed25519(ds, [9u8; 32], &sk);
    // A future PQ producer's envelope:
    env.suite = SignatureSuite::HybridEd25519MlDsa65;
    env.signatures.push(SignatureComponent {
        algorithm: SignatureAlgorithm::MlDsa65,
        public_key: vec![0u8; 1952],
        signature: vec![0u8; 3309],
    });
    // Attacker relabels it classical and strips the PQ leg:
    env.suite = SignatureSuite::Ed25519;
    env.signatures.retain(|c| c.algorithm == SignatureAlgorithm::Ed25519);
    // Signature still verifies — suite/signatures were never signed.
    assert!(env.verify(SignatureVerificationMode::ClassicalRequired).is_ok());
}
```

**Fix:** fold the suite identifier (and the ordered algorithm list) into `signature_envelope_message` before any PQ work is enabled, and bump the envelope prefix/schema. Until then, correct `ADR-0038:199`.

**Regression coverage:** the existing tests at `:332-465` all assert accept/reject for a _fixed_ suite; none mutates the label after signing.

**A-P2-2 — ML-DSA hybrid signatures do not exist as a shipped control**

**Severity:** P2 (documentation/launch-readiness) · **Confidence:** high · **File:** `crates/olympus-crypto/src/signature_envelope.rs:66-72`, `:196-204`

`SignatureVerificationMode::HybridRequired` unconditionally returns `UnsupportedAlgorithm(MlDsa65)` after checking presence. No code path signs hybrid (`sign_ed25519` is the only constructor), and no ML-DSA crate appears in `Cargo.lock`. This is fail-closed, so it is not a vulnerability — but any launch material that describes "ML-DSA hybrid checkpoint signatures" as a shipped property is inaccurate. The ADR itself is correctly scoped as experimental (`ADR-0038:174-186`); the risk is only in downstream prose.

**A — clean (what was checked and holds):**

- **BJJ group/encoding checks.** `verify_checkpoint_signature` (`federation/verify.rs:400-492`) requires canonical decimal Fr for root, authority hash, and every signature component, recomputes the authority hash from the pinned peer key, and enforces `checkpoint_scope == shard`, `sanitize_shard`, and non-negative `tree_size`/timestamp before delegating to `baby_jubjub::verify_signature`, which enforces `R8` + pubkey subgroup membership (V6 M-1).
- **Poseidon vs BLAKE3 roots are separate by construction.** The Poseidon document tree's empty leaf is `Fr(0)` (`zk/poseidon.rs:108` calls `empty_tree_root(20, Fr::from(0), NODE_DOMAIN)`), which matches `non_existence.circom`'s `merkle.leaf <== 0`. The BLAKE3 SMT's empty slot is the domain-separated `BLAKE3("OLY:EMPTY-LEAF:V1")` (`crates/olympus-crypto/src/smt.rs:489`). ADR-0044 signs the BLAKE3 _shard subtree_ root under its own domain (`OLY:SMT:ROOT:V1`) and folds `shard_id`, `ledger_root`, `tree_size`, and the BLAKE3 root into the digest; the global 256-depth proof is reinterpreted against that shard root only via the dedicated functions, not by comparing the global root (`smt.rs:524-567`).
- **`document_existence` binding.** Public signals are exactly `[root, leafIndex, treeSize]` (`proofs/circuits/document_existence.circom:115`), `leafIndex` is bound to `pathIndices` (`:79`), and the `treeSize > 0 ⇒ leafIndex < treeSize` constraint uses circomlib `IsZero` rather than a hint (`:88-100`).
- **The `treeSize=0` invariant is enforced twice** — at `/zk/verify` and on the federation receive path (`federation/verify.rs:558` calls `zk::verify::enforce_empty_tree_invariant`), which is the correct place given the circuit cannot know the empty root.
- **Signed Merkle fold order.** The verifier re-derives the artifact spans first, then recomputes `table_hash` from the bundle's segments, checks the Ed25519 signature over the payload that includes `format`, `N`, `recipient_id`, and `table_hash`, then recomputes the nullifier (`verifiers/rust/src/redaction.rs:1482-1509`). Signature is checked **before** the nullifier comparison, and the nullifier is recomputed rather than trusted.
- **Cargo dependency graph is free of the GPL family.** `poseidon-rs`, `ff_ce`, and `babyjubjub-rs` do not appear in `Cargo.lock`; `deny.toml:71-80` bans GPL with the old `poseidon-rs` carve-out removed.

### B. Sparse Merkle Tree

**B — clean on every question the brief asks.**

- **No hot-path full-tree rebuild.** There is no `_load_tree_state` symbol in the repository. `update_batch_inner` (`src-tauri/src/smt/tree.rs:369`) walks only the batch's key paths and norms the nodes it touches; the only bulk work is `prove`'s over-cap canopy materialisation (`:885-935`), bounded by `CANOPY_RECOMPUTE_CAP`.
- **Pinned constants intact.** `LAZY_DEPTH = 72` (`tree.rs:129`) and `CANOPY_RECOMPUTE_CAP = 1024` (`:148`), with the `const` assertions at `:184-197`; over-cap canopies keep their persisted deep nodes (`:603-662`).
- **Writers serialise.** `NodeBackend::begin_write` is the single write transaction (`smt/backend.rs:184`), implemented for Postgres (`:683`), SQLite (`:1189`), and memory (`:1673`); `update_batch` takes the read-modify-write inside it and publishes the cache only afterwards.
- **Exclusion proofs cannot verify for a present key.** `verify_nonexistence_proof` (`crates/olympus-crypto/src/smt.rs:474-490`) folds from the **fixed** `empty_hashes()[0]`, not from a proof-supplied terminal leaf, and compares against the root. A present key has a different leaf hash, so the fold cannot reconstruct the root except by a hash collision. That is the right direction.
- **Leaf domain tag.** `leaf_hash` uses the ADR-0005 structured prefix and binds `shard_id`; `verify_existence_proof` additionally enforces `shard_id_matches_key` (`smt.rs:456`), so a proof cannot claim a shard its key does not address.

**B-P3 — Over-cap canopy proof cost is unbounded in wall-clock, not memory.** `prove` fetches up to `CANOPY_RECOMPUTE_CAP + 1` leaves per canopy and folds each (`tree.rs:899-935`). This is bounded and documented, but it is the one place where proof latency scales with data shape; worth a benchmark before launch, not a security finding.

### C. Untrusted input parsing and DoS

**C-P2-1 — The highest-risk parsers have no fuzz target, and there is no in-repo corpus**

**Severity:** P2 · **Confidence:** high

Parser entry points reachable from untrusted input, and whether a fuzz target exists:

| Parser entry point                                                                     | Reachable from            | Fuzz target?                                                                         |
| -------------------------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------ |
| `zk/segment/pdf_objects.rs` — traditional xref, `parse_trailer_info`, `skip_pdf_value` | `POST /ingest/files`      | **No**                                                                               |
| `zk/segment/pdf_xref.rs` — xref streams, ObjStm, `/Prev` chain                         | `POST /ingest/files`      | **No**                                                                               |
| `zk/segment.rs` — `pdf_object_type_name` / `skip_group`                                | `POST /redaction/redact`  | **No**                                                                               |
| `zk/segment/ooxml.rs` — Stored-zip repackage, central directory                        | `POST /ingest/files`      | **No**                                                                               |
| `zk/segment/text.rs` — line-block segmenter                                            | `POST /ingest/files`      | **No**                                                                               |
| `verifiers/rust/src/redaction.rs::parse_bundle` / `verify_bundle`                      | offline recipient         | **Yes** — `verifiers/rust/fuzz/fuzz_targets/fuzz_redaction_bundle.rs`                |
| `crates/olympus-crypto` SMT/leaf primitives                                            | internal + verifier       | **Yes** — `fuzz/fuzz_targets/fuzz_smt.rs`                                            |
| `zk/verify` Groth16 proof parsing                                                      | `POST /zk/verify`         | **No** (primitives only: `fuzz_crypto_primitives.rs`, `fuzz_compute_merkle_root.rs`) |
| `api/middleware/signed_request.rs::parse_wire_envelope`                                | signed-admin routes       | **No**                                                                               |
| `crates/olympus-crypto/src/signature_envelope.rs::verify`                              | signed routes             | **No**                                                                               |
| `crates/olympus-crypto/src/request_envelope.rs`                                        | signed routes             | **No**                                                                               |
| `anchoring/rfc3161_verify.rs::take_der_tlv`                                            | TSA replies               | **No**                                                                               |
| `proofs/zkvm` journal/claim decoder (`zk/canonicalization.rs`)                         | canonicalization receipts | **No**                                                                               |

`fuzz/` contains three targets, `verifiers/rust/fuzz/` contains two; `fuzz/corpus/*` expanded to no directories, i.e. **no corpus is checked in** (V6's "report corpus size" answer is: not present). The two recursion defects this repo fixed by hand (V6 M-01, L-01) are exactly the class a segmenter fuzz target would have found. The verifier-side target covers bundle parsing but not the producer's PDF walk.

**Fix:** add libFuzzer targets for `segment::segment_document` (all four formats behind one entry), `pdf_objects::parse_trailer_info`, and `parse_wire_envelope`; seed each with the existing `verifiers/test_vectors` artifacts and commit a small corpus. The nightly job (`fuzz-nightly.yml`) already exists.

**C — clean:** document-wide inflate budget (V6 A1-02 fix) and depth caps at 64 for both recursion sites; `DefaultBodyLimit` 128 MiB globally (`server/mod.rs:346,389`), a separate `AUTH_BODY_LIMIT` (`:309`), and `VERIFY_BODY_LIMIT` on `/zk/verify` (`api/zk/mod.rs:834,848`); general rate limit 60 req/min and registration 2 req/min (`api/middleware/auth.rs:697-743`); `MAX_REDACTION_SEGMENTS = 1 << 16` enforced on both producer and verifier with `checked_add` on every span arithmetic (`verifiers/rust/src/redaction.rs:40,710-716,812,946-950`); three-dot diff with `--no-renames` and a commit-existence check in the scope gate.

### D. Federation and quorum

**D-P2-1 — Checkpoint quorum is collected and pinned but not enforced at acceptance, and its threshold fails open to 1 on a typo**

**Severity:** P2 · **Confidence:** high on the code behaviour, medium on intent
**Files:** `src-tauri/src/quorum/checkpoint.rs:76-91`, `src-tauri/src/federation/checkpoint_cosign.rs:490-560`

`configured_checkpoint_threshold()` (`quorum/checkpoint.rs:76-91`) returns `1` when the env var is unset **and** when it is present but unparseable, logging a warning:

```rust
// quorum/checkpoint.rs:83-89
Err(_) => {
    tracing::warn!("… is not a valid non-negative integer; defaulting … to 1");
    1
}
```

The only consumer in the federation path uses it to collect co-signatures (`checkpoint_cosign.rs:482`), and `verify_checkpoint_quorum` is consulted only to skip a redundant collection round (`:517-523`). The primitive's own doc comment says the acceptance policy "must be applied by the future Phase-2 producer" (`:177-186`). So today an operator who set `OLYMPUS_CHECKPOINT_QUORUM_THRESHOLD=3` and made a typo gets a silently recorded 1-of-N quorum, and nothing rejects a checkpoint for having too few co-signatures.

**Why P2, not P1:** signature and proof verification on the receive path are independent of this and do fail closed (`verify.rs` steps 1-2). The quorum block is currently evidence metadata, not the acceptance gate. It becomes P1 the moment a launch document claims checkpoint quorum is enforced.

**Fix:** treat a present-but-unparseable value as a startup error (matching the `OLYMPUS_ENV` lesson), and wire `verify_checkpoint_quorum(...).satisfied` into the acceptance path with a configured `2 ≤ M ≤ N` minimum before advertising the feature.

**D — clean:** the A1-03 atomicity fix (single tx + advisory lock); the disjunctive `tree_size`-or-timestamp conflict rule; wire-version gate (`verify.rs:126-135`); canonical-decimal enforcement; proof-to-envelope binding on root **and** `tree_size` (`verify.rs:523-545`), which closes the red-team F-1 "valid proof of the wrong fact" path; `tree_size=0` rejection on the federation path. **Quorum math:** `valid_signatures >= threshold` is inclusive at the boundary (correct), duplicates are counted once by normalized pubkey (`quorum/mod.rs`, test `duplicate_signer_counts_once` at `quorum/checkpoint.rs:442`), and `threshold == 0` is never vacuously satisfied (`:487`). Revoked signers are not modelled in the counting primitive; the pinned signer set is loaded from `trusted_signer_set`, so revocation is a trust-list refresh question, not a quorum-counting bug.
**D-P3 — the "federation.py decomposition" blocker is obsolete.** The responsibilities are already separated across ten Rust modules. If a split is attempted anyway, the one invariant to preserve is that **detection, auto-block, and storage stay in one transaction under the per-identity advisory lock** (`federation/verify.rs:186-276`); moving `check_and_flag` into its own module with its own transaction would reintroduce V5 A1-03 exactly.

### E. Tauri 2 / GTK4 boundary

**E-P2-1 — Path-based IPC commands accept any renderer-supplied absolute path**

**Severity:** P2 · **Confidence:** high · **Files:** `src-tauri/src/commands/files.rs:161-175` (`hash_file_for_manifest`), `:265-269` (`read_file_for_render`), `:285-292` (`describe_by_path`), helper `:212-238`

`read_file_capped` checks only "is a regular file" and the size cap. It does not confine the path to a dialog-picked file, a workspace root, or an allow-list. The renderer supplies the string, so anything that can execute script in the webview can read any file the user can read (up to `RENDER_BYTES_LIMIT` / `IPC_BYTES_LIMIT`) and post it to the loopback API, which the renderer can also reach.

Controls that make this P2 rather than P1: the CSP is strict (`tauri.conf.json:24`, `script-src 'self' 'wasm-unsafe-eval'`, `object-src 'none'`, `frame-ancestors 'none'`), there is **no** `dangerouslySetInnerHTML`/`innerHTML`/`eval`/`new Function` anywhere in `app/public-ui/src`, and the capability set is minimal (`capabilities/default.json`: `core:default`, `dialog:allow-open` only — no `fs:` plugin). So the renderer compromise this depends on has no obvious route today.

**Fix:** have the dialog hand back an opaque token referencing the picked path (the codebase already keeps bytes out of JS for this reason), or record dialog-approved paths in a short-lived server-side set and require membership.

**E — clean:** 16 `#[tauri::command]` handlers, none returns raw key material except the deliberate one-shot `take_initial_secrets` (`commands/secrets.rs:57-62`, `Option::take`, cleared after first call); `save_text_to_disk` writes only to a user-chosen save-dialog path (`files.rs:513-536`); keychain account is fixed and separate from authority material (test at `commands/keychain.rs:68`); CSP has no `unsafe-eval` beyond the WASM allowance, no remote origins, and `connect-src` is loopback-only.

### F. Supply chain and CI

**F-P0-1** is the launch blocker above (§1).

**F-P2-1 — The advisory ignore-list must be revalidated before launch**

**Severity:** P2 · **Confidence:** medium · **File:** `cargo-audit-baseline.txt`

26 distinct `RUSTSEC` IDs are ignored (the header's "23 remaining" is consistent: three IDs appear only in the removed-entries commentary). Clusters: 17 in the tauri/gtk-rs/glib/unic/proc-macro tree, 5 via ark/RISC Zero (`wasmer`, `memmap2`, `paste`, `derivative`, `tracing-subscriber`), 1 via Arti/RSA. Only **RUSTSEC-2023-0071** (the `rsa` Marvin timing side channel) has a plausible first-party-adjacent path, and only when the optional `federation` feature and the Tor RSA stack are compiled in. The rest are unmaintained-crate notices or build/GUI-only code. I did not execute `cargo audit`, so this is a reading of the baseline, not a fresh scan.

**F — clean:** every `uses:` in `ci.yml` and `pr-scope-drift.yml` is pinned to a full commit SHA with a version comment (e.g. `actions/checkout@3d3c42e5…`); the scope gate uses `pull_request` (not `pull_request_target`) with `contents: read` and no secrets, and passes attacker-influenced strings through `env:`/files rather than `${{ }}` in `run:`; `deny.toml` allows only `https://github.com/OlympusLedgerOrg/tauri.git` as a git source, denies unknown registries and wildcards, and bans GPL; `babyjubjub-permissive`'s tree contains no `poseidon-rs`/`ff_ce`/`babyjubjub-rs`; secrets scanning is present in `ci.yml` (gitleaks/trufflehog). `codeql.yml` covers `javascript-typescript` and Rust (`build-mode: none`).
**F-P3 — the "forked tao and wry" premise is partly wrong.** Only `tauri-runtime-wry` is pinned to the org fork (`Cargo.toml:85`, rev `1afd9bd871f7100fab6bdc6002f029203b7f38e7`); `wry 0.55.1` resolves from crates.io (`Cargo.lock:12766-12769`), and `tao` likewise. The CVE patch therefore lives inside the `tauri` fork, not in a local `tao`/`wry` crate. I could not diff the fork against upstream without fetching an external repository; see unverified leads.

### G. Launch readiness

**G-P2-1 — Coverage is measurement-only; there is no gate and no current number**

**Severity:** P2 · **Confidence:** high · **Files:** `docs/coverage.md:3,9`, `.github/workflows/coverage.yml:3-5`

The brief's "90% gate" does not exist. `docs/coverage.md:3` states coverage "is **measurement-only** — … do not block merges"; `:9` says the eventual goal is "≥85% line coverage per module"; `:57` repeats that the ratchet is not merge-blocking. The workflow measures both Rust and frontend and posts a summary, but no threshold is enforced for Rust, and no current per-module figure is published in the repo. **I cannot identify the lowest-covered security-critical modules from the tree**, because that requires running `cargo llvm-cov` (not permitted in this read-only pass) or reading a stored report (none is committed). The claim that coverage sits "against the 90% gate" is unsupported in both directions.

**G-P2-2 — A fresh install needs network access for PostgreSQL, and the embedded port is hardcoded**

**Severity:** P2 · **Confidence:** high · **Files:** `src-tauri/src/db/embedded.rs:20,96`, `src-tauri/tauri.conf.json:38-44`

`PG_PORT` is `5433` with no environment override on the `init_embedded` path, and the module documents that "on a cold binary cache, pg_embed downloads PG 15 binaries to the OS cache". The Tauri `resources` list bundles only proof artifacts and `LICENSES/*` — **no PostgreSQL binaries**. So an offline first run, or a machine already using 5433, cannot start the database, which contradicts `AGENTS.md`'s "No external Python, Go, Node, or Docker required at runtime" and the desktop-first deployment story. `DATABASE_URL` is the escape hatch, but that is a server deployment, not a desktop install.

**G-P2-3 — All four circuits ship placeholder proving artifacts; dev mode proceeds anyway**

**Severity:** P2 · **Confidence:** high · **Files:** `proofs/keys/` (state), `src-tauri/src/startup.rs` (gate behaviour)

wiserepo's `circuit_status` at the audited SHA: for all four circuits, `wasm`, `r1cs`, and `ark_zkey` are `placeholder`, `ready: false`, and `production_circuits_ready: false`. `build.rs` writes those ~60-byte stubs so resources and `include_str!` resolve. Under `OLYMPUS_ENV=production` startup exits 2 (correct, fail-closed), and `env.rs:113-137` resolves an unset `OLYMPUS_ENV` to the release channel's default — presumably production for release builds, which is the safe direction. In dev the manifest check logs an error and continues, so an ordinary `cargo tauri dev` (or a build without the production env) presents a working UI whose every proof fails at runtime. That is the expected pre-ceremony state, but it means **no proof path is end-to-end testable from a clean checkout**, and any launch artifact must be built with the production gate enabled and verified to refuse.

**G — clean:** E2E against real PostgreSQL **does** run in CI — seven binaries including `e2e_http`, `api_db`, `smt_pg_backend`, `checkpoint_transition_attestation`, `federation_equivocation`, and `db_init_embedded`, invoked serially via `scripts/embedded-postgres-tests.sh` at `ci.yml:1815-1830` and again in `tauri-release.yml:175-195`. **Migrations 0062 and 0063 are additive and non-destructive:** 0062 adds a nullable column plus a `CHECK` guarded by a `pg_constraint` existence test; 0063 creates three new tables and indexes with no `ALTER`/`DROP` of existing objects. sqlx migrations are forward-only by design, so the absence of down-migrations is the tool's model, not an omission. Ordering risk is low: 0063's FKs reference tables it creates in the same file.

---

## 4. Unverified leads

Each of these needs the stated evidence before it can become a finding.

1. **Forked `tauri`/`tao`/`wry` diff.** Needs `git clone https://github.com/OlympusLedgerOrg/tauri` at rev `1afd9bd8…` and a diff against upstream `tauri` at the same version, filtered to `tao`/`wry`/`tauri-runtime-wry`. Claim to verify: the delta is limited to GHSA-wrw7-89jp-8q8g. `deny.toml:109` restricts git sources to that repo, which limits the blast radius to whatever that fork contains.
2. **`unified_canonicalization_inclusion_root_sign.circom` public-input binding.** Not read this pass. The API exposes only the narrower `unified_section_commitment_inclusion_root` statement; the claim that the composed RISC Zero receipt binds canonicalization correctly needs a read of `proofs/circuits/unified_canonicalization_inclusion_root_sign.circom` plus `zk/canonicalization.rs`'s journal decoder (V6 cleared the latter).
3. **`federation_quorum.circom`** — feature-gated behind `quorum-circuit`, ceremony-pending, not read. The explicit signature set is authoritative; the circuit is not on the default path.
4. **`pdf_xref.rs` cumulative inflate budget** — relied on V6's re-verification and regression test; I did not re-read the threading. Medium confidence.
5. **`pg_embed` binary-download authenticity** — `embedded.rs:374-419` mentions an "authenticated executable cache" and forbids cache reuse until a target is authenticated, but I did not read the checksum/signature source.
6. **GitHub branch protection / required status checks** — not readable from the repository. This decides whether P0-1 is theoretical (gate not required) or a real gate bypass (gate required, but bypassable).
7. **ADR-0041 trust-list state machine** (`src-tauri/src/trust/`, migration 0063) — not audited beyond the migration's constraints.
8. **ADR-0032's actual subject** — the brief describes a Plonky3 recursive ledger proof; no such code exists. If a second proof backend is planned, it is not in this tree.
9. **`cargo audit` / `cargo deny` / `pip-audit` execution** — not run (read-only, and tool availability unverified). The advisory picture here is a reading of `cargo-audit-baseline.txt` and `deny.toml`.

---

## 5. Coverage gaps

- **No dynamic verification.** No `cargo check`, `cargo test`, coverage run, or build. Every statement about behaviour is from reading the committed source. The one place this matters most is V5 A1-02, which is marked FIXED on V6's evidence plus the presence of the budget plumbing, not on a re-read.
- **wiserepo was not available as an MCP tool.** The in-repo server exists and its deterministic `checkInvariants`/`circuit_status` were run, but there is **no structural-drift-against-baseline or blast-radius tool in it**, and no model-backed `repo_qa`/`review_diff`. The structural pass therefore consisted of `checkInvariants`, `circuit_status`, `git log`, `CODEOWNERS`, and grep. **`checkInvariants` itself is unreliable:** at the audited SHA it reports "no hits in relevant files" for `LAZY_DEPTH`, `CANOPY_RECOMPUTE_CAP`, and `LEAF_BODY_FIELD_COUNT`, although `LAZY_DEPTH` is at `src-tauri/src/smt/tree.rs:129`, `CANOPY_RECOMPUTE_CAP` at `:148`, and `LEAF_BODY_FIELD_COUNT` is defined in `crates/olympus-crypto/src/lib.rs`. It found the cross-language prefix constants correctly, so the failure is specific to the `relevant_files` lookup (likely CRLF/path handling). As a gate it would produce false drift alarms, and if its output were trusted as "not found ⇒ missing", it would fail open on exactly the pinned constants it exists to protect. This is P3 tooling work, not a product finding.

**Fixed in the working tree during this pass:** `checkInvariants` now passes each invariant's own files to `gitGrep` as pathspecs, so truncation cannot hide a relevant file, and `test/olympus.test.mjs` pins the `tree.rs:129` hit as a regression. The audit above still describes the committed SHA; the fix is uncommitted.

- **Dirty working tree.** The audit is of `HEAD`; the tree a developer would build right now differs in 15 files, including ingest. I re-checked the three security-relevant ones against `git show HEAD:` but did not audit the uncommitted diffs themselves.
- **Frontend not built or rendered.** CSP and the absence of `dangerouslySetInnerHTML`/`eval` were checked by grep; no visual or runtime check was performed.
- **GitHub settings not visible** (branch protection, required checks, secret scanning alerts, CodeQL alert state).
- **Not audited at all:** `anchoring/*` beyond the two fixed items, `trust/*`, `mmd.rs`, `clients/cli`, `clients/python` SDK behaviour, `proofs/zkvm` guest code, and the `pg-embed-local` fork.

---

## 6. Recommended next steps

Sequenced against the three stated pre-public blockers.

**Blocker 1 — Groth16 ceremony (largest, start first).**

1. Run `proofs/setup_circuits.sh` and the Phase-2 ceremony; publish the signed manifests and the real `.ark.zkey`/vkey set. Until then, `circuit_status` stays `production_circuits_ready: false` and no proof path is end-to-end testable.
2. Build the launch artifact with the production gate on and verify it **refuses** to start on a placeholder (the `exit 2` path), then verify it starts with real artifacts.
3. Before the ceremony freezes the vkeys, decide A-P2-1 (suite binding). Changing the envelope digest after PQ work begins would be a wire break; changing it now is free.

**Blocker 2 — `federation.py` decomposition: nothing to do as described.** No such module exists; the split already happened in Rust. Reframe the task as "wire checkpoint quorum into acceptance" (D-P2-1) and treat the atomic detect+store transaction in `federation/verify.rs` as untouchable during any refactor.

**Blocker 3 — E2E against PostgreSQL: already green in CI.** Close this as done (`ci.yml:1815-1830`). Replace it with the two launch-readiness gaps that are real: fresh-install PostgreSQL provisioning (G-P2-2) and the absence of a coverage ratchet (G-P2-1).

**Gate integrity (blocks a trustworthy launch process).** 4. Fix P0-1: run the scope checker and workflow from base-commit content, and fail any PR that edits its own gate without a second CODEOWNER approval. Confirm the check is a _required_ status check. 5. Add the missing fuzz targets (C-P2-1) for the four segmenters and the signed-request parser; commit a seed corpus. This is the highest-value P2 by defect class, given that both recent blockers were hand-found parser recursion.

**Hygiene.** 6. Revalidate the 26 ignored advisories at launch and record the reachability argument for RUSTSEC-2023-0071. 7. Fix `checkInvariants`'s `relevant_files` lookup, or stop presenting it as an invariant gate. 8. Correct `ADR-0038:199`'s downgrade claim until the suite is actually bound into the signed digest; confirm no downstream launch text advertises ML-DSA as shipped.
