# Audit — Build / Supply Chain (Area 7)

**Date:** 2026-05-29
**Branch:** `claude/next-code-audit-1qzNj` (HEAD `8f026f3`)
**Scope:** The build and dependency-provenance surface explicitly deferred by
the 2026-05-25 API and frontend audits. Specifically:

- Rust dependency policy: workspace `Cargo.toml`, `Cargo.lock`, `deny.toml`,
  `cargo-audit-baseline.txt`, per-crate manifests.
- Vendored / patched crates: `crates/glib-0.18.5-patched/`,
  `crates/light-poseidon/`, `crates/babyjubjub-permissive/`, and
  `proofs/vendor/circomlib/`.
- Build scripts: `src-tauri/build.rs`, the vendored-provenance scripts in
  `scripts/`.
- JS dependency policy: root + `app/public-ui/` + `verifiers/javascript/` +
  `proofs/` `package.json`, `pnpm-lock.yaml`, the `safe-jsonpath` shim.
- CI supply-chain enforcement: `.github/workflows/ci.yml` (`supply-chain`,
  provenance jobs), `dependabot.yml`, `dependency-lock.yml`,
  `dependabot-pnpm-lockfile.yml`, `copilot-setup-steps.yml`.

**Type:** Audit + remediation. The original pass was read-only; this PR
additionally lands the minimal fixes for the still-valid findings (see
§5 for the per-finding status).

**Out of scope:** Tauri shell config / capabilities (Area 8 — partially
covered by the 2026-05-25 IPC audit), sqlx migrations (un-audited; flagged as
a separate next area), the cryptographic correctness of `babyjubjub-permissive`
(covered by the cross-language verifier vectors, not supply-chain provenance).

---

## 1. Executive summary

**7 findings: 0 High, 2 Medium, 5 Low. 9 verified clean.**

The supply-chain posture is **strong and unusually well-documented** on the
parts that protect the shipping binary:

- `deny.toml` bans GPL in the Cargo graph with **no exceptions**, denies
  unknown registries/git sources, and denies wildcards (correctly exempting
  unpublishable path crates only).
- `cargo-audit-baseline.txt` is exemplary — every one of the 20 ignored
  RUSTSEC advisories carries a dated rationale, blast-radius analysis, and a
  concrete upstream-release unblock condition; revalidated 2026-05-24.
- The one genuinely exploitable advisory (glib `RUSTSEC-2024-0429`) is
  **actually patched in-tree**, not merely suppressed.
- SBOMs (CycloneDX) are emitted for every Rust + JS artifact with pinned tool
  versions and uploaded as a 90-day artifact.
- Two of the four vendored trees (`light-poseidon`, `circomlib`) have
  committed `PROVENANCE.md` + **pinned-SHA CI drift checks**.

The findings cluster into two themes, neither of which weakens the shipped
binary today:

1. **One vendored tree is missing the CI drift-check the others have**
   (M-SC-1), and **three tracked lockfiles are never audited** (M-SC-2).
2. **Build/CI plumbing has drifted away from the v0.9.0 Python/Go retirement**
   — Dependabot, `dependency-lock.yml`, and `copilot-setup-steps.yml` all
   still point at deleted trees or a missing `pyproject.toml` (L-SC-1 through
   L-SC-3), plus JS package-manager drift (L-SC-4) and undocumented JS audit
   suppressions (L-SC-5).

### Findings table

| ID | Sev | Headline |
|---|---|---|
| M-SC-1 | 🟡 | Vendored `glib-0.18.5-patched` (52 k LoC, ships in the Linux binary) has **no CI drift-check**, unlike `light-poseidon`/`circomlib`; byte-identity is verified by a manual local procedure only |
| M-SC-2 | 🟡 | `cargo audit` covers only 2 of the 5 tracked `Cargo.lock` files; `fuzz/`, `verifiers/rust/fuzz/`, and `services/cdhs-smf-rust/fuzz/` lockfiles are never audited despite the `deps` filter triggering on `**/Cargo.lock` |
| L-SC-1 | 🟢 | Dependabot config points at four deleted/absent trees (`pip /`, `gomod /verifiers/go`, `gomod /services/sequencer-go`, `cargo /services/cdhs-smf-rust`) — each errors on every weekly run |
| L-SC-2 | 🟢 | `dependency-lock.yml` runs `pip-compile pyproject.toml` weekly against a **non-existent** `pyproject.toml`, holding `contents: write` + `pull-requests: write` |
| L-SC-3 | 🟢 | `copilot-setup-steps.yml` runs `pip install -e ".[dev]"` + `ruff` against the same missing `pyproject.toml` — broken setup step |
| L-SC-4 | 🟢 | JS package-manager / lockfile drift: `packageManager` mismatch (`pnpm@11.1.2` root vs `pnpm@10` in public-ui) and `vite@^8` ↔ `esbuild@0.21.5` lockfile drift that CI works around with `--ignore-npm-errors` |
| L-SC-5 | 🟢 | Three `pnpm.auditConfig.ignoreGhsas` suppressions in root `package.json` carry no rationale **and** are not consulted by the `npm audit` calls CI actually runs |

---

## 2. Findings

### 🟡 M-SC-1 — Vendored `glib-0.18.5-patched` has no CI drift-check

**Where:** `crates/glib-0.18.5-patched/` (~52,330 lines of Rust),
`[patch.crates-io] glib = { path = … }` in `Cargo.toml:35-36`,
`crates/glib-0.18.5-patched/PROVENANCE.md`.

**What.** Olympus vendors a full copy of `glib 0.18.5` and `[patch]`-overrides
the crates.io version to backport the `GHSA-wrw7-89jp-8q8g` /
`RUSTSEC-2024-0429` soundness fix. This crate **links into every Linux build**
(it's the GTK/glib binding under the webview). Its `PROVENANCE.md` asserts the
tree is "byte-identical to the published `glib-0.18.5` except the 2-line fix in
`src/variant_iter.rs`" — but that claim is enforced only by a **manual local
procedure** (`## Verifying the backport locally`: `cargo tree`, a `grep` for
the two patched lines, and a `cargo audit` run).

By contrast, the two other vendored Rust/circuit trees each have a committed
re-vendor pin **and a CI job that fails on drift**:

- `crates/light-poseidon/` → `scripts/check_light_poseidon_upstream.sh`
  (pins `UPSTREAM_SHA=203de7f…`) → CI job `light-poseidon-provenance`.
- `proofs/vendor/circomlib/` → `scripts/check_circomlib_upstream.sh` → CI job
  `circomlib-provenance`.

There is **no `scripts/check_glib_upstream.sh` and no glib provenance CI job.**
A silent edit to any of the 52 k vendored lines — or a botched future
re-vendor — would pass CI. This is the largest vendored surface in the repo
and the only one that ships in the binary without an automated provenance gate.

**Severity rationale.** Medium, not High: the `[patch]` is real and the fix is
in place today, the GHSA is genuinely closed, and the dep filter
(`rust-app: crates/**`) at least *triggers* CI on edits to the crate — there's
just no job that checks the content against upstream. The risk is future drift
going unnoticed, not a present-day vulnerability.

**Fix.** Add `scripts/check_glib_upstream.sh` modeled on
`check_light_poseidon_upstream.sh`: clone `gtk-rs/gtk-rs-core` at the pinned
0.18.5 tag, diff every vendored file, and allow exactly the documented
`variant_iter.rs` delta (assert the two patched lines are present and nothing
else diverges). Wire it as a `glib-provenance` CI job gated on
`rust-app == 'true'`, mirroring the existing two provenance jobs. Cross-link it
from `PROVENANCE.md`'s "Verifying" section so the manual steps and the CI gate
stay in sync.

---

### 🟡 M-SC-2 — Three tracked lockfiles are never audited

**Where:** `.github/workflows/ci.yml` `supply-chain` job, lines 191-192:

```bash
cargo audit --file Cargo.lock ${IGNORE_ARGS}
cargo audit --file verifiers/rust/Cargo.lock ${IGNORE_ARGS}
```

**What.** Five `Cargo.lock` files are committed and tracked:

| Lockfile | Audited by CI? |
|---|---|
| `Cargo.lock` (workspace) | ✅ |
| `verifiers/rust/Cargo.lock` | ✅ |
| `fuzz/Cargo.lock` | ❌ |
| `verifiers/rust/fuzz/Cargo.lock` | ❌ |
| `services/cdhs-smf-rust/fuzz/Cargo.lock` | ❌ |

The `changes` filter's `deps` output triggers the `supply-chain` job on
`**/Cargo.lock` (ci.yml `deps` filter) — so an edit to any of the three
fuzz lockfiles *runs* the job, but the job's `cargo audit` invocations never
inspect them. The fuzz harnesses are dev-only and not shipped, which keeps
this Medium rather than High, but a known-vulnerable transitive dep could land
in a fuzz lockfile and pass the very job that claims to gate dependency
vulnerabilities.

**Fix.** Loop `cargo audit` over every tracked lockfile rather than naming two:

```bash
IGNORE_ARGS=$(grep -v '^[[:space:]]*#' cargo-audit-baseline.txt | awk 'NF {printf "--ignore %s ", $1}')
while IFS= read -r lock; do
  echo "::group::cargo audit $lock"
  cargo audit --file "$lock" ${IGNORE_ARGS}
  echo "::endgroup::"
done < <(git ls-files '*Cargo.lock')
```

If the fuzz lockfiles are intentionally out of scope, document that explicitly
in `cargo-audit-baseline.txt` (which currently only reasons about the two
audited graphs) so the omission is a decision, not an oversight.

---

### 🟢 L-SC-1 — Dependabot points at four deleted/absent trees

**Where:** `.github/dependabot.yml`.

**What.** Four `updates` entries target paths that no longer exist after the
v0.9.0 Python/Go retirement (verified absent on disk):

| Ecosystem / directory | State |
|---|---|
| `pip` `/` | no `pyproject.toml` / `requirements.txt` |
| `gomod` `/verifiers/go` | directory removed |
| `gomod` `/services/sequencer-go` | directory removed |
| `cargo` `/services/cdhs-smf-rust` | no `Cargo.toml` (only a `fuzz/` subdir survives) |

Dependabot raises a repo-level error for each manifest it can't resolve. The
noise can mask a real failure on the entries that *do* matter (the four cargo +
three npm + github-actions ecosystems).

**Fix.** Delete the four stale entries. The surviving Rust graphs worth
watching are already covered (`cargo /` workspace, `cargo /verifiers/rust`).
Optionally add `cargo /fuzz` and the fuzz sub-lockfiles if M-SC-2 is resolved
by auditing rather than documenting-out.

---

### 🟢 L-SC-2 — `dependency-lock.yml` compiles a non-existent `pyproject.toml`

**Where:** `.github/workflows/dependency-lock.yml`.

**What.** A scheduled (`cron: "0 6 * * 1"`) workflow with `contents: write` +
`pull-requests: write` runs:

```bash
pip-compile pyproject.toml --generate-hashes --output-file requirements.txt
pip-compile pyproject.toml --extra dev --generate-hashes --output-file requirements-dev.txt
```

There is no `pyproject.toml` in the repo. The job fails every Monday (and a
write-scoped scheduled workflow that always fails is both noise and a standing
liability). This is pure pre-v0.9.0 residue.

**Fix.** Delete the workflow. Python is retired; the residual `*.py` tooling
(`proofs/*.py`, `scripts/*.py`, `verifiers/cli|python/*.py`) has no packaging
metadata and isn't part of the shipped artifact. If those scripts are meant to
be lockfile-managed, that's a deliberate decision that needs a `pyproject.toml`
re-added first — but absent one, the workflow is dead.

---

### 🟢 L-SC-3 — `copilot-setup-steps.yml` runs broken Python setup

**Where:** `.github/workflows/copilot-setup-steps.yml:14-32`.

**What.** The Copilot environment setup installs Python 3.12, creates a venv,
and runs `python -m pip install -e ".[dev]"` followed by `python -m ruff check
.` — again against the missing `pyproject.toml`. The `pip install -e .` step
errors out (no project metadata to install).

**Fix.** Same root cause as L-SC-2: either strip the Python setup steps, or
re-add a minimal `pyproject.toml` for the residual `*.py` tooling if it is
still meant to be linted in CI. (Note: CodeQL's `python` matrix entry in
`codeql.yml` *is* justified — those `*.py` files exist and CodeQL analyzes
source directly without a build/install step. This finding is only about the
`pip install -e` packaging assumption.)

---

### 🟢 L-SC-4 — JS package-manager / lockfile drift

**Where:** `package.json`, `app/public-ui/package.json`, `pnpm-lock.yaml`,
`.github/workflows/ci.yml` Node SBOM step.

**What.** Two drifts:

1. **`packageManager` mismatch.** Root declares `pnpm@11.1.2`;
   `app/public-ui/package.json` declares `pnpm@10`. CI's `frontend-build` job
   pins `pnpm/action-setup@v6` to `11.1.2`. Corepack-strict environments will
   refuse the public-ui declaration; at minimum the two should agree.
2. **`vite` ↔ `esbuild` lockfile drift.** `app/public-ui` pins
   `vite@^8.0.14`, which wants `esbuild ^0.27 || ^0.28`, but `pnpm-lock.yaml`
   still resolves `esbuild@0.21.5`. The CI Node-SBOM step documents this
   inline ("a real upstream drift somebody should fix in a separate PR") and
   works around it with `--ignore-npm-errors`. That separate PR hasn't landed.

**Fix.** Run `pnpm install` to refresh `pnpm-lock.yaml` so the manifest and
lock agree, and align the `packageManager` field across the workspace. Once
the lockfile is consistent, the `--ignore-npm-errors` workaround in the SBOM
step can be revisited (keep it as defense-in-depth, but it should no longer be
load-bearing).

---

### 🟢 L-SC-5 — Undocumented + mis-targeted JS audit suppressions

**Where:** `package.json` (root) `pnpm.auditConfig.ignoreGhsas`.

**What.** Three advisories are suppressed with no rationale:

```json
"ignoreGhsas": ["GHSA-848j-6mx2-7j84", "GHSA-6c59-mwgh-r2x6", "GHSA-87r5-mp6g-5w5j"]
```

Two problems:

1. **No rationale.** This is the JS analogue of `cargo-audit-baseline.txt`,
   which sets the bar: every Rust suppression there names the affected crate,
   blast radius, and unblock condition. The JS suppressions are bare GHSA IDs.
2. **Wrong tool.** `pnpm.auditConfig.ignoreGhsas` is read by `pnpm audit`. The
   CI `supply-chain` job runs **`npm audit --prefix …`** (ci.yml), which does
   **not** consult pnpm's `auditConfig`. So either these suppressions are inert
   relative to CI (and CI would fail on those GHSAs if they're high/critical),
   or CI isn't actually hitting them. Worth confirming which.

**Fix.** Add a per-GHSA comment block (or a short `THIRD_PARTY_LICENSES`-style
sibling doc) explaining each suppression and its unblock condition, matching
the Rust baseline's discipline. Reconcile the suppression mechanism with the
tool CI invokes — if CI uses `npm audit`, move the ignores to a mechanism
`npm audit` honors, or switch the CI step to `pnpm audit` so the existing
config takes effect.

---

## 3. Verified clean — appendix

Checked and intentionally **not** flagged, with reason (saves the next audit
time).

| Item | Why it's not a finding |
|---|---|
| `deny.toml` license allow-list | Permissive-only; GPL banned with **no** `[licenses.exceptions]`; the former `poseidon-rs` GPL carve-out was removed after the `babyjubjub-permissive` swap. Tight and current. |
| `deny.toml` sources policy | `unknown-registry = "deny"`, `unknown-git = "deny"`, `allow-git = []`, only crates.io allowed. No git/path escape hatch. |
| `deny.toml` wildcard bans | `wildcards = "deny"` with `allow-wildcard-paths = true` correctly scoped — exempts unpublishable `path` crates (`publish = false`) only, still catches real `version = "*"`. |
| `cargo-audit-baseline.txt` | Best-in-repo: 20 advisories, each with dated rationale, blast radius, and concrete upstream unblock release; revalidated 2026-05-24; `cargo tree -i` confirmation noted per entry. |
| glib `RUSTSEC-2024-0429` | Not just suppressed — the fix from gtk-rs#1343 is backported in-tree (`variant_iter.rs`) and `[patch]`-wired; the ignore entry exists only because cargo-audit matches name+version and can't see the `[patch]`. (Provenance enforcement gap is M-SC-1, separate concern.) |
| `light-poseidon` / `circomlib` provenance | Both have committed `PROVENANCE.md` + pinned-SHA CI drift-check scripts (`light-poseidon-provenance`, `circomlib-provenance`). The model M-SC-1 asks glib to follow. |
| `src-tauri/build.rs` | Ceremony compile-time check (#1) is sound: pulls `artifacts.vkey.blake3` via untyped `serde_json::Value`, LF-normalizes before hashing (Windows/Linux parity), skips placeholders cleanly, panics with actionable messages, emits correct `rerun-if-changed`. |
| `cargo deny check bans licenses sources` (not `advisories`) | Deliberate and documented: advisory scanning is owned by `cargo audit`; running it twice is redundant and cargo-deny 0.16.4's bundled rustsec parser skews on newer DB entries. Correct division of labor. |
| `dependabot-pnpm-lockfile.yml` `pull_request_target` use | Safe: guarded by `github.actor == 'dependabot[bot]'` and a `--lockfile-only` install (no install-script execution), so it can't run arbitrary PR code with the elevated token. |
| `safe-jsonpath` shim | `proofs/safe-jsonpath` is a deliberate MIT in-repo replacement aliased over the insecure upstream `jsonpath`; Dependabot is explicitly told to ignore the `jsonpath` dependency-name (the `file:` path it can't resolve). Intentional and documented. |

---

## 4. Recommended sequencing

1. **M-SC-1** (glib provenance CI job) — closes the one shipped-binary
   provenance gap; ~1 new script + 1 CI job, mirrors existing pattern.
2. **L-SC-1 / L-SC-2 / L-SC-3** (prune Python/Go residue) — one small PR;
   removes recurring CI noise and a write-scoped always-failing scheduled job.
3. **M-SC-2** (audit all lockfiles) — small ci.yml change.
4. **L-SC-4 / L-SC-5** (JS lockfile refresh + documented suppressions) —
   hygiene; do alongside the next frontend dependency bump.

None of these block production; they harden provenance enforcement and clear
post-retirement drift.

---

## 5. Remediation status (this PR)

All seven findings were re-verified against current code and remain valid. The
fixes landed here are deliberately minimal.

| ID | Status | What changed |
|---|---|---|
| M-SC-1 | ✅ Fixed | Added `scripts/check_glib_upstream.sh` (downloads the published `glib-0.18.5` crate, diffs the whole tree, allows only the documented `variant_iter.rs` backport + the vendored-only `PROVENANCE.md`) and wired a `glib-provenance` CI job mirroring the light-poseidon/circomlib jobs. |
| M-SC-2 | ✅ Fixed | `ci.yml` now loops `cargo audit` over every tracked `Cargo.lock` (`git ls-files '*Cargo.lock'`) instead of naming two. |
| L-SC-1 | ✅ Fixed | Pruned the four stale Dependabot entries (`pip /`, `gomod /verifiers/go`, `gomod /services/sequencer-go`, `cargo /services/cdhs-smf-rust`). |
| L-SC-2 | ✅ Fixed | Deleted `.github/workflows/dependency-lock.yml` (compiled a non-existent `pyproject.toml` weekly with write scope). |
| L-SC-3 | ✅ Fixed | Removed the broken Python/venv/ruff steps from `copilot-setup-steps.yml`; Rust + Node setup retained. |
| L-SC-4 | 🟡 Partial | Aligned `app/public-ui` `packageManager` to `pnpm@11.1.2`. **Skipped** the `vite`↔`esbuild` lockfile refresh — it requires `pnpm install` + network and produces a large lockfile diff; it belongs in a dedicated dependency-bump PR (as the finding itself recommends), not this provenance-hardening change. |
| L-SC-5 | ⏭️ Skipped | Two blockers to a *minimal* fix: (1) `package.json` is JSON and can't carry the per-suppression rationale the Rust baseline has; (2) making the three suppressions effective requires a **policy decision** — switch the CI step from `npm audit` to `pnpm audit` (so `pnpm.auditConfig` is honored) vs. drop the inert config — which is owner's-call, not a mechanical edit. Flagged for follow-up. |
