# Plan (for review): `preview` release channel

**Status:** Shipped 2026-08-15. All four PRs from §12 landed as
[#1648](https://github.com/OlympusLedgerOrg/Olympus/pull/1648); the first tag
(`preview-v0.10.0-rc.1`) failed and was fixed by
[#1649](https://github.com/OlympusLedgerOrg/Olympus/pull/1649), then re-cut as
`preview-v0.10.0-rc.2`. `tauri-release.yml` is unchanged, as §3 requires. See
§13 for what differs from this plan, the three traps found, and the rc.1
postmortem.
**Scope:** A publicly downloadable, unmistakably non-production installer channel
built from a single-contributor development ceremony, with zero change to the
`v*` tag path.

---

## 0. Recommendation in one paragraph

Add a **separate `.github/workflows/tauri-preview.yml`** triggered only by
`preview-v*` tags and `workflow_dispatch`, and change `tauri-release.yml` **not at
all**. `preview-v0.10.0-rc.1` does not match the `v*` tag filter, so the
production workflow never fires for a preview tag and its nine
`startsWith(github.ref, 'refs/tags/')` guards keep their current meaning
untouched. `scripts/release-assets.mjs` needs **no channel parameter** — it treats
the tag as an opaque string. `.github/actions/zk-ceremony-artifacts` is
**sufficient unmodified**. The two things that genuinely need new code are (a) a
build-time channel stamp in the Rust crate, because **the app as it stands today
cannot be run by anyone who did not set four environment variables first**, and
(b) a preview Tauri config overlay that renames the product so the channel is
visible in the filename, the installed app name, and the window title.

---

## 1. What I read, and what is actually true

Files read: [`.github/workflows/tauri-release.yml`](../../.github/workflows/tauri-release.yml),
[`.github/actions/zk-ceremony-artifacts/action.yml`](../../.github/actions/zk-ceremony-artifacts/action.yml),
[`scripts/release-assets.mjs`](../../scripts/release-assets.mjs),
[`src-tauri/src/startup.rs`](../../src-tauri/src/startup.rs) (`verify_ceremony_manifests`
lives here now, not `main.rs`), plus `src-tauri/src/env.rs`, `src-tauri/src/main.rs`,
`src-tauri/tauri.conf.json`, `proofs/setup_circuits.sh`,
`.github/workflows/build-week-demo.yml`, `scripts/release-assets.test.mjs`,
`README.md`, `docs/index.html`, `app/public-ui/src/components/Layout.tsx`.

### 1.1 The blocking finding: today, *no* installer is runnable by a stranger

This is not preview-specific. It is equally true of a signed production tag build,
and it invalidates the acceptance criterion for every channel until it is fixed.

- [`src-tauri/src/env.rs:31`](../../src-tauri/src/env.rs:31) — `is_production()`
  fails closed: `OlympusEnv::Unset => true`. Unset, empty, and unrecognised
  `OLYMPUS_ENV` all mean production. This is deliberate and documented
  ([`docs/quickstart.md:44`](../quickstart.md:44)).
- The desktop binary never sets `OLYMPUS_ENV`. There is no dotenv loader in
  `src-tauri/src`, and `tauri.conf.json` sets no environment.
- [`src-tauri/src/main.rs:69`](../../src-tauri/src/main.rs:69) calls
  `run_preflight_checks` unconditionally in the Tauri `setup` hook, which calls
  `production_runtime_config_errors()`
  ([`startup.rs:683`](../../src-tauri/src/startup.rs:683)).
- In production that function requires **all four** of `OLYMPUS_ADMIN_KEY`,
  `OLYMPUS_BJJ_AUTHORITY_KEY`, `OLYMPUS_INGEST_SIGNING_KEY`,
  `OLYMPUS_REDACTION_BLIND_SECRET`
  ([`startup.rs:18-35`](../../src-tauri/src/startup.rs:18),
  [`:122-131`](../../src-tauri/src/startup.rs:122)) and `std::process::exit(2)`s if
  any is missing ([`startup.rs:689-702`](../../src-tauri/src/startup.rs:689)).

The repo's own test asserts exactly this behaviour:
`prod_runtime_config_missing_env_fails_closed`
([`startup.rs:1787`](../../src-tauri/src/startup.rs:1787)) — unset `OLYMPUS_ENV`
must produce the `OLYMPUS_ADMIN_KEY` / `OLYMPUS_BJJ_AUTHORITY_KEY` errors.

**Consequence:** a stranger double-clicks the MSI, the app installs, the process
starts, and dies with exit code 2 during the setup hook before the Axum server
ever binds. There is no window to read an error in. Shipping a preview installer
without addressing this ships a binary that cannot start.

This is why the plan contains a Rust change and is not purely a CI change.

### 1.2 Constraint 3 verified — and the trap in verifying it

**The property holds.** A preview binary run with an explicit
`OLYMPUS_ENV=production` still refuses to start on a dev ceremony:

- `apply_extra_prod_gates` gate A-4
  ([`startup.rs:541-557`](../../src-tauri/src/startup.rs:541)) pushes a hard
  reason when `manifest.ceremony_id.starts_with("olympus-dev-")` and `is_prod`.
- Gate A-2/H-04 ([`startup.rs:459-473`](../../src-tauri/src/startup.rs:459))
  additionally requires `MIN_PROD_CONTRIBUTORS = 3` *authenticated* contributors,
  and treats a missing/malformed `OLYMPUS_CEREMONY_TRUSTED_CONTRIBUTORS_JSON` as a
  hard failure in production.
- Gate A-3 ([`startup.rs:497-539`](../../src-tauri/src/startup.rs:497)) rejects a
  coordinator pubkey equal to the runtime bootstrap pubkey — which is what a
  single-contributor `setup_circuits.sh` ceremony produces by default.
- Any hard reason becomes an `Err` in `ManifestCheck`, increments
  `real_failures`, and `exit(2)`s
  ([`startup.rs:985-993`](../../src-tauri/src/startup.rs:985)).
- Existing unit test: `extra_prod_gates_prod_refuses_dev_ceremony_id`
  ([`startup.rs:1696`](../../src-tauri/src/startup.rs:1696)) — and it asserts
  *why* (`err.contains("A-4")`), not merely that it errored.

**The trap.** A naive acceptance test — "run the preview binary with
`OLYMPUS_ENV=production`, assert exit 2" — **passes for the wrong reason**. It
exits 2 at §1.1's missing-secrets gate, hundreds of lines before the ceremony
check. Such a test would still pass if A-4 were deleted. To prove the ceremony
gate you must supply four *valid* production secrets so preflight clears, and
reach bootstrap. See §9.

**Second-order note (out of scope, worth recording):**
`verify_ceremony_manifests` is called inside `if let Some(br) = bjj_result`
([`startup.rs:825`](../../src-tauri/src/startup.rs:825),
[`:943`](../../src-tauri/src/startup.rs:943)). If the database never comes up,
`bjj_result` is `None` and the ceremony gate is skipped entirely. Production
startup with a dead DB therefore does not exercise A-2/A-3/A-4. Not a preview
problem; flagging it because it shapes how the test in §9 must be written.

### 1.3 What already works on the non-tag path

More is already channel-aware than the brief assumes:

| Behaviour | Already non-tag-safe? | Evidence |
|---|---|---|
| Dev ceremony generation on dispatch | Yes | [`tauri-release.yml:93-95`](../../.github/workflows/tauri-release.yml:93) |
| 3-contributor minimum skipped off-tag | Yes | [`:152-166`](../../.github/workflows/tauri-release.yml:152) |
| Windows cert import | Tag-only, no throw off-tag | [`:363`](../../.github/workflows/tauri-release.yml:363) |
| macOS `APPLE_*` resolve to `''` off-tag | Yes, documented | [`:456-468`](../../.github/workflows/tauri-release.yml:456) |
| SBOM generation | Ungated — runs on dispatch | [`:583-598`](../../.github/workflows/tauri-release.yml:583) |
| `attest-build-provenance` | **Ungated** | [`:702-706`](../../.github/workflows/tauri-release.yml:702) |
| `attest-sbom` ×2 | **Ungated** | [`:707-717`](../../.github/workflows/tauri-release.yml:707) |
| `release-assets.mjs stage` | Ungated | [`:600-613`](../../.github/workflows/tauri-release.yml:600) |
| GitHub release create/upload/verify/publish | Tag-only | [`:622`](../../.github/workflows/tauri-release.yml:622), [`:673`](../../.github/workflows/tauri-release.yml:673), [`:687`](../../.github/workflows/tauri-release.yml:687), [`:719`](../../.github/workflows/tauri-release.yml:719) |

So constraint 5 (SBOM + attestation on preview) is *already* proven to work off-tag
— the attestation steps have no `if:` at all. The only genuinely missing piece on
the dispatch path is **publication**: assets land as 7-day, login-gated Actions
artifacts instead of a public prerelease. That is precisely the reachability gap
in the brief.

There is also working prior art for public prerelease publication in this repo:
[`build-week-demo.yml:143-190`](../../.github/workflows/build-week-demo.yml:143)
already creates a `--prerelease` GitHub release with checksums, and refuses to
refresh a release whose `targetCommitish` differs from `GITHUB_SHA`. Reuse that
refusal check.

---

## 2. Design decisions

### D1. Separate `tauri-preview.yml`, not a channel concept in `tauri-release.yml`

**Recommendation: separate workflow.** This is the option with the smallest blast
radius on the tag path, by a wide margin, and the argument is concrete rather than
stylistic.

*Why extending is worse than it looks.* `tauri-release.yml` expresses "this is a
production release" as `startsWith(github.ref, 'refs/tags/')` in **nine** places.
`refs/tags/preview-v0.10.0-rc.1` satisfies that predicate. So adding
`preview-v*` to `on.push.tags` does not add a channel — it routes preview tags
straight down the production path: Windows cert import throws (constraint 6
violated), the `olympus-dev-*` rejection fires (build fails), the
3-contributor minimum fires. Making it work means rewriting all nine guards from
"is a tag" to "is a production tag". Every one of those rewrites is an
opportunity to weaken the tag path, and reviewing the change means re-verifying
nine security-relevant predicates instead of zero.

*Why a separate workflow is nearly free.* `v*` is anchored at the start of the ref
name. `preview-v0.10.0-rc.1` starts with `p`. **`tauri-release.yml` needs zero
edits** — it simply never fires. Its guards keep their exact current semantics,
and the diff a reviewer must audit for "did this make a production tag easier to
cut" is empty.

*The real cost, stated honestly.* Duplication. A naive copy is ~600 lines that
will drift. Mitigate three ways:

1. **Do not duplicate the preflight test suite.** `tauri-release.yml`'s
   `preflight` job runs the full workspace/nextest/doctest battery
   ([`:171-201`](../../.github/workflows/tauri-release.yml:171),
   `timeout-minutes: 180`). Preview builds do not need it: `ci.yml` already gates
   the same commit. The preview preflight runs only what packaging depends on —
   dev ceremony generation, `verify_ceremony_bundle` **without**
   `--minimum-authenticated-contributors`, frontend build, and the ceremony-id
   assertion in §5. *Coverage given up:* a preview bundle is not backed by the
   release-grade native-host test legs. Acceptable for a channel whose entire
   point is that it is not production.

   This originally rested on two legs — avoiding drift-prone duplication, and
   keeping wall-clock under 40 minutes. Now that the timing target is soft
   (§11 D3), only the first leg carries weight. It still holds, and the
   recommendation is unchanged: duplicating ~150 lines of test invocations into a
   second workflow is the single most drift-prone thing this plan could do, and
   `ci.yml` already gates the same commit. If preview bundles later need
   release-grade backing, the right move is to make `tauri-release.yml`'s
   `preflight` a `workflow_call` target and invoke it — not to copy its steps.
2. **Extract two composite actions** used by both workflows, so the shared setup
   cannot drift: `.github/actions/setup-build-toolchain` (Rust 1.95.0 + pnpm +
   Node 22.14.0 + Linux deps + Windows OpenSSL) and
   `.github/actions/generate-sboms` (cargo-cyclonedx + pnpm sbom + the `jq -e`
   shape check). Both are lifted verbatim from `tauri-release.yml`; adopting them
   there is a **separate, later, no-behaviour-change PR** so the preview work
   lands without touching the release file at all.
3. **A tripwire test** asserting the two workflows' pinned action SHAs and
   toolchain versions agree, so drift fails CI rather than shipping.

*Rejected alternative:* `workflow_call`. The guard sets differ at nearly every
step; parameterising them reproduces the nine-predicate audit problem inside a
single file with worse readability.

### D2. Channel stamp via `build.rs`, not a cargo feature

The app needs a compile-time notion of "this is a preview build" to solve §1.1.
Two shapes were considered.

**Recommendation: an env var read at compile time in `src-tauri/build.rs`,**
emitting `OLYMPUS_RELEASE_CHANNEL` (default `stable`) and `OLYMPUS_PREVIEW_TAG`
(default empty) as `cargo::rustc-env`, with matching
`cargo::rerun-if-env-changed=` lines.

Why not a cargo feature:

- **A feature is a boolean; the requirement is a string.** Constraint 4 says
  someone who forgets where a build came from must still be able to tell. That
  means the binary should carry `preview-v0.10.0-rc.1` and the source commit, not
  just a "preview: yes" bit. A feature cannot carry the tag.
- **Feature-flag semantics are additive and get swept up.** No CI job today
  compiles `olympus-desktop`'s tests with `--all-features`, so this is latent
  rather than live — but `windows-ci.yml:120` already resolves the desktop crate
  with `cargo tree --all-features`, and `ci.yml:1459` runs `cargo deny
  --all-features` over the workspace. A feature whose effect is *relaxing a
  fail-closed default* is the wrong shape for a flag that anything might turn on
  by accident.

Semantics (the whole change to `env.rs`):

| `OLYMPUS_ENV` | `stable` channel | `preview` channel |
|---|---|---|
| `production` / `prod` | production | **production** (unchanged) |
| `development` / `dev` / `test` | development | development |
| unset / empty / unrecognised / non-UTF-8 | **production** (unchanged) | development |

Only the last row differs, and only for preview binaries. Constraint 3 is
preserved verbatim: an explicit `OLYMPUS_ENV=production` on a preview binary is
still production, still hits A-4, still `exit(2)`s. The "fail closed on garbage"
property is retained for stable builds exactly as written.

Guards that keep this honest:

- A unit test asserting `RELEASE_CHANNEL == "stable"` when the env var is unset
  (i.e. every ordinary developer build and every `v*` tag build).
- A unit test asserting `is_production()` is `true` for `OLYMPUS_ENV=production`
  **under the preview channel** — the direct expression of constraint 3.
- `tauri-preview.yml` is the only place in the repo that sets
  `OLYMPUS_RELEASE_CHANNEL`. A grep-based tripwire in `ci.yml` asserts that.

### D3. Identity: rename the product, do not decorate the version

Preview installers must self-identify in the filename. `release-assets.mjs`
derives asset names as `` `${target}--${sourceName}` ``
([`release-assets.mjs:207`](../../scripts/release-assets.mjs:207)), where
`sourceName` comes from Tauri's bundler, which builds it from `productName` and
`version` in `tauri.conf.json`.

**Decided: change `productName` and `identifier`, keep `version` numeric.**

```jsonc
// src-tauri/tauri.preview.conf.json — overlay, applied with --config
{
  "productName": "Olympus Ledger Preview",
  "identifier": "io.olympus.ledger.preview",
  "app": { "windows": [{ "label": "main", "title": "Olympus Ledger Preview — NOT FOR PRODUCTION" }] }
}
```

This uses the overlay pattern already proven in this repo for Windows signing
([`tauri-release.yml:436-448`](../../.github/workflows/tauri-release.yml:436)
writes `tauri.windows-signing.conf.json` and
[`:473`](../../.github/workflows/tauri-release.yml:473) passes it via `--config`),
so the mechanism is not novel here.

It buys four things at once:

- **Filename:** `Olympus Ledger Preview_0.10.0_x64_en-US.msi` → staged as
  `x86_64-pc-windows-msvc--Olympus Ledger Preview_0.10.0_x64_en-US.msi`.
- **Installed app name** in Start menu / Applications / `.desktop`.
- **Window title**, visible before the server binds — the one identification
  surface that works even if startup fails.
- **A distinct `app_data_dir`.** Tauri derives it from `identifier`, so a preview
  install gets its own embedded-PostgreSQL directory and cannot collide with a
  future production install on the same machine. Preview data does not migrate
  forward — correct behaviour, and consistent with the existing
  `PRE_V1_NOTICE` wording ("development databases are disposable").

A separate `identifier` means **no upgrade path** from a preview install to a
production one: different app-data dir, so the preview's embedded PostgreSQL
cluster and every record in it stay behind when the user installs v1. That is the
intended outcome — a dev-ceremony database is not something to carry forward — and
it is already what the `PRE_V1_NOTICE` promises. It also means a user can keep
both installed side by side during the transition, which makes the retirement in
§10 gentler: nothing has to be uninstalled for the real build to work.

**Must verify before implementing:** Tauri's WiX/MSI bundler requires a numeric
`major.minor.patch` product version and is expected to reject a semver prerelease
suffix such as `0.10.0-preview.1`. That is why the channel rides on
`productName` rather than `version`. Confirm with one throwaway Windows build
before committing to it; if MSI in fact accepts the suffix, adding it is a bonus,
not a substitute.

---

## 3. Guard conditions, per job and step

### `tauri-release.yml` — **unchanged, and provably so**

The diff is empty. The invariant argument is a two-liner a reviewer can check
without reading the file: `on.push.tags` is `["v*"]`; the preview ref is
`refs/tags/preview-v*`; `v*` is anchored, `preview-v…` does not start with `v`;
therefore the workflow does not trigger, therefore none of its nine
`startsWith(github.ref, 'refs/tags/')` guards are evaluated in a preview run.

Backstop (belt and braces, added in the preview PR): a first step in
`tauri-preview.yml` that hard-fails if `github.ref` matches `refs/tags/v*`, so
even a future edit to the preview trigger cannot let a production tag through the
preview path.

### `tauri-preview.yml` — new

```yaml
on:
  push:
    tags: ["preview-v*"]
  workflow_dispatch:
    inputs:
      publish:
        description: "Publish a public prerelease (otherwise artifacts only)"
        type: boolean
        default: false
      preview_tag:
        description: "Prerelease tag when publishing from a dispatch"
        type: string
        default: ""
concurrency:
  group: tauri-preview-${{ github.ref }}
  cancel-in-progress: true
permissions:
  contents: read
```

| Job / step | Guard | Rationale |
|---|---|---|
| **`guard`** (first job) | none | Fails if `startsWith(github.ref, 'refs/tags/v')` — a `v*` tag must never reach this workflow — or if a tag ref is not `preview-v*`. Also resolves and validates the preview tag. Channel *containment* is enforced by `scripts/check-preview-channel.mjs` in `pnpm tooling:check`, not here. |
| `preview-preflight` → committed-ceremony tripwire | none | §10: fails once the real ceremony lands. Runs **before** `zk-ceremony-artifacts`. |
| `preview-preflight` → `zk-ceremony-artifacts` | none | Always; this workflow has no other artifact source. |
| `preview-preflight` → ceremony-id **positive** assertion | none | §5: every manifest's `ceremony_id` **must** start with `olympus-dev-`. Mirror-image of [`tauri-release.yml:130`](../../.github/workflows/tauri-release.yml:130). |
| `preview-preflight` → `verify_ceremony_bundle` | none | Run **without** `--minimum-authenticated-contributors`. The flag is production-only by construction. |
| `build` matrix | none | Same four targets. `OLYMPUS_RELEASE_CHANNEL=preview` and `OLYMPUS_PREVIEW_TAG` in this job's `env:` — **job-scoped, not workflow-scoped**. At workflow level it would also stamp the preflight's test binary, and the preflight runs the tests that assert the *stable* default; they would fail on the channel they exist to protect. |
| Windows cert import | **omitted entirely** | Not present in the file → cannot throw. Constraint 6 by absence, not by condition. |
| Windows signature verification | **omitted entirely** | Nothing to verify. |
| `tauri-action` `APPLE_*` | literal `''` | Same mechanism as [`:456-468`](../../.github/workflows/tauri-release.yml:456); tauri-action skips `security import` on empty and emits an unsigned bundle. |
| `tauri-action` `args` | `--target … --config src-tauri/tauri.preview.conf.json` | D3 overlay. Never the Windows signing overlay. |
| `provenance` → SBOMs | none | Constraint 5. |
| `provenance` → `release-assets.mjs stage` | none | Unmodified; §4. |
| `provenance` → `attest-build-provenance` | none | Constraint 5. |
| `provenance` → `attest-sbom` ×2 | none | Constraint 5. |
| `provenance` → publish prerelease | `startsWith(github.ref,'refs/tags/preview-v') \|\| inputs.publish` | Tag push publishes; dispatch publishes only on explicit opt-in, matching [`build-week-demo.yml:145`](../../.github/workflows/build-week-demo.yml:145). |
| publish step body | — | `gh release create --prerelease --target "$GITHUB_SHA"`, and the `targetCommitish != GITHUB_SHA` refusal from [`build-week-demo.yml:174-178`](../../.github/workflows/build-week-demo.yml:174). |

`--prerelease` matters beyond cosmetics: GitHub never promotes a prerelease to
"Latest release", so `/releases/latest` and every tool that follows it keep
pointing at nothing (or, later, at the real v1) rather than at a preview.

---

## 4. `scripts/release-assets.mjs` — works unmodified

**No channel parameter needed.** Evidence:

- `stageReleaseAssets` validates the tag with exactly `if (!tag) throw new
  Error("release tag/ref must not be empty")`
  ([`:189`](../../scripts/release-assets.mjs:189)). Otherwise it is an opaque
  string written into `manifest.releaseTag` and compared on the way back out
  ([`:269-273`](../../scripts/release-assets.mjs:269)).
- `TARGETS` ([`:23-52`](../../scripts/release-assets.mjs:23)) is keyed on Rust
  target triple. Signing state is not part of the contract, and unsigned MSI /
  NSIS / DMG / deb / AppImage / rpm are all still produced, so
  `validateInstallerCoverage`'s "exactly one of each required type" holds.
- `safeAssetName` ([`:124-139`](../../scripts/release-assets.mjs:124)) rejects
  path separators and control characters. `Olympus Ledger Preview_0.10.0_x64_en-US.msi`
  contains a space, which is permitted — spaces are already present in today's
  `Olympus Ledger_…` names, so this is not new.
- `release-assets.test.mjs` binds a fixture tag and asserts a mismatch throws
  ([`:180-184`](../../scripts/release-assets.test.mjs:180)) — the tag is data, not
  a validated format.

**One thing to add, in the test file only:** a case staging and verifying under a
`preview-v0.10.0-rc.1` tag, so the claim "works unmodified" is asserted rather
than assumed. Zero production-code change.

*Deliberately not doing:* teaching the manifest a `channel` field. It would be a
second source of truth for something the tag and `productName` already carry, and
`RELEASE_ASSETS.json` is consumed by `scripts/verify-release.sh`, which would then
need a matching change for no verification gain.

---

## 5. Dev ceremony artifacts in CI

**`.github/actions/zk-ceremony-artifacts` is sufficient unmodified.**

- [`proofs/setup_circuits.sh:590`](../../proofs/setup_circuits.sh:590) —
  `CEREMONY_ID="${OLYMPUS_CEREMONY_ID:-olympus-dev-$(date -u +%Y-%m-%d)}"`. The
  default is already the `olympus-dev-` marker the A-4 gate keys on, so the action
  produces exactly the dev ceremony the preview channel wants, with no argument.
- The action's final step already verifies all four circuits' artifacts exist and
  are non-placeholder
  ([`action.yml:205-236`](../../.github/actions/zk-ceremony-artifacts/action.yml:205)).
- Its cache restores previously generated dev artifacts, which are still
  `olympus-dev-*`, so a cache hit does not change the channel property.

**Two additions, both in the workflow rather than the action** (the action stays
shared with the dispatch path and should not grow preview-specific policy):

1. **Positive ceremony-id assertion** — the mirror image of the tag path's
   rejection. For each of the three production circuits, assert
   `jq -er '.ceremony_id'` **does** start with `olympus-dev-`, and fail otherwise.
   This is what makes the preview channel structurally incapable of shipping a
   build that looks production, and it is the retirement tripwire in §10.
2. **`OLYMPUS_CEREMONY_ID` must be unset** in this workflow's environment, since
   setting it would override the dev default and defeat (1). Assert it rather
   than merely omitting it.

*Cost note:* on a cold ceremony cache the action fetches a 1.15 GB ptau and runs
the full Groth16 setup — roughly 10–20 minutes. Warm, it is a cache restore. This
dominates the variance in §11's timing estimate.

---

## 6. Version / naming scheme, and where it surfaces

| Surface | Value | Source |
|---|---|---|
| Git tag | `preview-v0.10.0-rc.1` | operator |
| `productName` | `Olympus Ledger Preview` | `tauri.preview.conf.json` |
| `identifier` | `io.olympus.ledger.preview` | `tauri.preview.conf.json` |
| `version` | `0.10.0` (unchanged, numeric) | `tauri.conf.json` |
| Installer filename | `x86_64-pc-windows-msvc--Olympus Ledger Preview_0.10.0_x64_en-US.msi` | bundler + `release-assets.mjs:207` |
| Window title | `Olympus Ledger Preview — NOT FOR PRODUCTION` | overlay |
| Release title | `Olympus Ledger 0.10.0 preview (rc.1) — NOT FOR PRODUCTION` | workflow |
| Release badge | GitHub amber `Pre-release` | `--prerelease` |
| Binary stamp | `RELEASE_CHANNEL=preview`, `PREVIEW_TAG=preview-v0.10.0-rc.1` | `build.rs` |

**UI surface.** [`Layout.tsx:19`](../../app/public-ui/src/components/Layout.tsx:19)
already defines `PRE_V1_NOTICE` and renders it at
[`:191`](../../app/public-ui/src/components/Layout.tsx:191). That is the right
home. Add a channel chip beside it, and extend the notice text when the channel is
`preview`.

Feed it from **one** source: the Rust const, exposed on the existing `/health`
route ([`server/mod.rs:298`](../../src-tauri/src/server/mod.rs:298)) as
`{"channel": "...", "preview_tag": "...", "commit": "..."}`. Do **not** also bake
it into the frontend via a Vite define — two sources drift, and only the Rust one
is bound to the binary that carries the ceremony artifacts.

`/health` is shared with the Tor-facing router
([`server/mod.rs:371`](../../src-tauri/src/server/mod.rs:371)), whose handler
comment notes it deliberately returns generic status only. Channel and short
commit are already-public build metadata, so adding them is fine — but confirm
against that handler's intent during review rather than assuming.

Coverage of constraint 4, for someone who has forgotten where the file came from:
filename ✓ (on disk), installed app name ✓ (Start menu), window title ✓ (works
even if the server never binds), in-app chip ✓ (once running), release body ✓.

---

## 7. Unsigned bundles, and the release-body copy

Constraint 6 is satisfied structurally: the cert import step does not exist in
`tauri-preview.yml`, so there is nothing to throw. macOS `APPLE_*` are passed as
literal `''`, which `tauri-action` already treats as "skip signing" — the
behaviour is documented in the existing comment at
[`tauri-release.yml:456-463`](../../.github/workflows/tauri-release.yml:456).

Draft release body (`.github/preview-release-body.md`, rendered with the tag and
commit substituted):

```markdown
# Olympus Ledger — PREVIEW BUILD. NOT FOR PRODUCTION USE.

Built from a **single-contributor development trusted setup**. The multi-party
ceremony has not happened yet. Proofs produced by this build carry no soundness
guarantee: whoever holds the setup's toxic waste could forge them.

Do not use this to record evidence you intend to rely on. Databases created by a
preview build are disposable and will not carry across to v1.

- Channel: `preview` · Tag: `TAG` · Commit: `SHA`
- Ceremony: `olympus-dev-*` (single contributor)
- Code signing: **none** on Windows and macOS (see below)
- This build refuses to start under `OLYMPUS_ENV=production` — by design.

## Install

### Windows
Download the `.msi` (or `.exe` NSIS installer). SmartScreen will warn that the
publisher is unknown, because these binaries are unsigned.
Click **More info** → **Run anyway**.

### macOS
Download the `.dmg` for your architecture (`aarch64` for Apple Silicon,
`x86_64` for Intel). Gatekeeper will refuse it as "damaged" or from an
unidentified developer, because these binaries are neither signed nor notarized.

Clear the quarantine attribute, then open it:

    xattr -cr "/Applications/Olympus Ledger Preview.app"

Then right-click the app → **Open** → **Open** in the dialog. A plain
double-click will not offer the override.

### Linux
Download the `.deb`, `.rpm`, or `.AppImage`. The AppImage needs the executable
bit:

    chmod +x x86_64-unknown-linux-gnu--Olympus*.AppImage

## Verify what you downloaded

Checksums, and GitHub build provenance + SBOM attestations, are attached.

    sha256sum -c SHA256SUMS
    gh attestation verify <installer> --repo OlympusLedgerOrg/Olympus

`scripts/verify-release.sh --level 3` runs the layered check.

## Reporting

Preview-build issues are welcome: https://github.com/OlympusLedgerOrg/Olympus/issues
```

The `xattr -cr` path and the right-click→Open path are both listed because
neither alone is sufficient on current macOS: clearing quarantine handles the
"damaged" case, the right-click override handles the unidentified-developer case.

---

## 8. README and landing-page copy

Today `README.md` contains **no download link and no install section at all** —
the word "download" does not appear. [`README.md:71`](../../README.md:71) says
"The desktop app is live", and the landing page's primary CTA
([`docs/index.html:696`](../index.html:696)) is "Evidence workflow", pointing at
`docs/court-evidence.md`. Neither leads to a binary.

Changes, all copy-only:

**`README.md` — new "Download" section immediately after "Current status".**

```markdown
## Download

Preview builds are available for Windows, macOS, and Linux:

**[Download the latest preview →](https://github.com/OlympusLedgerOrg/Olympus/releases)**

> **Preview builds are not production software.** They are built from a
> single-contributor development trusted setup, so their proofs carry no
> soundness guarantee, and they are unsigned (expect a SmartScreen or Gatekeeper
> warning — the release page has the exact commands). Records committed with a
> preview build are disposable.

Production builds ship after the multi-party trusted-setup ceremony. See
[`ROADMAP.md`](docs/ROADMAP.md).
```

**`README.md:71`** — "The desktop app is live." → "The desktop app is live and
downloadable as a **preview build** (see Download above); production builds are
gated on the ceremony." The current sentence is the one an evaluator acts on, and
it currently over-promises relative to what is reachable.

**`docs/index.html`** — add a second primary CTA in the hero beside "Evidence
workflow" ([`:696`](../index.html:696)): `Download preview →`, with a small
`Pre-v1 · unsigned · not for production` caption **directly under the button**.
Per the brief, the pre-v1 status must be stated at the download, not only in the
README, so the caption is part of the button block, not a footnote.

Also update the "Where to start" block
([`:984`](../index.html:984)) so the developer path lists the download ahead of
build-from-source.

**Deliberately not changing:** the four-claims copy and the comparison table.
Nothing there becomes false; only the reachability of a binary changes.

---

## 9. Verification plan — tests that prove what their names say

Per the repo's own pre-push discipline: negative tests must assert *why* they
rejected, and a test must be able to fail if the property it names is removed.

**T1 (unit, exists — cite, do not rewrite).**
`extra_prod_gates_prod_refuses_dev_ceremony_id`
([`startup.rs:1696`](../../src-tauri/src/startup.rs:1696)). Already asserts
`err.contains("A-4")`. Proves A-4 rejects `olympus-dev-*` under `is_prod`.

**T2 (unit, new).** `preview_channel_keeps_explicit_production_production` —
with the channel const forced to `preview`, `OLYMPUS_ENV=production` still yields
`is_production() == true`. This is constraint 3 expressed directly. Use the
existing `with_olympus_env` guard ([`env.rs:80`](../../src-tauri/src/env.rs:80))
so the env mutation is serialised.

**T3 (unit, new).** `release_channel_defaults_to_stable` — with
`OLYMPUS_RELEASE_CHANNEL` unset at build time, the const is `stable` and unset
`OLYMPUS_ENV` still means production. Guards against the preview default leaking
into ordinary builds and `v*` tags.

**T4 (integration, new — the one that earns the claim).** Stage the *actual
CI-generated dev manifests* into a temp proofs dir and call
`verify_ceremony_manifests(dir, &trusted, /* is_prod */ true, Some(&bootstrap))`
directly; assert every `ManifestCheck.result` is `Err` and that the joined
reasons cite `A-4`. Calling the function directly rather than launching the
packaged binary sidesteps the §1.2 trap **and** the §1.2 second-order note (the
gate is skipped entirely when the DB does not come up), and it is deterministic
on every runner.

**T5 (smoke, new).** Launch the packaged preview binary with
`OLYMPUS_ENV=production` **and four valid production secrets set**, assert exit
code 2 and that stderr contains the ceremony-manifest FATAL banner from
[`startup.rs:987`](../../src-tauri/src/startup.rs:987). Without the four secrets
this test passes at the §1.1 gate and proves nothing — put that reason in a
comment next to the fixture so nobody "simplifies" it later.

**T6 (smoke, new).** Launch the packaged preview binary with **no** environment
at all; assert it starts, binds, and `/health` reports `"channel":"preview"`.
This is the acceptance criterion for the stranger, and it is the test that fails
today for every existing bundle.

**T7 (script).** `release-assets.test.mjs` case under a `preview-v*` tag (§4).

Docker is available locally, so T4/T5/T6 for the Linux target can be rehearsed in
the existing `docker/Dockerfile.zk-setup` container before pushing a preview tag —
worth doing once, since a failed preview tag burns a full matrix build.

---

## 10. What breaks when the real ceremony lands, and how preview retires

**It does not retire itself by accident, and that is a design problem to solve up
front.** After the real ceremony, `zk-ceremony-artifacts` still runs
`setup_circuits.sh` on a cache miss and still restores dev artifacts on a hit,
overwriting the committed real ones in the runner workspace. So the §5 positive
assertion would keep passing and the preview channel would keep shipping
dev-ceremony builds indefinitely, silently, after they stopped being the best
thing available.

**Fix: assert on the committed tree, before the ceremony action runs.** The first
step of `preview-preflight` reads the **git-tracked** manifests
(`proofs/keys/manifests/*_manifest.json`) and fails if any `ceremony_id` is *not*
`olympus-dev-*`:

```
::error::Committed ceremony is no longer a development ceremony
(document_existence: olympus-mainnet-2026Q4). The preview channel is obsolete —
cut a v* tag and delete .github/workflows/tauri-preview.yml. See
docs/plans/preview-release-channel.md §10.
```

That turns "the ceremony landed" into an immediate, self-explaining CI failure on
the next preview run, instead of a slow drift into shipping the wrong thing.

**Retirement checklist**, once a `v*` tag is cuttable:

1. Delete `.github/workflows/tauri-preview.yml` and
   `src-tauri/tauri.preview.conf.json`.
2. Remove the `preview` arm from `env.rs`'s channel table and the `build.rs`
   stamp; keep `RELEASE_CHANNEL` only if the `/health` field is worth retaining
   as `stable` (recommended — the field is useful and removing it is a breaking
   API change for anything that started reading it).
3. Keep `.github/actions/setup-build-toolchain` and `generate-sboms` — by then
   `tauri-release.yml` should be using them too.
4. Remove T2/T4/T5/T6; keep T1 and T3.
5. **Do not delete the published preview releases** — the links will be in
   grant applications, issue threads, and mailing lists. Edit each body to
   prepend a deprecation banner pointing at the production release. Deleting them
   converts a stale download into a 404, which is worse for an evaluator.
6. README: replace the Download section's preview language with the production
   release link; revert `README.md:71` to a plain "The desktop app is live."
7. `docs/index.html`: retarget the download CTA and drop the pre-v1 caption.

**Also breaks, and should be expected:** the §5 positive assertion and T4 both
fail the moment real manifests are committed, by design. T5 fails too — a real
ceremony under `OLYMPUS_ENV=production` should *not* exit 2. All three failing
together is the signal that retirement is due, not a regression to patch around.

---

## 11. Costs, risks, and open questions

**Timing: warm ~25–40 minutes, cold 60–90.** The four-target Tauri matrix plus
`cargo install tauri-cli`
([`tauri-release.yml:354`](../../.github/workflows/tauri-release.yml:354)) is the
floor. Cold means the first preview run, any `Cargo.lock` change, or a
ceremony-cache key rotation. Per §11 D3 the 40-minute figure is a target, not a
requirement, so no optimisation work is scheduled. If it later becomes annoying,
the cheapest lever is caching the `tauri-cli` binary instead of `cargo
install`-ing it on all four legs; the second is a warm-cache priming run on `main`.

**Risks, ranked:**

1. **§1.1 is a bigger change than the brief anticipates.** It touches
   `env.rs`, which is a fail-closed security primitive. It must land as its own
   small, heavily-tested PR, reviewed on its own merits, before anything
   CI-shaped.
2. **MSI numeric-version constraint (D3) is unverified.** Mitigated by putting
   the channel in `productName`, which is not subject to it — but confirm with a
   throwaway Windows build.
3. **`/health` shape change touches the Tor-facing router.** Low risk (build
   metadata is public) but the handler's comment says "generic status only", so it
   is a deliberate decision, not an oversight to wave through.
4. **Workflow drift between the two files.** Mitigated by the composite actions
   and the pin-agreement tripwire (D1.2, D1.3), not eliminated.
5. **An evaluator uses a preview build for real evidence anyway.** Mitigated by
   five independent identification surfaces (§6) plus the disposable-data notice —
   but it cannot be prevented, only made hard to do accidentally.

**Decisions (2026-08-14):**

- **D1. Separate bundle identifier — yes.** `io.olympus.ledger.preview`, product
  name `Olympus Ledger Preview`. Consequences in §D3: distinct app-data dir, no
  forward migration of preview records, side-by-side install with a future
  production build.
- **D2. Ship all four targets.** Windows, both macOS architectures, Linux. The
  Gatekeeper documentation burden in §7 is therefore in scope for the first cut,
  and the `xattr -cr` / right-click→Open copy is required, not optional. macOS is
  the platform whose users are most likely to be the ones this project is for.
- **D3. The 40-minute figure is a target, not a requirement.** No timing
  optimisation is scheduled. Its main downstream effect is on D1.1 — see the note
  there; the reduced preview preflight stays, on the anti-duplication argument
  alone.

**Still open (repo-settings question, not a design question):** whether
`preview-v*` tags should be protected so only a maintainer can cut one. Worth
deciding before PR 3 lands, but it does not block any of the four PRs.

---

## 12. Suggested PR sequence

Four PRs, each independently reviewable and revertible. Nothing in PR 1–3 makes a
production tag easier to cut; PR 4 is the only one that publishes anything.

1. **`env.rs` channel stamp** — `build.rs` env plumbing, `RELEASE_CHANNEL` /
   `PREVIEW_TAG` consts, the one-row change to `is_production()`, T2 + T3.
   Defaults to `stable`, so this PR changes no observable behaviour on its own.
2. **Identity + UI surface** — `tauri.preview.conf.json`, `/health` channel
   fields, the `Layout.tsx` chip, T7. Still publishes nothing.
3. **`tauri-preview.yml`** — the workflow, the two composite actions, the §5
   assertions, the §10 committed-ceremony tripwire, T4 + T5 + T6. First PR that
   can produce a public prerelease; land it with `publish` defaulted to `false`
   and exercise it via dispatch before tagging.
4. **Copy** — README Download section, `README.md:71`, `docs/index.html` CTA.
   Land last, so the CTA never points at a page that does not exist yet.

---

## 13. Implementation notes (2026-08-14)

### What shipped

All four PRs landed as one squash merge, [#1648](https://github.com/OlympusLedgerOrg/Olympus/pull/1648)
(`f9851fad`), including the copy changes. The original advice was to hold the
copy until a preview release existed; it merged with the rest on the reasoning
that `/releases` is not a 404 — it already lists two releases — so the CTA is
briefly *ahead of itself* rather than broken, and the tag was cut minutes later.
If the preview channel ever goes dark for longer than a pipeline run, revert the
Download section rather than leaving a promise the releases page cannot keep.

`.github/workflows/tauri-preview.yml` is on `main`, so `workflow_dispatch` is
now available as a dry run (`-f publish=false`) for any change to the channel.

### Two things that differ from the plan as written

- **The channel is exercisable without a rebuild.** §D2 described a build-time
  const feeding `is_production()`. The implementation additionally splits out
  `is_production_on(channel, env)`, so both channels are tested from an ordinary
  `cargo test` rather than only from a binary rebuilt with
  `OLYMPUS_RELEASE_CHANNEL=preview`. T2/T3 exercise the preview arm on a stable
  build.
- **The drift tripwire is a script, not a workflow job.** §D1.3 proposed a
  "pin-agreement job". It landed as `scripts/check-preview-channel.mjs`
  (+ `.test.mjs`, 13 tests), wired into `pnpm tooling:check`, and it carries
  three checks rather than one:
  1. **Containment** — `OLYMPUS_RELEASE_CHANNEL` may appear only in
     `tauri-preview.yml`, `build.rs`, and `env.rs`, so it cannot leak into a
     workflow where a `v*` tag build or a test job would see it.
  2. **Pin agreement** — where the two workflows pin the same third-party action
     or toolchain version, the pins must match.
  3. **No expressions in action metadata** — added after it cost a pipeline; see
     the rc.1 postmortem below.

### Three traps found while implementing, worth remembering

- **`startup.rs` is a `main.rs` module, not a `lib.rs` one.** `cargo test --lib`
  contains no startup tests at all, and libtest exits 0 when a filter matches
  nothing — so the first draft of the T4 workflow step ran zero tests and passed.
  The step now uses `--bin olympus-desktop` and greps for `1 passed`.
- **The channel stamp must be job-scoped, not workflow-scoped.** The first draft
  set `OLYMPUS_RELEASE_CHANNEL: preview` at workflow level, which would also
  stamp the preflight's *test* binary. The preflight runs
  `release_channel_defaults_to_stable` and `unset_env_fails_closed_to_production`
  — the tests that assert the stable default — so they would have failed on the
  channel they exist to protect. It now lives in the `build` job's `env:` only,
  which is also where it belongs semantically: the stamp matters for the binary
  that gets bundled, not for anything the preflight compiles.
- **`check-privileged-action-pins.mjs` requires literal toolchain versions.**
  The shared composite action originally took `rust-toolchain` / `node-version`
  as inputs; the pin checker cannot see through `${{ inputs.* }}` and failed.
  They are now literals in the action, which is the correct posture anyway —
  they are a reviewed security pin, not a knob.

### Postmortem: `preview-v0.10.0-rc.1` (2026-08-15)

The first preview tag failed in four seconds, in `preflight`, at "Setup build
toolchain":

```
.github/actions/setup-build-toolchain/action.yml (Line: 2, Col: 14):
Unrecognized named-value: 'inputs'. Located at position 1 within expression: inputs.*
```

Line 2 is the `description:` field. The trap immediately above this section —
"`check-privileged-action-pins.mjs` requires literal toolchain versions" — was
written up *inside that description*, and the sentence explaining that the
versions were literals "rather than a `${{ inputs.* }}` indirection" contained
live expression syntax. **The runner evaluates expressions in action metadata**,
so a comment about an expression was parsed as one, and the manifest failed to
load before any step ran.

Three things worth extracting:

- **Prose in an Actions manifest is not inert.** `name`, `description`, and every
  input/output `description` are template strings. This is the rare case where
  documenting a decision *caused* the defect it documented.
- **Nothing local could have caught it.** The YAML is valid, so `js-yaml` parsed
  it and prettier formatted it; the file passed every gate in
  `pnpm tooling:check` and the whole PR CI suite. The defect exists only for the
  runner's template evaluator, at execution time.
- **The job ordering held.** `guard` passed, `preflight` failed, and the publish
  step is four jobs downstream — so rc.1 published nothing. That is the property
  §3 was designed for, confirmed by accident rather than by the dry run.

Fixed in [#1649](https://github.com/OlympusLedgerOrg/Olympus/pull/1649)
(`7f73fb8a`): reworded, plus `checkActionMetadataExpressions` in the tripwire,
which scans metadata fields of every local composite action and deliberately
does **not** scan `steps:`, where expressions are legal and necessary. One of
its three tests reintroduces the exact string that killed rc.1.

Re-cut as `preview-v0.10.0-rc.2`. `rc.1` is left in place as honest history: it
produced no artifacts and no release.

**Method note.** `gh run watch --exit-status` exited 0 on the failed run; the
verdict is `gh run view <id> --json conclusion`. A watcher's exit code is not the
run's conclusion.

### Postmortem: `preview-v0.10.0-rc.2` (2026-08-15)

rc.2 got much further and split the risk list cleanly in two:

**Retired.** `guard` and the full `preflight` passed — dev ceremony generated,
the positive `olympus-dev-*` assertion held, the ceremony-refusal test ran and
counted. **Windows and Linux built**, and both passed the installer-name
assertion: WiX accepted the renamed `Olympus Ledger Preview` product, which was
the plan's single biggest must-verify (§D3). Those questions are now answered by
a real run, not an assumption.

**Failed.** Both macOS legs, identically:

```
failed to bundle project: failed codesign application:
failed to run command security import: failed to import keychain certificate
```

Root cause: the build step set `APPLE_CERTIFICATE` (and siblings) to `""`.
tauri-action's JS wrapper skips signing on an empty string — but the Rust
bundler independently reads the variable via `var_os("APPLE_CERTIFICATE")`, and
`var_os` returns `Some("")` for a set-but-empty variable. The bundler entered
the certificate-import branch with zero-byte cert material. **Set-but-empty is
not unset**, and the two halves of the toolchain disagree about which one means
"don't sign".

Fixed in [#1652](https://github.com/OlympusLedgerOrg/Olympus/pull/1652) by
removing the five env vars entirely; their absence is now documented in-place as
load-bearing. Re-cut as `preview-v0.10.0-rc.3`.

**Latent finding for `tauri-release.yml`, flagged not fixed:** its macOS env
uses `${{ … && secrets.X || '' }}`, which resolves to the same set-but-empty
state on `workflow_dispatch` runs — so its comment's claim that dispatch builds
emit an unsigned macOS bundle is contradicted by rc.2's evidence. The tag path
(real secrets) is unaffected, the release workflow keeps its zero-line diff per
the prime constraint, and the preview channel now serves the unsigned-bundle
use case the dispatch path was carrying.

### Verified locally

`cargo fmt --all --check` (root and `verifiers/rust`) · `cargo clippy -p
olympus-desktop --no-default-features --features prover --all-targets -D
warnings` · `cargo test -p olympus-desktop … --lib -- env::tests` (10 passed) ·
`… --bin olympus-desktop -- --exact startup::tests::embedded_ceremony_manifests_are_dev_and_refused_in_production`
(1 passed) · `pnpm --filter public-ui test:run` (587 passed) · `tsc -b` ·
`eslint . --max-warnings 0` from inside `app/public-ui` · `pnpm --filter
public-ui build` · `node --test scripts/release-assets.test.mjs` (8 passed) ·
`node --test scripts/check-preview-channel.test.mjs` (13 passed) ·
`pnpm format:prettier:check` · `pnpm license:headers` · `pnpm
release-actions:check`.

**Not verified locally, and unverifiable on Windows:** the four-target Tauri
build, whether the MSI bundler accepts the renamed product, the exact installer
filenames the self-identification step matches against, and the workflow itself.
Only a real run exercises these — rc.1 proved the point by failing on something
no local gate could see.

Now that the workflow is on `main`, the cheap way to exercise a change to it is
a dispatch dry run, which stages and validates the full asset set without
publishing:

```bash
gh workflow run tauri-preview.yml --ref main -f publish=false
```
