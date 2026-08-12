---
name: claim-verification
description: >
  Turns a vague status/readiness/"is X true" question about Olympus into a
  checklist of specific, independently-verifiable claims, checks each one
  against the actual repo (code, tests, CI, docs), and reports a verdict per
  claim with a file:line or test-name citation — never a single confident
  paragraph. Explicitly lists what could not be verified as a Gap instead of
  guessing. Use for: "are we ready for X", "is Olympus ready for an external
  audit", "does PR #NNNN actually fix Y", "is this documented behavior still
  true", "what's left before we can ship Z", or any question whose honest
  answer is "it depends, some parts yes, some parts no, and here's what I
  couldn't check." Do NOT use for questions with a single unambiguous
  factual answer (use direct search/read for those) or for writing new code
  (use olympus-dev-standards). Formalizes the discipline already required by
  CLAUDE.md's "Before every git push: do the claims match the code?"
  section into a repeatable, on-demand tool.
---

# Claim Verification

A vague question ("are we audit-ready?", "did PR #1609 actually resolve the
CodeRabbit deferral?", "is the ceremony-coordinator trap really fixed?") is
easy to answer with a confident-sounding paragraph that is subtly wrong,
because it's built from memory and vibes instead of checked evidence. This
skill forces the check.

Modeled on the "Essential Elements of Information" pattern from intelligence
requirements analysis: don't answer the vague question directly — decompose
it into the specific, checkable facts that would have to be true for the
answer to be "yes," verify each one against the actual repo, and report the
verdicts individually. A question with 6 sub-claims where 4 are confirmed,
1 is false, and 1 couldn't be checked is a *more useful and more honest*
answer than "yes, mostly."

## Process

### 1. Decompose the question into claims

Read the question and write out 3–10 claims, each phrased as a specific,
falsifiable proposition — not a topic. Bad: "checks CVEs." Good: "cargo-deny
runs in CI and fails the build on any GPL-licensed transitive dependency."

For each claim, note *what kind of evidence* would settle it:
- **Code fact** — a function/check/type exists and does what's claimed (Grep/Read).
- **Test fact** — a test exists AND asserts the specific failure mode, not just
  "doesn't panic" (Read the test body — see CLAUDE.md's negative-test rule).
- **CI fact** — a gate runs in the actual CI config, in the actual scope
  (repo-root invocations often silently skip `verifiers/rust`,
  `app/public-ui`, `clients/python` — check the workflow YAML, not just that
  a script exists).
- **Doc-vs-code fact** — a claim in an ADR/README/CLAUDE.md is checked
  against the implementation it describes, not the other way around.
- **State fact** — something about current repo/PR/CI state (open PRs,
  merged commits, check-run conclusions) — verify live, don't recall.

### 2. Surface the plan before expensive verification (scope-dependent)

For a small, scoped question (one PR, one file), just proceed — decomposing
and checking is cheap enough not to need a checkpoint.

For a broad question ("audit readiness," "is the whole rotation series
complete") list the claims first and let the user redirect before you spend
a large fan-out verifying all of them. This mirrors the approval-gate step
in the requirements-builder pattern this skill is based on: cheap to check
the plan, expensive to verify wrongly-scoped claims.

### 3. Verify each claim independently

Use the cheapest tool that actually settles the claim — Grep/Read for code
and test facts, the GitHub MCP tools for PR/CI state, WebFetch only for
external claims. For claims spanning many files or requiring broad search,
delegate to an Explore agent rather than doing it serially yourself — but
keep verification of different claims independent so one wrong assumption
doesn't contaminate the others.

Apply the same skepticism CLAUDE.md already demands pre-push:
- A test that recomputes a value with the same code that produced it proves
  agreement, not correctness — check whether it would pass if the function
  under test were replaced with a constant.
- `assert!(x.is_err())` / `assert.throws(fn, Error)` pass on *any* failure —
  check the test names the specific rejection reason.
- "Same as X, reused" claims must be checked against X, not assumed.
- A CI job existing is not the same as it running in the relevant directory
  with the relevant flags (`--max-warnings 0`, `--filter ./path`, etc. have
  each been silent-no-op traps in this repo before).

### 4. Classify and report

For each claim, one line with a citation, using these verdicts:

- ✅ **Confirmed** — cite the exact file:line, test name, or CI job/run that
  settles it.
- ⚠️ **Partial** — true with a caveat; state the caveat precisely (e.g. "the
  check exists but only runs on `ubuntu-latest`, not the Windows job").
- ❌ **False** — the claim is contradicted by the code/tests/CI; cite the
  contradiction.
- ❔ **Gap** — could not be verified with available tools/access (e.g.
  requires a live production environment, requires running an
  embedded-Postgres test this sandbox can't run as root, requires
  information only a human has). Say what would settle it, not just that
  you didn't check.

Never collapse a mixed result into an unqualified "yes" or "done." End with
a short list of open Gaps — a claim-verification report with zero gaps on a
nontrivial question is itself a sign the decomposition wasn't sharp enough.

## Example

**Question:** "Is the ceremony-coordinator retirement trap actually fixed?"

**Claims:**
1. The coordinator-signing digest binds `created_unix` for schema v3 manifests.
2. `verify_coordinator_signature` window-checks the trusted-issuer entry at
   the signed `created_unix`, not wall-clock now, for v3.
3. A retired key (bounded `valid_until`) still verifies a v3 manifest it
   signed inside its window — this is tested, not just implied by (1)+(2).
4. Legacy v1/v2 manifests are unaffected (still check wall-clock now).
5. `generate_manifest` (the tool that produces real manifests) emits v3, not
   v1/v2 — otherwise the fix exists but nothing uses it.
6. The docs (`docs/key-rotation.md`) were updated to stop telling operators
   the trap is unconditional.

**Verification:** (1)–(2) via Read of `coordinator_signing_digest` /
`verify_coordinator_signature` in `src-tauri/src/zk/manifest.rs`; (3) via
Grep for a test that constructs a retired-key scenario and asserts success,
by name; (4) via a negative test asserting v1/v2 still uses `now`; (5) via
Read of `generate_manifest.rs`'s `version:` field; (6) via Read of the
relevant doc section.

**Report:** six lines, each ✅/⚠️/❌/❔ with a citation — not a paragraph
saying "yes, this was fixed in PR #1609."
