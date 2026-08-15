# wiserepo

Self-hosted replacement for the `repowise` MCP server — same shape (repo Q&A,
diff review, summarization) but running as a plain local Node process against
a **local Ollama model**, instead of an opaque Docker image.

**Trust boundary.** Repo contents leave the machine: never. wiserepo hands
this tool's model whatever `repo_qa` / `review_diff` / `summarize` gathers —
file bodies, diffs, grep hits — and the only destination it can reach is an
Ollama daemon on `localhost`. There is deliberately **no cloud backend and
no API key**: that isn't a configuration default you could flip, it's the
only code path that exists (`src/backend.mjs`). For a repo whose whole point
is verifiable custody of documents, "the model can't phone home because
there's nothing to phone" is a stronger property than any policy setting.

Two caveats worth stating plainly, since "local" invites over-trust:

- The path-confinement guards in `src/repo.mjs` still matter. They stop the
  tool from reading files outside the repo (e.g. a symlink to
  `~/.ssh/id_rsa`) — with a local model that's no longer an exfiltration
  risk, but it's still the tool reading things you didn't ask it to.
- `WISEREPO_OLLAMA_URL` can be pointed at a non-localhost daemon. If you do
  that, the repo content this tool gathers (file bodies, diffs, grep hits)
  will be sent to that configured endpoint, reopening the network-trust
  question this design closes — the guarantee above is about the default, not
  about every possible config.

## Setup

```bash
cd tools/wiserepo
npm install
```

Install [Ollama](https://ollama.com), then pull a model:

```bash
ollama pull qwen3-coder:30b
```

That's the default (`WISEREPO_OLLAMA_MODEL` to override) — the strongest
coding-tier model that fits a 24GB card (e.g. an RTX 3090) at Q4. On a
smaller card use `qwen2.5-coder:14b`, or `qwen2.5-coder:7b` for 8GB.
`devstral:24b` is worth trying for agentic multi-file work specifically.

No API key, no per-token cost, nothing to rotate or leak. Other knobs:

- `WISEREPO_OLLAMA_URL` — daemon origin (default `http://localhost:11434`)
- `WISEREPO_TEMPERATURE` — default `0`
- `WISEREPO_TIMEOUT_MS` — default `300000` (5 min). Much larger than a
  cloud-backed tool would need: local generation on a 30B model is far
  slower per token, and `review_diff` / AGENTS.md regeneration can emit
  thousands of tokens. Raise it (or drop to a smaller model) if a big
  regeneration still times out.

Low temperature reduces wording churn between runs — it does **not** make
output byte-reproducible, and re-pulling a model tag can change the weights
underneath you. Nothing here assumes a _regeneration_ is byte-identical to
the last one; the drift _detection_ below is byte-based (a hash of
`CLAUDE.md` itself, not of the model's output), and a _successful_
regeneration's output is separately verified for structure, not bytes. See
below for why that split matters.

Already registered as a project MCP server (`wiserepo`) in `.claude.json`
alongside `repowise` — no extra Claude Code config needed.

## MCP tools

- `repo_qa` — ask a question grounded in repo file contents / a git-grep search
- `review_diff` — review a diff against `CLAUDE.md`'s engineering standards
- `summarize` — summarize a diff or set of files (changelog entry, PR description, etc.)

Every file/diff/grep result is truncated per-piece, and the combined context
for a single call is capped at 300k chars (`TOTAL_CONTEXT_BUDGET_CHARS` in
`src/mcp-server.mjs`) — truncation is always noted inline in the text handed
to the model, never silent.

**`diffArgs` is allowlisted, not passed through.** `git diff` accepts flags
that write files (`--output=PATH`) and read arbitrary paths; because
`diffArgs` is an MCP tool input it is model-chosen, and therefore
influenceable by any untrusted content the calling agent has read. So
`sanitizeDiffArgs` (`src/repo.mjs`) permits only a small set of read-only
flags plus revision-shaped arguments, confines post-`--` pathspecs to the
repo, and always terminates the argv with `--`. An unguarded version of this
was verified to write a file outside the repo root; `test/repo.test.mjs`
carries the regression test.

## AGENTS.md auto-sync

`CLAUDE.md` and `AGENTS.md` carry the same guidance for two different
assistants (Claude Code vs OpenAI Codex) and have drifted apart for real in
this repo before (commit `4f5e270f`). `bin/sync-agent-docs.mjs` regenerates
`AGENTS.md` from `CLAUDE.md` via the model backend, preserving every fact and
only reframing what must differ for Codex.

**Sync detection is a content-hash comparison, not a structural one.**
`AGENTS.md` carries a trailing `<!-- wiserepo:source-sha256:... -->` comment
recording the exact `CLAUDE.md` bytes it was generated from
(`src/source-trailer.mjs`). "In sync" means that hash still matches the
current `CLAUDE.md` — full stop. This is deterministic and needs **no model
call** to answer "has anything changed since last generation"; the model is
only invoked once drift is found, to produce the fix.

That replaced an earlier design that treated "`AGENTS.md` still satisfies
structural parity against the current `CLAUDE.md`" as proof of sync. That
was unsound, and demonstrably so: a `CLAUDE.md` edit that rewords a bullet's
prose — softening an invariant, changing a command, fixing a typo — without
changing the bullet _count_ passes structural parity trivially, because
nothing in that check reads prose. The old code reported `{ ok: true }` on
exactly that mutation in testing, meaning real drift could go undetected
indefinitely and silently — the precise failure mode this tool exists to
prevent. `test/source-trailer.test.mjs` carries the regression test.

**Once regeneration does run, its output is still verified before being
trusted enough to write.** `src/sections.mjs::checkStructuralParity` checks
four independent structural signals against the output — headings, per-
section bullet counts, per-section table-row counts, and fenced-code-block
count — and the script refuses to write anything on mismatch. This is a
_different_ safeguard than the hash check above: it catches the model
truncating or dropping content mid-generation, not staleness. Heading
comparison alone was tried first and is not sufficient here either, for the
same reason — most of `CLAUDE.md`'s load-bearing content is bullets and rows
under a single heading each, so a naive check would miss a dropped
invariant. Code-block _content_ is deliberately not required to match
(that's the whole point of `AGENTS.md` existing — some commands legitimately
differ for Codex); only the count is asserted, so wholesale deletion is
still caught. The checker is fence-aware (`stripFencedCode`): `CLAUDE.md`'s
` ```bash ` blocks are full of `# shell comments`, and a naive line-wise
heading regex counts every one as a heading — which made the first version
of this checker reject the repo's own correct docs 100% of the time.

**What none of this guarantees:** semantic equivalence of a _successful_
regeneration. The hash check proves something changed and triggers a fresh
generation; the structural check proves that generation didn't lose content
wholesale. Neither proves the model reworded the changed content
_correctly_. A regenerated `AGENTS.md` is reviewable output, not
automatically trustworthy — read the diff.

`CODEX.md` is a short hand-written pointer at both files and is deliberately
**not** regenerated — see its own text for why a near-duplicate was retired.

### Exit codes (used by both the pre-commit hook and CI)

- `0` — success (written, or already in sync).
- `1` — **blocking.** `--check` found the source hash has drifted (or
  `AGENTS.md` has no trailer at all — e.g. it was hand-edited), a
  regeneration's output failed structural parity, or wiserepo itself is
  broken (bad request, programming error, unreadable `CLAUDE.md`). All of
  these need a human.
- `2` — **non-blocking.** The backend was unavailable: Ollama daemon not
  running, network error, timeout, or an empty completion. The check did not
  run — which is not the same as failing. **`--check` never hits this path**
  — hash comparison needs no model, so it can only exit `0` or `1`. Only an
  actual regeneration (no `--check`) can hit `2`.

The 1-vs-2 split for regeneration failures is deliberate and tested
(`test/backend.test.mjs`): a daemon that isn't running must never block a
commit, while a 400 (a request _we_ built wrong) or a 404 (model never
pulled) must, because retrying will never fix either one and silence would
hide the bug.

```bash
node tools/wiserepo/bin/sync-agent-docs.mjs          # regenerate (needs Ollama only if hash drifted)
node tools/wiserepo/bin/sync-agent-docs.mjs --check  # CI-style: exit 1 if stale, never needs Ollama
```

### Where it's wired in

- **`.githooks/pre-commit`** — runs automatically whenever `CLAUDE.md` is
  staged, re-stages the regenerated `AGENTS.md` into the same commit on
  success, blocks the commit on exit `1`, and warns-but-continues on exit
  `2` (Ollama not running, or npm deps not installed). Silence it entirely
  with `WISEREPO_SKIP=1`.
- **CI (`docs-agent-sync` job in `.github/workflows/ci.yml`)** — runs
  `npm test` unconditionally, then `--check`. Because `--check` is pure hash
  comparison it needs no model, no daemon, and no secret, so it's a **hard
  gate on every trigger**. GitHub runners have no Ollama and never need one:
  regeneration is a local-developer action, and CI's job is only to refuse a
  stale `AGENTS.md`, never to produce a fresh one. This step used to juggle
  a repo secret and skip itself on `pull_request` to keep an API key away
  from PR-authored code; going Ollama-only deleted that whole class of
  problem along with the key.

## Tests

```bash
cd tools/wiserepo
npm test
```

70 tests covering the places a bug is silent rather than loud:

- `resolveInRepo` path-traversal guard, including the sibling-prefix case
  (`Olympus-evil` must not count as inside `Olympus`) — and
  `resolveInRepoFollowingSymlinks`, which catches what the lexical check
  can't: a repo-tracked symlink pointing at `~/.ssh/id_rsa` passes
  `resolveInRepo` (it's lexically inside the repo) but must still be
  refused, because `readRepoFile` puts whatever it reads into a prompt. Back
  when wiserepo had a cloud backend an unguarded version of this was a real
  exfiltration path, not a hypothetical; with a local-only model the guard
  now stops the tool reading files you never pointed it at, rather than
  stopping them leaving the machine.
- `sanitizeDiffArgs` option-injection guard, including an end-to-end check
  that `gitDiff(["--output=…"])` writes no file, and a `gitGrep` globs
  regression (a double `--` silently made every glob after the first match
  nothing).
- `checkStructuralParity` against **the real `CLAUDE.md`**, not just
  synthetic fixtures. The original test suite was 14 green tests against a
  checker that failed on both documents it would ever see — synthetic-only
  fixtures are how that happened, so two regression tests now load the
  actual file.
- `source-trailer`'s hash tracking, including the regression proving a
  prose-only edit (same Markdown structure, different meaning) changes the
  hash — the exact case structural parity alone let through.
- HTTP failure classification (`408`/`5xx` → non-blocking; `400`/`422` →
  blocking; `404` → blocking _and_ naming the `ollama pull` command to run,
  since a bare "API error 404" sends people hunting a network problem that
  doesn't exist), and `numericEnv`'s rejection of malformed
  `WISEREPO_TIMEOUT_MS`/`WISEREPO_TEMPERATURE` (silently becoming `NaN` used
  to fail the gate open forever with no diagnostic).
