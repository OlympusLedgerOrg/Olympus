# wiserepo

Self-hosted replacement for the `repowise` MCP server — same shape (repo Q&A,
diff review, summarization) but running as a plain local Node process backed
by **your own** Claude or Codex API key instead of an opaque Docker image.

## Setup

```bash
cd tools/wiserepo
npm install
```

Set one or both keys in your shell environment (never commit them):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

Pick the default backend with `WISEREPO_BACKEND=claude|openai` (defaults to
`claude`); each tool call can also override it per-call. Requests use
`temperature: 0` (override with `WISEREPO_TEMPERATURE`) and time out after 45s
(`WISEREPO_TIMEOUT_MS`).

Low temperature reduces wording churn between runs — it does **not** make
output byte-reproducible, and a floating model alias can change underneath
you. Nothing here assumes byte-identical regeneration; the drift check below
compares structure, never bytes.

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

**Verification, not blind trust.** After regenerating, the script runs
`src/sections.mjs::checkStructuralParity` and refuses to write anything on
mismatch. It compares four independent signals:

1. every Markdown heading, verbatim and in order (title line excepted),
2. per-section bullet counts,
3. per-section table-row counts,
4. fenced-code-block count.

Heading comparison alone was tried first and is **not** sufficient: most of
`CLAUDE.md`'s load-bearing content — `## Critical Invariants`, the
`## Before every git push` gates table — is bullets and rows under a single
heading each, so an invariant could be dropped or inverted invisibly. Signals
2–4 exist for exactly that.

**What it does not guarantee:** semantic equivalence. A model can still
reword one bullet incorrectly while keeping every count intact. A regenerated
`AGENTS.md` is reviewable output, not automatically trustworthy — read the
diff.

Code-block _content_ is deliberately not required to match, because the whole
point of `AGENTS.md` is that some commands legitimately differ for Codex;
only the count is asserted, so wholesale deletion is still caught.

Note the checker is fence-aware (`stripFencedCode`). This is load-bearing,
not cosmetic: `CLAUDE.md`'s ` ```bash ` blocks are full of `# shell
comments`, and a naive line-wise heading regex counts every one as a heading
— which made the first version of this checker reject the repo's own correct
docs 100% of the time.

`CODEX.md` is a short hand-written pointer at both files and is deliberately
**not** regenerated — see its own text for why a near-duplicate was retired.

### Exit codes (used by both the pre-commit hook and CI)

- `0` — success (written, or already in sync)
- `1` — **blocking.** The model responded but the result failed structural
  parity, `--check` found real drift, or wiserepo itself is broken (bad
  request, programming error, unreadable `CLAUDE.md`). All need a human.
- `2` — **non-blocking.** The backend was unavailable: no API key, network
  error, timeout, rate limit, auth rejection, or an empty completion. The
  check did not run — which is not the same as failing.

The 1-vs-2 split is deliberate and tested (`test/backend.test.mjs`): a 401 or
429 must never block a commit, while a 400 (a request _we_ built wrong) must,
because retrying will never fix it and silence would hide the bug.

```bash
node tools/wiserepo/bin/sync-agent-docs.mjs          # regenerate
node tools/wiserepo/bin/sync-agent-docs.mjs --check  # CI-style: exit 1 if stale, 2 if unreachable
```

### Where it's wired in

- **`.githooks/pre-commit`** — runs automatically whenever `CLAUDE.md` is
  staged, re-stages the regenerated `AGENTS.md` into the same commit on
  success, blocks the commit on exit `1`, and warns-but-continues on exit
  `2` (no key configured yet, or npm deps not installed). Silence it
  entirely with `WISEREPO_SKIP=1`.
- **CI (`docs-agent-sync` job in `.github/workflows/ci.yml`)** — runs
  `npm test` (see below) unconditionally, then `--check` as a **soft gate**:
  it only enforces drift if the `WISEREPO_ANTHROPIC_API_KEY` repo secret is
  set. Without that secret the job posts a `::warning::` and passes — add
  the secret to make this a hard gate in CI, not just locally.

## Tests

```bash
cd tools/wiserepo
npm test
```

43 tests covering the places a bug is silent rather than loud:

- `resolveInRepo` path-traversal guard, including the sibling-prefix case
  (`Olympus-evil` must not count as inside `Olympus`).
- `sanitizeDiffArgs` option-injection guard, including an end-to-end check
  that `gitDiff(["--output=…"])` writes no file.
- `checkStructuralParity` against **the real `CLAUDE.md`**, not just
  synthetic fixtures. The original test suite was 14 green tests against a
  checker that failed on both documents it would ever see — synthetic-only
  fixtures are how that happened, so two regression tests now load the actual
  file.
- HTTP failure classification (`401/429/5xx` → non-blocking, `4xx` →
  blocking) and the OpenAI restricted-model parameter split.
