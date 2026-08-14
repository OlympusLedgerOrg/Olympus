# wiserepo

Self-hosted replacement for the `repowise` MCP server — same shape (repo Q&A,
diff review, summarization) but running as a plain local Node process backed
by **your own** Claude or Codex API key, or by a **local Ollama model** that
never leaves the machine, instead of an opaque Docker image.

**Trust boundary — read before use.** "Self-hosted" describes where the
_process_ runs, not automatically where your data goes — that depends on
which backend you pick. With `claude` or `openai`, every `repo_qa` /
`review_diff` / `summarize` call sends the file contents, diffs, and grep
results it gathers — plus your question or prompt — to the configured
Anthropic or OpenAI API over the network. wiserepo provides no
confidentiality from that provider: it is exactly as private as calling
their API directly, and no more. Don't point it at files you would not
otherwise send to that provider (secrets, credentials, anything outside
this repo — the path-confinement guards in `src/repo.mjs` exist
specifically to stop the tool from reading and sending those without you
asking it to by name). With `ollama`, none of that applies: the request
goes to a daemon on `localhost` (or wherever `WISEREPO_OLLAMA_URL` points)
and nothing crosses the network boundary — see "Local LLM (Ollama)" below.

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

Pick the default backend with `WISEREPO_BACKEND=claude|openai|ollama`
(defaults to `claude`); each tool call can also override it per-call.
Requests use `temperature: 0` (override with `WISEREPO_TEMPERATURE`) and
time out after 45s (`WISEREPO_TIMEOUT_MS`).

Low temperature reduces wording churn between runs — it does **not** make
output byte-reproducible, and a floating model alias can change underneath
you. Nothing here assumes a _regeneration_ is byte-identical to the last
one; the drift _detection_ below is byte-based (a hash of `CLAUDE.md`
itself, not of the model's output), and a _successful_ regeneration's output
is separately verified for structure, not bytes. See below for why that
split matters.

Already registered as a project MCP server (`wiserepo`) in `.claude.json`
alongside `repowise` — no extra Claude Code config needed.

## Local LLM (Ollama)

No API key, no per-token cost, no repo content leaving the machine. Needs
[Ollama](https://ollama.com) running locally and a model pulled:

```bash
ollama pull qwen3-coder:30b   # ~24GB VRAM at Q4 -- fits a 3090 with room to spare
export WISEREPO_BACKEND=ollama
```

`qwen3-coder:30b` is the default (`WISEREPO_OLLAMA_MODEL` to override) —
picked as the strongest coding-tier model that fits comfortably in 24GB.
`qwen2.5-coder:14b` is a faster fallback on the same card if 30B feels
sluggish or context gets tight; `devstral:24b` is worth trying for
agentic multi-file work specifically. wiserepo talks to Ollama's native
`/api/chat` endpoint on `http://localhost:11434` by default — override
the daemon origin with `WISEREPO_OLLAMA_URL` (e.g. for a non-default port
or a remote/tunneled instance; note that "remote" reopens the
network-trust question the local case avoids).

Same error-handling contract as the other two backends: the daemon not
running (connection refused) or timing out classifies as
`ModelUnavailableError` (non-blocking — `sync-agent-docs.mjs --check`
never depends on any backend, so this only affects an actual regen or a
`repo_qa`/`review_diff`/`summarize` call); an unpulled model (HTTP 404
from Ollama) classifies as `ModelRequestError` (blocking — fix by pulling
the model, not by retrying).

**Not yet local:** the semantic index's embedding step (`src/embed.mjs`,
see below) still calls the OpenAI embeddings API regardless of which
`WISEREPO_BACKEND` you pick for chat — Ollama serves chat completions
here, not embeddings. Building the index still sends full file contents
to OpenAI even when every `repo_qa` call itself runs fully local.

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
- `2` — **non-blocking.** The backend was unavailable: no API key, network
  error, timeout, rate limit, auth rejection, or an empty completion. The
  check did not run — which is not the same as failing. **`--check` never
  hits this path** — hash comparison needs no model, so it can only exit `0`
  or `1`. Only an actual regeneration (no `--check`) can hit `2`.

The 1-vs-2 split for regeneration failures is deliberate and tested
(`test/backend.test.mjs`): a 401 or 429 must never block a commit, while a
400 (a request _we_ built wrong) must, because retrying will never fix it
and silence would hide the bug.

```bash
node tools/wiserepo/bin/sync-agent-docs.mjs          # regenerate (needs a key only if hash drifted)
node tools/wiserepo/bin/sync-agent-docs.mjs --check  # CI-style: exit 1 if stale, never needs a key
```

### Where it's wired in

- **`.githooks/pre-commit`** — runs automatically whenever `CLAUDE.md` is
  staged, re-stages the regenerated `AGENTS.md` into the same commit on
  success, blocks the commit on exit `1`, and warns-but-continues on exit
  `2` (no key configured yet, or npm deps not installed). Silence it
  entirely with `WISEREPO_SKIP=1`.
- **CI (`docs-agent-sync` job in `.github/workflows/ci.yml`)** — runs
  `npm test` unconditionally, then `--check`. Because `--check` is pure hash
  comparison, it runs the **same way on every trigger and needs no secret at
  all** — it's a hard gate on `pull_request`, not a soft one. The
  `ANTHROPIC_API_KEY` env var in that step is deliberately scoped to
  `github.event_name == 'push'` only: a `pull_request` job checks out the PR
  head and runs `node` against that checkout, so any code a same-repository
  PR adds (in `sync-agent-docs.mjs` or anywhere else executed in that step)
  could otherwise read and exfiltrate the secret regardless of whether the
  model is ever actually called. On `push` (post-merge, protected branch)
  the key is present so a genuinely stale `AGENTS.md` can be regenerated by
  re-running the script by hand or in a follow-up job.

## Tests

```bash
cd tools/wiserepo
npm test
```

65 tests covering the places a bug is silent rather than loud:

- `resolveInRepo` path-traversal guard, including the sibling-prefix case
  (`Olympus-evil` must not count as inside `Olympus`) — and
  `resolveInRepoFollowingSymlinks`, which catches what the lexical check
  can't: a repo-tracked symlink pointing at `~/.ssh/id_rsa` passes
  `resolveInRepo` (it's lexically inside the repo) but must still be
  refused, because `readRepoFile` puts whatever it reads into a prompt sent
  to a third-party model API. An unguarded version of this was a real
  exfiltration path, not a hypothetical.
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
- HTTP failure classification (`401/403/429/5xx` plus `402/408` → non-
  blocking, `4xx` → blocking), the OpenAI restricted-model parameter split,
  `numericEnv`'s rejection of malformed `WISEREPO_TIMEOUT_MS`/
  `WISEREPO_TEMPERATURE` (silently becoming `NaN` used to fail the gate open
  forever with no diagnostic), and API-key redaction from provider error
  bodies.
