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
the last one; the byte-exact assertions in this repo are the SSMF/SMT golden vectors, which
no model touches.

Already registered as a project MCP server (`wiserepo`) in `.claude.json`
alongside `repowise` — no extra Claude Code config needed.

## MCP tools

- `repo_qa` — ask a question grounded in repo file contents / a git-grep search
- `review_diff` — review a diff against `AGENTS.md`'s engineering standards
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

## AGENTS.md is hand-maintained

There is exactly **one** agent-instructions document in this repo: the root
`AGENTS.md`. Nothing generates it, and there is no second copy to drift.
(`CLAUDE.md` is a one-line `@AGENTS.md` import bridge for Claude Code older
than v2.1.277, not a duplicate.)

An earlier design generated `AGENTS.md` from a `CLAUDE.md` source, stamped a
`sha256` trailer, regenerated from a pre-commit hook and hard-gated drift in CI.
It was retired because the generated copy was **lossy**: it paraphrased the
invariants and dropped real content. One hand-maintained file removes both the
drift and the paraphrase; `review_diff` grounds on `AGENTS.md` directly.

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
- coverage of the request-building and path-guard surfaces.

- `source-trailer`'s hash tracking, including the regression proving a
  prose-only edit (same Markdown structure, different meaning) changes the
  hash — the exact case structural parity alone let through.
- HTTP failure classification (`408`/`5xx` → non-blocking; `400`/`422` →
  blocking; `404` → blocking _and_ naming the `ollama pull` command to run,
  since a bare "API error 404" sends people hunting a network problem that
  doesn't exist), and `numericEnv`'s rejection of malformed
  `WISEREPO_TIMEOUT_MS`/`WISEREPO_TEMPERATURE` (silently becoming `NaN` used
  to fail the gate open forever with no diagnostic).
