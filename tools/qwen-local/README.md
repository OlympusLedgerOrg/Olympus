# qwen-local

One question, one local answer, policy first: the shell-side `local` tier.

```bash
node tools/qwen-local/ask.mjs "how is the leaf hash built?" -f docs/adr/ADR-0005.md
node tools/qwen-local/ask.mjs --check -f README.md "summarize this repo"
node tools/qwen-local/ask.mjs --json "what does this doc say?" -f docs/court-evidence.md
```

Exit codes: `0` answered, `1` usage or local-file error, `2` Ollama unavailable,
`3` **refused by the agent policy** — escalate to a paid tier and read the file
yourself; do not retry, rephrase, or narrow the request.

## The guard

`tools/agent-policy/policy.mjs` decides. This CLI calls the same `decideTask`
that wiserepo's MCP tools and CLI call, so:

- a path that is not allowlisted, or that hits the deny set, refuses the **whole**
  request — not just that file;
- a question whose prose names a protected concern (hash, proof, auth, migration,
  …) escalates, even with no files attached;
- an unknown `--task` class is a refusal, not a default;
- `..`, absolute paths, and symlinks that escape the repo are refused before any
  read, and one denied path is enough.

A refusal here is not advisory. The message it prints is the instruction to
follow: read the file directly on the paid tier the refusal implies.

## What it sends, and where

Only the files named with `-f`, plus the question, to
`WISEREPO_OLLAMA_URL` — which must be a credential-free `http` URL on
`localhost`, `127.0.0.1`, or `::1`. There is no cloud path and no API key: the
Ollama client is `../wiserepo/src/backend.mjs`, which refuses any other
destination before a request is made.

That reuse is deliberate. A naive `fetch` loop gets two things wrong on this
machine: Node's own 300 s body timeout kills a multi-minute CPU call, and an
Ollama `num_ctx` the caller did not pin silently truncates the prompt. The
shared backend already fixes both, so this wrapper does not carry a second copy
of that knowledge.

Its dependencies therefore have to be installed once:

```bash
npm install --prefix tools/wiserepo
```

## Prompt budget

Per file `MAX_FILE_CHARS` (24 000 characters), total `MAX_PROMPT_CHARS`
(48 000). A cut file carries an explicit `[truncated: …]` line, and a file that
does not fit at all is named in `[not sent (prompt budget): …]` — never dropped
silently, because a model answering from a partial view does not say so.

The budget is spent in `-f` order, so name the important file first.

## Tests

```bash
node --test tools/qwen-local/ask.test.mjs
```

No Ollama needed: the tests inject a backend stub and assert that a refused
request never reaches it.
