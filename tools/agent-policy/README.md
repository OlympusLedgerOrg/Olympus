# Agent policy

One data file (`policy.json`) and one module (`policy.mjs`) decide whether a
piece of work may be handed to the **local** model running on this machine.

Everything else in the repo — the model router, the Qwen wrapper, wiserepo's
MCP tools and its CLI — calls this module. There is exactly one place to change
when the rule changes, and exactly one place a test can point at.

## The rule

**Default-deny.** A repo-relative path reaches the local model only when it
matches `allow` **and** does not match `deny`. Anything unmatched is refused.

| Stage                                   | Meaning                                                                                                     |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `taskClasses`                           | Only these task classes are eligible for the local model at all.                                            |
| `deny`                                  | Hard override. A hit refuses the request even when `allow` matches.                                         |
| `allow`                                 | The set of paths that may be sent, once `deny` has passed.                                                  |
| `criticalPrefixes` / `criticalKeywords` | Which paid tier a refusal goes to: `top` when the path or the prose names a critical subsystem, else `mid`. |

Path matching runs on **normalized** paths: forward slashes, `./` stripped,
lower-cased, and any path that is absolute or contains `..` is refused rather
than resolved. Windows case-insensitivity is why folding happens — `SRC-TAURI/`
must not dodge `src-tauri/`.

Nothing in the task prose can _grant_ access. Keywords only escalate, which is
why the matcher is not asked to interpret intent.

## What gets checked

- an explicit file list (`files` on `repo_qa` / `summarize`);
- every path in `git diff` output, including both sides of a rename;
- every path in `git grep` output;
- path-like tokens in the task text, restricted to real top-level directories
  (so `and/or` is not read as a path).

One denied path refuses the **whole** request. Partial context would let a
model answer from a sanitized view while reading as if it had the full one.

## Changing it

Edit `policy.json`; `policy.mjs` validates the shape on load and throws with the
file name and the offending key. Run the tests afterwards:

```bash
node --test tools/agent-policy/policy.test.mjs
```

`tools/agent-policy/policy.json` is meant to be listed in
`scripts/check-gate-integrity.mjs` (`GATE_PATHS`) so weakening the deny set
requires the `gate-change-approved` label, like the other gate files.

## Known over-denials

`deny` is written with substring globs for the `app/` UI, as specified:
`app/**/*sign*` matches `DesignPanel.tsx` because "Design" contains "sign".
That is intentional — the deny set is allowed to be blunt, and a false denial
costs one escalation, while a false allow is the failure this file exists to
prevent. Add a narrower `allow` entry only if a real file is blocked and is
provably not crypto-adjacent.

## Logging

`log.mjs` appends one JSON object per line to `.olympus-logs/route-report.jsonl`
(gitignored): a `route` record for each decision `route.mjs` makes, and a
`usage` record for each local call, carrying Ollama's own `prompt_eval_count` /
`eval_count`. A hosted model's billing is not visible from here, so the log
records which tier was chosen rather than inventing a token count for it.

```bash
python tools/agent-policy/route_report.py          # counts per tier, local tokens
python tools/agent-policy/route_report.py --json
```

`OLYMPUS_ROUTE_LOG=0` disables writing; `OLYMPUS_ROUTE_LOG_PATH` overrides the
file, which is what the tests use. A failed write is a warning on stderr, never
a failed task.

## Model table

`models` maps the client-agnostic tier (`local`, `mid`, `top`) to the model id
each client should use. It is data, not code, because the ids move faster than
the policy does. `local` is the same on every client: whatever
`WISEREPO_OLLAMA_MODEL` runs.
