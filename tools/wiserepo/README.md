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
- `WISEREPO_OLLAMA_URL`, when set, is restricted by code to a credential-free
  HTTP endpoint on `localhost`, `127.0.0.1`, or `::1`. Remote Ollama endpoints,
  URL credentials, query strings, and fragments are rejected before any model
  request is made.

## Setup

```bash
cd tools/wiserepo
npm install
```

Install [Ollama](https://ollama.com) on Windows from PowerShell:

```bash
irm https://ollama.com/install.ps1 | iex
```

For a laptop with 16 GB system RAM and Intel Arc integrated graphics, use the
7B Q4 model. It is about 4.7 GB and is a practical balance of coding quality,
memory use, and responsiveness:

```powershell
ollama pull qwen2.5-coder:7b-instruct
```

Wiserepo's default is `qwen2.5-coder:7b-instruct` (`WISEREPO_OLLAMA_MODEL` can
override it). If memory pressure or speed is a problem, use the smaller 3B
model instead:

```powershell
ollama pull qwen2.5-coder:3b
$env:WISEREPO_OLLAMA_MODEL = 'qwen2.5-coder:3b'
```

Avoid the 14B and larger models on this machine: they may fit on disk but leave
too little RAM for Windows, Tauri, and Wiserepo at the same time.

Note that Ollama drops the Intel Arc iGPU here ("dropping integrated GPU; to
enable, set OLLAMA_IGPU_ENABLE=1"), so inference is CPU-only unless you opt in —
and CPU is slow enough that a `qa` call over `crates/olympus-crypto/src/lib.rs`
(34 KB) takes **10–14 minutes** of wall clock (polled from a background run, not
timed; `bin/eval.mjs` prints exact per-question seconds). The rates behind that
are in the measured A/B below.

### `qwen3.5:4b` is not recommended here (settled — read before re-proposing)

The 3B tag above is the fallback when memory or latency is the binding
constraint. `qwen3.5:4b` is **not recommended for this repo**, tempting as it
looks on paper (newer tag, smaller download). Three reasons, heaviest first:

1. **General-purpose family vs the code-specialised default.**
   `qwen2.5-coder:7b-instruct` was trained for reading and writing code (5.5T
   code tokens over 92 languages), which is exactly this workload: read a
   30–60 KB Rust file, or judge a diff against `AGENTS.md`. A general model at
   4B fights both the task match and the parameter count at once.
2. **Half the size.** 4B against 7.6B is a quality cut in the one dimension this
   tool sells. `repo_qa` answers feed a reviewer and `review_diff` output is
   judged against the repo's standards, so a weaker model yields more
   confident-but-wrong prose. The citation check catches invented *paths*; it
   cannot catch invented *reasoning*.
3. **Thinking tokens cost minutes.** `qwen3.5` is thinking-capable and Ollama
   enables reasoning for such models unless told not to. Wiserepo sends
   `think: false` unless `WISEREPO_THINK=1`, but that flag is all that stands
   between a short answer and thousands of reasoning tokens — minutes per
   question on this machine, spent on a model that is *still* smaller than the
   default.

No speedup ratio for the 4B was ever measured on this box, so the "it will be
faster" half of the argument has never had evidence behind it. When latency is
the real complaint, the measured levers are `OLLAMA_IGPU_ENABLE=1` (the A/B
below — roughly 7× prefill) and the 3B tag; both stay inside the
code-specialised family. If someone does benchmark `qwen3.5:4b` against the
default with `bin/eval.mjs`, record the numbers here and revisit — until then,
this is the decision, and a re-pull is not progress.

### Hardware: iGPU yes, NPU no

This is a Core Ultra (Arc 140V iGPU + NPU) laptop, and Ollama uses neither by
default.

**Measured A/B (same machine, same prompt, two runs per arm, one cold daemon per
arm).** A fixed `qa`-shaped prompt — 9,440 tokens from the 34 KB
`crates/olympus-crypto/src/lib.rs` — sent to a freshly started `ollama serve` on
its own port, with `num_ctx 16384`, `temperature 0` and `keep_alive 0`, so no run
inherited a warm prompt cache. The only difference between the arms was
`OLLAMA_IGPU_ENABLE`:

| | CPU (`=0`) | iGPU (`=1`) | iGPU ÷ CPU |
| --- | --- | --- | --- |
| **prefill** | 16.9 tok/s (482 s, 668 s) | 130 tok/s (64 s, 84 s) | ~7.7× |
| **generation** | 3.0 tok/s | 8.8 tok/s | ~2.9× |
| model load | 13.5 s | 13–18 s | — |
| placement (`api/ps`) | `vram=0.00 GB` | `vram=5.64 GB` (100 %) | — |

Reproducing this needs no harness. `POST /api/chat` with `stream: false`,
`"keep_alive": 0`, `"options": {"num_ctx": 16384, "num_predict": 160,
"temperature": 0, "seed": 42}`, against a daemon started as `OLLAMA_IGPU_ENABLE=<0|1>
OLLAMA_HOST=127.0.0.1:<port> ollama serve`. The user message is exactly:

````text
You are answering a question about a Rust repository.

File: crates/olympus-crypto/src/lib.rs
```rust
<entire file contents>
```

Question: Which constant holds the SMT node hash domain prefix, and what is its value?
Answer in at most 120 words.
````

Ollama reports the timings itself, so no timing code is involved: prefill is
`prompt_eval_count / prompt_eval_duration`, generation is `eval_count /
eval_duration`, and load is `load_duration`. The context-length control below
omits the `File:` block (a 68-token prompt) and changes nothing else — same
`num_ctx`, same `num_predict`, same seed.

Read the table with its error bars, because both arms vary. They are global
rates over two runs that disagreed noticeably — CPU prefill 14.1 vs 19.6 tok/s
(39 % apart), iGPU 112 vs 148 (32 %) — so the prefill ratio is ~7.7× on the
means, but 5.7–10.5× depending on which samples you pair; treat "about 7×, ±3×"
as the honest statement. Generation stopped at 31 tokens in every run, so that
ratio rests on ~3 s of timed output per run and is the softest number here. The
CPU arm ran first, leaving the model file in the OS page cache for the iGPU arm,
which flatters the iGPU's load time but not its prefill or generation rate.
Prefill is the rate that decides whether this tool is usable.

Two separate facts about the hardware:

- **iGPU is worth turning on.** Ollama drops integrated GPUs unless
  `OLLAMA_IGPU_ENABLE=1`. **Nothing in this repo sets it** — it is a user
  environment variable on the machine these figures come from (`setx
  OLLAMA_IGPU_ENABLE 1`, then restart the daemon), and the daemon proves it took
  by logging `inference compute … library=Vulkan … type=iGPU` at startup instead
  of `dropping integrated GPU`. The gain is almost entirely **prefill** (see the
  table above), consistent with published Arc 140V figures (~173 tok/s).
- **NPU is not usable.** Ollama has no Intel NPU backend (ollama/ollama #19535
  confirms there is still no path), so no environment variable reaches it. Even
  where reachable — llama.cpp's OpenVINO backend supports Intel NPUs — a 7B
  model at long context is the wrong shape for it: NPU inference needs an INT4
  OpenVINO IR export, is largely static-shape, and OpenVINO's own docs note that
  on Core Ultra Series 2 prompts beyond 1024 tokens with a 7B model want more
  than 16 GB of RAM, which this machine does not have.

To measure the iGPU claim rather than repeat it, run the same question twice
(before and after the reboot) and compare wall clock:

```bash
node bin/eval.mjs --limit 1
```

Two model behaviours the backend has to account for (`src/backend.mjs`):

- **Thinking is off by default.** Ollama enables reasoning for thinking-capable
  models unless told not to, and on CPU that is thousands of tokens before the
  first answer token; the default `qwen2.5-coder` is not one and ignores the
  flag. `WISEREPO_THINK=1` opts in (worth it for a hard `review_diff`).
- **`num_ctx` is pinned, not inherited.** Ollama sizes its default window from
  available VRAM (4096 here) and truncates an oversized prompt *silently*, so the
  model would answer from a partial view with nothing saying so. The window sent
  — and the context budget derived from it — is `WISEREPO_NUM_CTX` clamped to
  what `/api/show` declares (see the knob below), so the two cannot disagree.

If generation fails with `llama-server binary not found`, the install is missing
its runners — `Programs\Ollama\lib\ollama\` should hold `llama-server.exe` and
the ggml/vulkan libraries. Restore them by reinstalling Ollama, or by extracting
`lib/ollama` from `ollama-windows-amd64.zip` for the matching release into the
install directory. The archive's only top-level file is `ollama.exe`; everything
else, including `llama-server.exe`, lives under `lib/ollama/`. A running daemon
picks the restored files up on the next model load, with no restart needed.

No API key, no per-token cost, nothing to rotate or leak. Other knobs:

- `WISEREPO_OLLAMA_URL` — daemon origin (default `http://localhost:11434`)
- `WISEREPO_OLLAMA_MODEL` — model tag (default `qwen2.5-coder:7b-instruct`)
- `WISEREPO_MODEL_QA` / `WISEREPO_MODEL_REVIEW` / `WISEREPO_MODEL_SUMMARIZE` —
  per-tool model overrides, so the cheap tools can run a small tag while
  `review_diff` keeps the strong one. Unset means the default model.
- `WISEREPO_NUM_CTX` — requested context window (default `16384`; range
  2048–262144). This is a ceiling, not a guarantee: the value actually sent is
  clamped to the window the model declares in `/api/show` (32K for the default
  tag), so configuring 256K on a 32K model cannot be silently truncated.
- `WISEREPO_KEEP_ALIVE` — how long the daemon keeps the model loaded (default
  `30m`; Ollama duration syntax or seconds, `-1` to pin). The default matters:
  Ollama unloads after 5 minutes and reloading this 7B costs ~17 s.
- `WISEREPO_THINK` — `1` to emit reasoning tokens before the answer, on a
  thinking-capable model such as `qwen3.5:4b` (default off)
- `WISEREPO_PROGRESS` — `0` disables the progress dots written to stderr during
  generation (on by default when stderr is a TTY)
- `WISEREPO_TEMPERATURE` — default `0`
- `WISEREPO_TIMEOUT_MS` — default `300000` (5 min). Local generation is far
  slower per token than a cloud API, and a `review_diff` or a full
  `AGENTS.md`-sized rewrite can emit thousands of tokens; raise it (or drop to a
  smaller model) if a bigger run still times out.

### Streaming, progress and honesty about what was sent

Requests use `stream: true` and reassemble the NDJSON response, which is what
makes progress reporting possible at all: a five-minute CPU call that prints
nothing is indistinguishable from a hang. On a TTY wiserepo writes one `.` per
~128 characters of answer to stderr (never stdout — that is the MCP channel).

Every answer is also checked for **fabricated citations**. The system prompt asks
for `path:line` references, and a small local model produces them confidently
whether or not it saw the file. Any cited path that does not resolve in the
working tree is named in an appended note (`N of M cited path(s) do not exist in
the repo — treat as unverified: …`). The answer is still returned — a wrong path
is not grounds to discard a useful review — but it cannot pass as evidence.

Two things are *not* fabricated citations. Git's diff headers carry `a/` and `b/`
prefixes (`--- a/src/pager.js`), so a path that does not resolve literally is
tried again with that prefix stripped — as a fallback, never a rewrite, so a
repo that really has an `a/` directory still resolves against it. And a file the
answer is **proposing** (`add a regression test in src/pager.test.js`, "…does not
exist yet") is supposed to be absent, so it is excused. Both rules are
sentence-scoped: a confident claim about a path with neither a header prefix nor
proposal language in its own sentence is still reported.

### Eval harness

Every model decision above was originally argued rather than measured. `bin/eval.mjs`
scores all three model-backed tools against golden cases in `eval/`:

| suite | cases | a pass means |
| --- | --- | --- |
| `qa` | `eval/golden-questions.json` | the answer contains every `expect` string; each case also names the files to ground on |
| `review` | `eval/golden-review.json` | three cases, each on a different two-revision range of the fixture (so no two send the same prompt): the review names the **planted bug** by its consequence (any of several accepted phrasings of `extra page`, never the `+ 1` token the hunk literally shows); it does **not** state the removed line (`lastPage - 1`) as current behaviour — naming it as removed passes; and on the **clean** range (`HEAD~1..HEAD`, whose only change is that fix) it flags nothing, so a review that calls the correct fix a defect fails |
| `summarize` | `eval/golden-summarize.json` | the summary names the surface it summarized |

Expectations are matched against the answer's **prose**: fenced code blocks are
stripped first, because a pasted diff or file excerpt is input, not a conclusion.
Without that, a review that discussed only one hunk passed the phantom case on
the other function's identifier appearing in the diff it copied back. Phantom
scanning still reads the whole answer — showing a removed line as live is a
failure wherever it appears.

Every case in every suite additionally fails if the answer cites a `path` or
`path:line` that does not resolve in the tree being scored. Citation checking is
not a separate suite: an invented path is a false claim, and a benchmark that
printed it beside a `PASS` would report the tool's worst failure mode as a
correct answer. The fixture repo contains only `src/pager.js` and `AGENTS.md`, so
a review that cites a plausible-looking file it never read fails there. The two
honest exceptions above apply here too — a quoted `a/`/`b/` header and a
recommended test file — so the case is decided by what the review claims about
the code, not by how it drew its paths.

`review_diff` and `summarize` take `git diff` arguments rather than diff text, so
those two suites share one throwaway git repo built from `eval/fixtures/` per run
(`qa` stays on this repo, since it grounds on the real tree):
`pager.before.js` is committed as `src/pager.js`, `pager.after.js` is committed
as a second commit, `WISEREPO_ROOT` is pointed at that repo, and the case diffs
`HEAD~1..HEAD`. Both states are committed because the two fixture files are the
same byte length — an uncommitted overwrite can fall inside git's racy-clean
window, producing a clean tree and an empty diff that scores like a model miss.
The eval also refuses to run on an empty fixture diff. The model therefore sees
a real two-revision `git diff` through the real tool path, so the eval cannot
drift from the prompt it is scoring. `eval/fixtures/README.md` explains why the diff
carries a *fix* alongside the bug: a review that reads deleted lines as current
reports the fix as a live defect and misses the real one — the exact failure a
smoke review here once produced.

```bash
node bin/eval.mjs                            # all three suites
node bin/eval.mjs --task qa                  # the cheap suite (real repo, no fixture)
node bin/eval.mjs --limit 2                  # first 2 cases per suite
node bin/eval.mjs --model qwen2.5-coder:3b   # compare tags on the same cases
node bin/eval.mjs --write-baseline           # record eval/baseline.json
node bin/eval.mjs --show-answers             # print each raw answer under its verdict
node bin/eval.mjs --rescore eval/runs/<stamp>.json   # re-score recorded answers, no model call
```

It prints PASS/FAIL per case, the number of unverified citations (any nonzero
count is a failure), and with `--show-answers` the raw answer beneath each
verdict — the score says a case moved, never why. It also prints a per-suite
and overall score, and — when `eval/baseline.json` exists — a per-suite
comparison (`unchanged` / `improved` / `REGRESSION`). It exits `0` whenever the
run completed (it is a benchmark, not a gate) and `2` when the backend was
unavailable. Runs are slow: one case is one full model call, so `--limit`
exists for smoke tests and `--task qa` for a model-only check that needs no
fixture repo.

Every run also writes its answers to `eval/runs/<timestamp>.json` (gitignored),
and `eval/baseline.json` points at the run that produced it via `answers`. Along
with the scores, the record carries the provenance needed to tell whether two
runs are comparable at all:

| field | what it fixes in place |
| --- | --- |
| `provenance.git_sha` / `git_dirty` | which commit the `qa` cases ran against, and whether the eval's own files still matched it |
| `provenance.models.<tag>.digest` | which weights answered — a re-pull changes the digest under an unchanged tag |
| `provenance.models.<tag>.num_ctx` | the window the prompt was actually truncated to |
| `provenance.prompt_sha256` | a hash of the exact system + user text each call was sent, so an `AGENTS.md` or prompt edit shows up in the record |

A run prints any provenance difference from the baseline before its scores,
because a number that moved alongside a prompt or weight change is not evidence
about either. A `null` digest means the daemon could not report one; it is
printed as `unknown` rather than filled in.

`--rescore <run file>` scores the stored answers again — against the current
matchers, golden cases and tree — with no Ollama call, and marks each case whose
verdict changed since it was recorded. That is how a scoring change is checked
against real answers, and how two recorded runs are compared later. Citations
are verified against the current tree, so re-score a run from another commit on
that commit (`git checkout <provenance.git_sha>`); otherwise a recorded
`src/pager.js` citation resolves nowhere in this repo.

The baseline is what makes prompt changes measurable: record one with
`--write-baseline` against the prompt you are about to change, then re-run
without the flag and read the comparison. Do not edit `eval/baseline.json` or a
run file by hand — the scores are derived from the recorded cases, and editing
one side would only make them disagree.

Low temperature reduces wording churn between runs — it does **not** make
output byte-reproducible, and re-pulling a model tag can change the weights
underneath you. Nothing here assumes a second run reproduces the first; the
only byte-exact assertions in this repo are the SSMF/SMT golden vectors, which
no model touches.

Registered as a project MCP server (`wiserepo`) by `.mcp.json` at the repo
root, for clients that read project-scoped config. MCP servers are loaded when
a client starts, so restart the client once after pulling it.

## Registering it and calling it

`.mcp.json` registers the server through `bin/mcp-launcher.mjs`, not by pointing
the client straight at `src/mcp-server.mjs`. Two failure modes that avoids:

- **The client's working directory.** An MCP client spawns `command` in its own
  cwd — for a GUI/IDE client often the editor or its install directory, not this
  repo. Reads are already anchored on the module location, and `git diff` /
  `git grep` pass `cwd: repoRoot()`, but a process sitting elsewhere is one
  relative-path mistake away from answering confidently about the wrong tree.
  The launcher derives the repo root from its own path (an explicit
  `WISEREPO_ROOT` still wins, resolved against the caller's cwd) and starts the
  server there.
- **Which node.** `"command": "${WISEREPO_NODE:-node}"` — Claude Code and VS
  Code both expand that form. If the client starts without node on its PATH
  (the usual reason a terminal works and the IDE does not), point
  `WISEREPO_NODE` at the absolute interpreter path and restart the client:
  `setx WISEREPO_NODE "C:\Program Files\nodejs\node.exe"`. The launcher
  re-executes the server with `process.execPath`, so the child uses exactly the
  interpreter the client resolved.

That entry relies on two host behaviours: expanding `${WISEREPO_NODE:-node}`,
and resolving `args` against the project root. Claude Code and VS Code do both.
A host that does neither — it passes `command` through literally and resolves
`args` against its own cwd — needs absolute paths, in **that host's own config**,
not in the committed file (a machine-specific path here breaks every other
clone):

```bash
node -e "console.log(process.execPath)"   # -> the absolute interpreter path
```

```json
{ "mcpServers": { "wiserepo": {
  "type": "stdio",
  "command": "C:\\Program Files\\nodejs\\node.exe",
  "args": ["C:\\path\\to\\Olympus\\tools\\wiserepo\\bin\\mcp-launcher.mjs"]
} } }
```

### Freebuff

Freebuff needs the same entry, but at a different path. Neither Freebuff surface
reads `.mcp.json`, and Desktop does not read a repository's `.agents/mcp.json`:
its orchestrator loads the server list from exactly one file,
`~/.agents/mcp.json` (`agentsConfigPath` in `McpConfigStore`), and keeps
approvals and per-server enable flags beside it in `~/.freebuff/mcp.json`. A
project `.agents/mcp.json` reaches the CLI only, so a server that works in a
shell can be missing in Desktop without anything being broken.

- **Add it in the app.** Settings → MCP / Connectors → _Add server_: paste the
  `mcpServers` block, approve the command, then pick the tools. Desktop writes
  the definition into `~/.agents/mcp.json` itself, so the CLI picks up the same
  entry and the two surfaces do not drift.
- **By hand.** The same entry in `~/.agents/mcp.json` is loaded but disabled; it
  connects once you approve and enable it under Connectors. The file is read at
  startup, so restart Desktop after editing it.
- **CLI precedence.** `.agents/mcp.json` in the project, then
  `../.agents/mcp.json`, then `~/.agents/mcp.json`; later wins, and a project
  file asks for trust before its server starts.

Because `~/.agents/mcp.json` sits outside this checkout, Desktop needs the
absolute `command`/`args` form above; only the committed `.mcp.json` can keep
the launcher path relative to the repo root.

### Verifying a host actually registered it

Parsing JSON is not registration. Check the host, in this order:

1. **The server is listed and connected.** Claude Code: `claude mcp list`, or
   `/mcp` in-session; VS Code: `MCP: List Servers`. Expect `wiserepo` with its
   six tools, not a red "failed".
2. **It reads *this* tree.** Call `olympus_context` and check `data.version`
   matches the version this checkout declares. That is the
   cwd-independence probe: a server launched from a foreign directory still has
   to report this repo's version. A wrong or empty answer means `args` resolved
   somewhere else and the launch silently failed.
3. **Only then** try `repo_qa`. It needs the Ollama daemon; `olympus_context`,
   `circuit_status` and `check_invariants` do not, so they separate "registered"
   from "model unreachable".

If step 1 reports a failed server with only `MCP error -32000: Connection
closed`, suspect the interpreter before anything else on this platform: with
`WISEREPO_NODE` unset and no `node` on the host's PATH, Windows writes
`'node' is not recognized as an internal or external command` to the child's
stderr and the client shows nothing but the closed connection. Put node on the
host's PATH or set `WISEREPO_NODE` (above); both are host-side fixes, which is
the point — the committed file cannot know where a given machine keeps node.

Because MCP registration only takes effect on a client restart, the same six
tools are also callable directly from the shell. The CLI calls the identical
`runTool()` the MCP transport uses — one implementation, two entry points:

```bash
cd tools/wiserepo
node bin/wiserepo.mjs tools                  # list the tools
node bin/wiserepo.mjs context                # context.json facts
node bin/wiserepo.mjs circuits               # artifact readiness
node bin/wiserepo.mjs invariants --check     # exit 1 if a pinned constant is missing
node bin/wiserepo.mjs qa "how is the leaf hash built?" -f crates/olympus-crypto/src/lib.rs
node bin/wiserepo.mjs review --diff-args main...HEAD
node bin/wiserepo.mjs summarize -f docs/adr/ADR-0044-smt-root-attestation.md --style "one paragraph"
```

The three structured commands need no model. `qa`, `review` and `summarize`
need Ollama; when it is not running they exit `2` ("did not run") instead of
printing an answer. Exit codes: `0` success, `1` usage/request error, `2`
backend unavailable. `--diff-args` consumes the rest of the argv, so put it
last.

## MCP tools

- `repo_qa` — ask a question grounded in repo file contents / a git-grep search
- `review_diff` — review a diff against `AGENTS.md`'s engineering standards. The
  prompt states the diff convention explicitly (`-` is removed code, `+` is added,
  a `-`/`+` pair at one position is a fix), because a small model otherwise
  reports a deleted line as current behaviour — the failure the `review` eval's
  second case scores.
- `summarize` — summarize a diff or set of files (changelog entry, PR description, etc.)

Every file/diff/grep result is truncated per-piece, and the combined context for
a single call is capped by `budgetCharsFor()` in `src/budget.mjs`. That cap
is derived from the **effective** context window (~3 chars per token, minus a
4096-token reserve for the answer) rather than a fixed number: a budget larger
than the window the daemon actually has would be truncated at the far end by
Ollama with no diagnostic, so the model would see less than wiserepo reported
sending.

When the budget runs out, the files that lost out are **named** in the appended
note instead of vanishing, and files whose path matches the question are read
first (`orderFilesForQuestion`) — because budget is spent in list order, so
otherwise the file named last is the one the model never sees.

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

`review_diff` grounds on the root `AGENTS.md` (see `AGENTS_MD` in
`src/mcp-server.mjs`). Nothing regenerates or gates that file, so keep it current
by hand. That there is exactly **one** instructions document is stated in
AGENTS.md's opening paragraph; the `.coderabbit.yaml` custom check "AGENTS.md
stays the only instructions document" enforces it and pins what the `CLAUDE.md`
bridge may contain. This file does not restate either.

The earlier design generated `AGENTS.md` from a `CLAUDE.md` source with a
`sha256` trailer and a drift gate. It was retired because the generated copy was
**lossy**: it paraphrased the invariants and dropped real content (the Python-SDK
copy of the leaf layout and its second vector set, the exact quorum co-sign
preimage).

## Tests

```bash
cd tools/wiserepo
npm test
```

The suite covers the places a bug is silent rather than loud:

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
- HTTP failure classification (`408`/`5xx` → non-blocking; `400`/`422` →
  blocking; `404` → blocking _and_ naming the `ollama pull` command to run,
  since a bare "API error 404" sends people hunting a network problem that
  doesn't exist), and `numericEnv`'s rejection of malformed
  `WISEREPO_TIMEOUT_MS`/`WISEREPO_TEMPERATURE` (silently becoming `NaN` used
  to fail the gate open forever with no diagnostic).
