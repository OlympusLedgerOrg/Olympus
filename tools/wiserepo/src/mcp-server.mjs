#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { callModel, effectiveNumCtx, modelForTool, DEFAULT_OLLAMA_MODEL } from "./backend.mjs";
import { verifyCitations, formatMissingCitations } from "./citations.mjs";
import { readRepoFile, gitDiff, gitGrep, truncateText, wouldTruncate } from "./repo.mjs";
import { getOlympusContext, getCircuitStatus, checkInvariants } from "./olympus.mjs";
// The same module the router and the Qwen wrapper use. The local model never
// gets to decide what it may read, so this is enforced here, at the one point
// where content becomes a prompt, rather than in each entry point.
import {
  assertPathsAllowed,
  extractDiffPaths,
  extractGrepPaths,
} from "../../agent-policy/policy.mjs";

// Total context budget across every file/diff/grep a single tool call pulls
// in, independent of the per-piece truncation each helper already applies.
// Without this a request naming 30 files each just under their own limit
// would still blow well past the model's context window.
//
// Derived from the model's ACTUAL window rather than a fixed 300k (which only
// fit a big-token model): Ollama truncates an oversized prompt silently, so a
// budget larger than num_ctx means the model answers from a partial view while
// wiserepo's inline truncation notes claim everything was sent. ~3 chars/token
// is deliberately pessimistic for this codebase (paths, diff markers and dense
// Rust prose all over-tokenize), and the output reserve keeps room for the
// answer so the prompt and the completion fit in one window.
const CHARS_PER_TOKEN_ESTIMATE = 3;
const OUTPUT_TOKEN_RESERVE = 4_096;

/**
 * Character budget for one gather, from the window the model will really get.
 *
 * Called with the EFFECTIVE num_ctx (configured value clamped to what the model
 * declares), not the configured value alone: a budget derived from a window the
 * model does not have is the silent-truncation bug this exists to prevent.
 */
export function budgetCharsFor(numCtx) {
  return Math.max(1_024, numCtx - OUTPUT_TOKEN_RESERVE) * CHARS_PER_TOKEN_ESTIMATE;
}

// Hard cap on how many files a single request may name. Without this,
// gatherContext reads and buffers EVERY requested file in full before the
// combined-budget truncation below ever runs — a request repeating a large
// path many times causes unbounded I/O and memory allocation up front, with
// the budget only trimming the final string. Capping the count bounds that
// work regardless of what the budget ends up doing.
const MAX_FILES_PER_REQUEST = 40;
const MAX_QUESTION_CHARS = 8_000;
const MAX_GREP_CHARS = 2_000;
const MAX_STYLE_CHARS = 200;
const MAX_DIFF_ARGS = 32;
const MAX_MODEL_OUTPUT_CHARS = 120_000;
// The one agent-instructions file this repo keeps. review_diff grounds on it.
const AGENTS_MD = "AGENTS.md";

export const TOOLS = [
  {
    name: "olympus_context",
    description:
      "Return machine-readable project facts from context.json: version, language rules, " +
      "critical constants (LAZY_DEPTH, CANOPY_RECOMPUTE_CAP, domain prefixes), leaf hash " +
      "implementations, circuit list, key env vars, and agent file locations. " +
      "Call this first when orienting to the repo — no model call, instant, works offline.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "circuit_status",
    description:
      "Check which ZK circuit artifacts (wasm, r1cs, ark.zkey, vkey.json, manifest) are present " +
      "and whether any are still build.rs PLACEHOLDER stubs. Reports per-circuit readiness and " +
      "whether production circuits are ready for cargo tauri build. No model call.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "check_invariants",
    description:
      "Grep the repo for ADR-0005/ADR-0022 pinned constants (LAZY_DEPTH, CANOPY_RECOMPUTE_CAP, " +
      "NODE_PREFIX, EMPTY_LEAF_PREFIX, LEAF_BODY_FIELD_COUNT) across all four leaf-hash " +
      "implementations (olympus-crypto, verifiers/rust, verifiers/javascript, clients/python). " +
      "Returns grep hits per invariant — evidence for whether implementations agree. No model call.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "repo_qa",
    description:
      "Answer a question about the Olympus repo, grounded in actual file contents. " +
      "Give it a question plus a few relevant file paths (relative to repo root) or a grep pattern to search first.",
    inputSchema: {
      type: "object",
      properties: {
        question: { type: "string" },
        files: {
          type: "array",
          items: { type: "string" },
          maxItems: 40,
          description: "Repo-relative file paths to read as context. Max 40 per request.",
        },
        grep: {
          type: "string",
          description: "Optional git-grep pattern to search first and include as context.",
        },
      },
      additionalProperties: false,
      required: ["question"],
    },
  },
  {
    name: "review_diff",
    description:
      "Review a git diff against this repo's AGENTS.md engineering standards (invariants, hard boundaries, etc). " +
      "Defaults to `git diff HEAD` (working tree + staged) if no diffArgs given.",
    inputSchema: {
      type: "object",
      properties: {
        diffArgs: {
          type: "array",
          items: { type: "string" },
          description:
            'Extra args passed to `git diff`, e.g. ["main...HEAD"]. Defaults to ["HEAD"].',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "summarize",
    description:
      "Summarize a diff or a set of repo files (e.g. for a changelog entry or PR description).",
    inputSchema: {
      type: "object",
      properties: {
        files: { type: "array", items: { type: "string" }, maxItems: 40 },
        diffArgs: { type: "array", items: { type: "string" } },
        style: {
          type: "string",
          description: "e.g. 'changelog entry', 'PR description', 'one paragraph'",
        },
      },
      additionalProperties: false,
    },
  },
];

/**
 * Order files by how well their PATH matches the question.
 *
 * The budget is spent in list order, so with a small window the files named
 * last simply vanish — and the caller has no idea which. Scoring on the path is
 * cheap (no reads, no model) and enough to float the obviously relevant file
 * above an incidental one. Ties keep the caller's order, so behaviour is
 * predictable when the question says nothing useful.
 */
export function orderFilesForQuestion(files, question) {
  if (!question) return [...files];
  const tokens = new Set(question.toLowerCase().match(/[a-z0-9_]{4,}/g) ?? []);
  if (tokens.size === 0) return [...files];
  return files
    .map((file, index) => {
      const haystack = file.toLowerCase();
      let score = 0;
      for (const token of tokens) if (haystack.includes(token)) score++;
      return { file, index, score };
    })
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((entry) => entry.file);
}

export async function gatherContext({
  files = [],
  grep,
  diffArgs,
  question,
  model,
  taskClass,
} = {}) {
  if (!taskClass) {
    throw new Error("gatherContext requires a taskClass so the agent policy can be applied");
  }
  // Before the budget is derived (which probes the backend) and before any
  // file is read: a refused path must cost nothing and must not be opened.
  assertPathsAllowed(files, taskClass);

  if (files.length > MAX_FILES_PER_REQUEST) {
    throw new Error(
      `Requested ${files.length} files, wiserepo's per-request cap is ${MAX_FILES_PER_REQUEST} — narrow the list`,
    );
  }

  const budget = budgetCharsFor(await effectiveNumCtx(model ?? DEFAULT_OLLAMA_MODEL));
  const parts = [];
  let runningChars = 0;
  const dropped = [];

  if (grep) {
    const hits = await gitGrep(grep);
    // Grep hits carry their own paths, so an empty `files` list is not an
    // empty request: without this, matching a denied file's contents would
    // still put those lines in the prompt.
    assertPathsAllowed(extractGrepPaths(hits), taskClass);
    const part = `## git grep "${grep}"\n\`\`\`\n${hits || "(no matches)"}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }
  if (diffArgs) {
    const diff = await gitDiff(diffArgs);
    assertPathsAllowed(extractDiffPaths(diff), taskClass);
    const part = `## git diff ${diffArgs.join(" ")}\n\`\`\`diff\n${diff || "(empty diff)"}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }
  for (const f of orderFilesForQuestion(files, question)) {
    // Stop READING once the budget is already spent, rather than reading
    // every file in full and only truncating the joined string afterward —
    // that pattern still pays the full I/O/memory cost of every requested
    // file before the budget has any effect. Keep walking the list (no reads)
    // so the ones that lost out can be named.
    if (runningChars >= budget) {
      dropped.push(f);
      continue;
    }
    const content = await readRepoFile(f, { maxBytes: budget - runningChars });
    const part = `## ${f}\n\`\`\`\n${content}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }

  const joined = parts.join("\n\n");
  const budgeted = truncateText(joined, budget, "combined context");
  // Surface this loudly rather than let the model quietly answer from a
  // partial view without saying so. wouldTruncate (not a length comparison)
  // is what makes this reliable even when the appended truncation note pushes
  // `budgeted` longer than `joined`.
  const notes = [];
  if (wouldTruncate(joined, budget)) {
    notes.push(
      `combined context exceeded ${budget} chars — the tail was cut; narrow the file/grep list for full coverage`,
    );
  }
  if (dropped.length > 0) {
    notes.push(`dropped ${dropped.length} file(s) that did not fit: ${dropped.join(", ")}`);
  }
  return notes.length > 0 ? `${budgeted}\n\n[wiserepo: ${notes.join("; ")}]` : budgeted;
}

const SYSTEM_PROMPT =
  "You are wiserepo, a self-hosted repo assistant for the Olympus verifiable-ledger codebase. " +
  "Be precise, cite file paths and line numbers when possible, and never invent code you have not been shown.";

/**
 * Execute one tool by name and return its text result.
 *
 * Exported so the CLI (`bin/wiserepo.mjs`) drives exactly the same
 * implementation the MCP transport exposes. Two entry points, one behaviour:
 * the CLI cannot drift from the server it wraps, and a tool only has to be
 * added or fixed in one place.
 */
/**
 * Label citations that do not resolve. The answer is still returned — a wrong
 * path is not grounds to discard a useful review — but it must not pass as
 * evidence, which is exactly how a small model's confident hallucination reads.
 */
// Exported so the model-output contract below (non-text output, oversized
// output) can be tested directly rather than only through a live model call.
export async function withVerifiedCitations(answer) {
  if (typeof answer !== "string") throw new Error("model returned a non-text response");
  answer = truncateText(answer, MAX_MODEL_OUTPUT_CHARS, "model output");
  const { checked, missing } = await verifyCitations(answer);
  if (checked === 0 || missing.length === 0) return answer;
  return (
    `${answer}\n\n[wiserepo: ${missing.length} of ${checked} cited path(s) do not exist in the repo ` +
    `— treat as unverified: ${formatMissingCitations(missing)}]`
  );
}

function validateToolArgs(name, args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new Error(`${name} arguments must be an object`);
  }
  const allowed = {
    olympus_context: [],
    circuit_status: [],
    check_invariants: [],
    repo_qa: ["question", "files", "grep"],
    review_diff: ["diffArgs"],
    summarize: ["files", "diffArgs", "style"],
  }[name];
  if (!allowed) throw new Error(`Unknown tool "${name}"`);
  for (const key of Object.keys(args)) {
    if (!allowed.includes(key)) throw new Error(`${name}.${key} is not a supported argument`);
  }
  const stringField = (field, max, required = false) => {
    if (args[field] === undefined) {
      if (required) throw new Error(`${name}.${field} is required`);
      return;
    }
    if (typeof args[field] !== "string" || args[field].length > max) {
      throw new Error(`${name}.${field} must be a string of at most ${max} characters`);
    }
  };
  const arrayField = (field, maxItems) => {
    if (args[field] === undefined) return;
    if (
      !Array.isArray(args[field]) ||
      args[field].length > maxItems ||
      args[field].some((v) => typeof v !== "string" || v.length > 4096)
    ) {
      throw new Error(
        `${name}.${field} must contain at most ${maxItems} strings of at most 4096 characters`,
      );
    }
  };
  if (name === "repo_qa") {
    stringField("question", MAX_QUESTION_CHARS, true);
    stringField("grep", MAX_GREP_CHARS);
    arrayField("files", MAX_FILES_PER_REQUEST);
  } else if (name === "review_diff") {
    arrayField("diffArgs", MAX_DIFF_ARGS);
  } else if (name === "summarize") {
    arrayField("files", MAX_FILES_PER_REQUEST);
    arrayField("diffArgs", MAX_DIFF_ARGS);
    stringField("style", MAX_STYLE_CHARS);
  }
}

/**
 * Run one tool through the same path the MCP transport uses.
 *
 * `onPrompt` receives the exact `{ system, prompt, model }` handed to the backend
 * for each model call. The eval uses it to hash what the model was actually
 * sent: a baseline that records only the golden case cannot tell a prompt edit
 * from a sampling difference, and reconstructing the prompt outside this
 * function would drift from it the first time the prompt changes.
 */
export async function runTool(name, args = {}, { onPrompt } = {}) {
  validateToolArgs(name, args);
  if (name === "olympus_context") {
    const ctx = await getOlympusContext();
    return JSON.stringify(ctx, null, 2);
  }

  if (name === "circuit_status") {
    const status = await getCircuitStatus();
    return JSON.stringify(status, null, 2);
  }

  if (name === "check_invariants") {
    const result = await checkInvariants();
    return JSON.stringify(result, null, 2);
  }

  if (name === "repo_qa") {
    const model = modelForTool("qa");
    const context = await gatherContext({
      files: args.files,
      grep: args.grep,
      question: args.question,
      model,
      taskClass: "qa",
    });
    const prompt = `${context ? context + "\n\n" : ""}Question: ${args.question}`;
    onPrompt?.({ system: SYSTEM_PROMPT, prompt, model });
    return withVerifiedCitations(await callModel({ system: SYSTEM_PROMPT, prompt, model }));
  }

  if (name === "review_diff") {
    const diffArgs = args.diffArgs?.length ? args.diffArgs : ["HEAD"];
    const diff = await gitDiff(diffArgs);
    assertPathsAllowed(extractDiffPaths(diff), "review");
    let standards = "";
    try {
      standards = await readRepoFile(AGENTS_MD);
    } catch (err) {
      // Only a genuinely missing file is safe to silently review without
      // standards. A permission error, a path-type error (e.g. AGENTS.md
      // is a directory), or any other I/O failure is a real problem the
      // caller should see — swallowing those would silently produce a
      // review that looks standards-checked but never actually was.
      if (err.code !== "ENOENT") throw err;
    }
    const prompt =
      `Review this diff against the project's engineering standards below. ` +
      `Flag correctness bugs, invariant violations, and missed test coverage. Be concise, most-severe first. ` +
      // The fixture now carries two separated hunks, so per-hunk coverage is
      // measurable; with a single merged hunk the model only ever had one region
      // to report on, which made this instruction unmeasurable rather than
      // merely ignored.
      `Report a finding for EVERY hunk in the diff; for a hunk with no issue, say ` +
      `so rather than leaving it out.\n\n` +
      // A small model reads a diff as if every line in it were the file: a
      // smoke review reported the fixture's removed `lastPage - 1` as live
      // behaviour because nothing said a `-` line is gone. Two sentences, not a
      // tutorial — the prompt is already ~10.5k tokens of AGENTS.md.
      `Diff semantics: \`-\` lines are code the diff REMOVES (no longer in the file), \`+\` lines ` +
      `are code it ADDS, and a \`-\`/\`+\` pair at one position is a single change to read as a ` +
      `fix. Judge the code as it stands after the diff, and describe removed code as removed, ` +
      `never as current behaviour.\n\n` +
      (standards ? `## AGENTS.md (standards)\n\`\`\`\n${standards}\n\`\`\`\n\n` : "") +
      `## Diff\n\`\`\`diff\n${diff || "(empty diff)"}\n\`\`\``;
    const model = modelForTool("review");
    onPrompt?.({ system: SYSTEM_PROMPT, prompt, model });
    return withVerifiedCitations(
      await callModel({ system: SYSTEM_PROMPT, prompt, maxTokens: 8192, model }),
    );
  }

  if (name === "summarize") {
    const model = modelForTool("summarize");
    const context = await gatherContext({
      files: args.files,
      diffArgs: args.diffArgs,
      model,
      taskClass: "summarize",
    });
    const style = args.style || "one paragraph";
    const prompt = `Summarize the following as a ${style}.\n\n${context || "(no context provided)"}`;
    onPrompt?.({ system: SYSTEM_PROMPT, prompt, model });
    return withVerifiedCitations(await callModel({ system: SYSTEM_PROMPT, prompt, model }));
  }

  throw new Error(`Unknown tool "${name}"`);
}

const server = new Server({ name: "wiserepo", version: "0.1.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    return { content: [{ type: "text", text: await runTool(name, args) }] };
  } catch (err) {
    return { content: [{ type: "text", text: `wiserepo error: ${err.message}` }], isError: true };
  }
});

// Guard the stdio bootstrap so this module can be imported by tests (for
// `gatherContext`, `TOOLS`, `runTool`, etc.) without hanging on a transport
// that waits forever for input nobody sends. Only actually connect when this
// file is run directly, e.g. `node src/mcp-server.mjs` (how Claude Code
// launches it). pathToFileURL (not manual string surgery) is what makes this
// comparison correct on Windows, where a hand-built `file://${argv[1]}` string
// is missing the extra leading slash before the drive letter that
// import.meta.url actually has.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
