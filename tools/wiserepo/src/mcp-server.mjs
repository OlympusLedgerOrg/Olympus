#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { callModel } from "./backend.mjs";
import { readRepoFile, gitDiff, gitGrep, truncateText, wouldTruncate } from "./repo.mjs";

// Total context budget across every file/diff/grep a single tool call pulls
// in, independent of the per-piece truncation each helper already applies.
// Without this a request naming 30 files each just under their own limit
// would still blow well past the model's context window.
const TOTAL_CONTEXT_BUDGET_CHARS = 300_000;

// Hard cap on how many files a single request may name. Without this,
// gatherContext reads and buffers EVERY requested file in full before the
// combined-budget truncation below ever runs — a request repeating a large
// path many times causes unbounded I/O and memory allocation up front, with
// the budget only trimming the final string. Capping the count bounds that
// work regardless of what the budget ends up doing.
const MAX_FILES_PER_REQUEST = 40;

const BACKEND_PROPERTY = {
  type: "string",
  enum: ["claude", "openai"],
  description: "Which API key/model to use. Defaults to $WISEREPO_BACKEND or claude.",
};

const TOOLS = [
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
        backend: BACKEND_PROPERTY,
      },
      required: ["question"],
    },
  },
  {
    name: "review_diff",
    description:
      "Review a git diff against this repo's CLAUDE.md engineering standards (invariants, hard boundaries, etc). " +
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
        backend: BACKEND_PROPERTY,
      },
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
        backend: BACKEND_PROPERTY,
      },
    },
  },
];

export async function gatherContext({ files = [], grep, diffArgs }) {
  if (files.length > MAX_FILES_PER_REQUEST) {
    throw new Error(
      `Requested ${files.length} files, wiserepo's per-request cap is ${MAX_FILES_PER_REQUEST} — narrow the list`,
    );
  }

  const parts = [];
  let runningChars = 0;
  let filesTruncated = false;

  if (grep) {
    const hits = await gitGrep(grep);
    const part = `## git grep "${grep}"\n\`\`\`\n${hits || "(no matches)"}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }
  if (diffArgs) {
    const diff = await gitDiff(diffArgs);
    const part = `## git diff ${diffArgs.join(" ")}\n\`\`\`diff\n${diff || "(empty diff)"}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }
  for (const f of files) {
    // Stop READING once the budget is already spent, rather than reading
    // every file in full and only truncating the joined string afterward —
    // that pattern still pays the full I/O/memory cost of every requested
    // file before the budget has any effect.
    if (runningChars >= TOTAL_CONTEXT_BUDGET_CHARS) {
      filesTruncated = true;
      break;
    }
    const content = await readRepoFile(f, { maxBytes: TOTAL_CONTEXT_BUDGET_CHARS - runningChars });
    const part = `## ${f}\n\`\`\`\n${content}\n\`\`\``;
    parts.push(part);
    runningChars += part.length;
  }

  const joined = parts.join("\n\n");
  const budgeted = truncateText(joined, TOTAL_CONTEXT_BUDGET_CHARS, "combined context");
  if (filesTruncated || wouldTruncate(joined, TOTAL_CONTEXT_BUDGET_CHARS)) {
    // Surface this loudly rather than let the model quietly answer from a
    // partial view without saying so. wouldTruncate (not a length
    // comparison) is what makes this reliable even when the appended
    // truncation note pushes `budgeted` longer than `joined`.
    return (
      budgeted +
      `\n\n[wiserepo: total context exceeded ${TOTAL_CONTEXT_BUDGET_CHARS} chars — narrow the file/grep list for full coverage]`
    );
  }
  return budgeted;
}

const SYSTEM_PROMPT =
  "You are wiserepo, a self-hosted repo assistant for the Olympus verifiable-ledger codebase. " +
  "Be precise, cite file paths and line numbers when possible, and never invent code you have not been shown.";

const server = new Server({ name: "wiserepo", version: "0.1.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    if (name === "repo_qa") {
      const context = await gatherContext({ files: args.files, grep: args.grep });
      const prompt = `${context ? context + "\n\n" : ""}Question: ${args.question}`;
      const answer = await callModel({ system: SYSTEM_PROMPT, prompt, backend: args.backend });
      return { content: [{ type: "text", text: answer }] };
    }

    if (name === "review_diff") {
      const diffArgs = args.diffArgs?.length ? args.diffArgs : ["HEAD"];
      const diff = await gitDiff(diffArgs);
      let claudeMd = "";
      try {
        claudeMd = await readRepoFile("CLAUDE.md");
      } catch (err) {
        // Only a genuinely missing file is safe to silently review without
        // standards. A permission error, a path-type error (e.g. CLAUDE.md
        // is a directory), or any other I/O failure is a real problem the
        // caller should see — swallowing those would silently produce a
        // review that looks standards-checked but never actually was.
        if (err.code !== "ENOENT") throw err;
      }
      const prompt =
        `Review this diff against the project's engineering standards below. ` +
        `Flag correctness bugs, invariant violations, and missed test coverage. Be concise, most-severe first.\n\n` +
        (claudeMd ? `## CLAUDE.md (standards)\n\`\`\`\n${claudeMd}\n\`\`\`\n\n` : "") +
        `## Diff\n\`\`\`diff\n${diff || "(empty diff)"}\n\`\`\``;
      const review = await callModel({
        system: SYSTEM_PROMPT,
        prompt,
        backend: args.backend,
        maxTokens: 8192,
      });
      return { content: [{ type: "text", text: review }] };
    }

    if (name === "summarize") {
      const context = await gatherContext({ files: args.files, diffArgs: args.diffArgs });
      const style = args.style || "one paragraph";
      const prompt = `Summarize the following as a ${style}.\n\n${context || "(no context provided)"}`;
      const summary = await callModel({ system: SYSTEM_PROMPT, prompt, backend: args.backend });
      return { content: [{ type: "text", text: summary }] };
    }

    throw new Error(`Unknown tool "${name}"`);
  } catch (err) {
    return { content: [{ type: "text", text: `wiserepo error: ${err.message}` }], isError: true };
  }
});

// Guard the stdio bootstrap so this module can be imported by tests (for
// `gatherContext`, `TOOLS`, etc.) without hanging on a transport that waits
// forever for input nobody sends. Only actually connect when this file is
// run directly, e.g. `node src/mcp-server.mjs` (how Claude Code launches it).
// pathToFileURL (not manual string surgery) is what makes this comparison
// correct on Windows, where a hand-built `file://${argv[1]}` string is
// missing the extra leading slash before the drive letter that
// import.meta.url actually has.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
