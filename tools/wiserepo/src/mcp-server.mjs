#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { callModel } from "./backend.mjs";
import { readRepoFile, gitDiff, gitGrep, truncateText } from "./repo.mjs";

// Total context budget across every file/diff/grep a single tool call pulls
// in, independent of the per-piece truncation each helper already applies.
// Without this a request naming 30 files each just under their own limit
// would still blow well past the model's context window.
const TOTAL_CONTEXT_BUDGET_CHARS = 300_000;

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
          description: "Repo-relative file paths to read as context.",
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
        files: { type: "array", items: { type: "string" } },
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

async function gatherContext({ files = [], grep, diffArgs }) {
  const parts = [];
  if (grep) {
    const hits = await gitGrep(grep);
    parts.push(`## git grep "${grep}"\n\`\`\`\n${hits || "(no matches)"}\n\`\`\``);
  }
  if (diffArgs) {
    const diff = await gitDiff(diffArgs);
    parts.push(`## git diff ${diffArgs.join(" ")}\n\`\`\`diff\n${diff || "(empty diff)"}\n\`\`\``);
  }
  for (const f of files) {
    const content = await readRepoFile(f);
    parts.push(`## ${f}\n\`\`\`\n${content}\n\`\`\``);
  }

  const joined = parts.join("\n\n");
  const budgeted = truncateText(joined, TOTAL_CONTEXT_BUDGET_CHARS, "combined context");
  if (budgeted.length < joined.length) {
    // Surface this loudly rather than let the model quietly answer from a
    // partial view without saying so.
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
      } catch {
        // CLAUDE.md missing — review without the standards doc.
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

const transport = new StdioServerTransport();
await server.connect(transport);
