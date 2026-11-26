#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Shell entry point for wiserepo.
//
// The MCP server (src/mcp-server.mjs) is the primary interface, but MCP
// registration is read when a client starts, so an already-running session
// cannot pick up a newly added server. This CLI calls the SAME runTool() the
// MCP transport calls — one implementation, two entry points — so it cannot
// drift from the server it wraps.

import process from "node:process";
import { pathToFileURL } from "node:url";
import { TOOLS, runTool } from "../src/mcp-server.mjs";
import { checkInvariants } from "../src/olympus.mjs";
import { ModelRequestError, ModelUnavailableError } from "../src/backend.mjs";

const EXIT_OK = 0;
const EXIT_ERROR = 1;
const EXIT_BACKEND_UNAVAILABLE = 2;

class UsageError extends Error {}

const USAGE = `wiserepo — call the Olympus repo tools from the shell

Usage:
  wiserepo <command> [options]

Commands:
  tools                 List the available tools and their descriptions
  context               context.json project facts (no model)
  circuits              ZK artifact readiness (no model)
  invariants [--check]  ADR-0005/0022 constants across implementations (no model)
  qa <question>         Answer a question grounded in repo files (needs Ollama)
  review                Review a diff against AGENTS.md standards (needs Ollama)
  summarize             Summarize files or a diff (needs Ollama)

Options:
  -f, --file <path>     Repo-relative file to include (repeatable)
      --grep <pattern>  git-grep pattern to include as context
      --style <style>   summarize style (default "one paragraph")
      --diff-args <...> Remaining args go to git diff (must be last)
      --check           invariants: exit 1 if a constant is missing from a file
  -h, --help            Show this help

Exit codes: 0 success · 1 usage/request error · 2 backend unavailable`;

function needValue(argv, index, flag) {
  const value = argv[index];
  if (value === undefined || value.startsWith("-")) {
    throw new UsageError(`${flag} requires a value`);
  }
  return value;
}

/**
 * Parse the CLI argv. `--diff-args` deliberately consumes everything after it:
 * diff args are already an argv fragment (`main...HEAD --stat`), and trying to
 * decide which of those tokens is "a flag for wiserepo" versus "a flag for git
 * diff" is exactly the ambiguity sanitizeDiffArgs exists to resolve later.
 */
export function parseArgs(argv) {
  const parsed = {
    command: null,
    positional: [],
    files: [],
    diffArgs: [],
    grep: undefined,
    style: undefined,
    check: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }
    if (arg === "--check") {
      parsed.check = true;
      continue;
    }
    if (arg === "--file" || arg === "-f") {
      parsed.files.push(needValue(argv, ++i, arg));
      continue;
    }
    if (arg.startsWith("--file=")) {
      parsed.files.push(arg.slice("--file=".length));
      continue;
    }
    if (arg === "--grep") {
      parsed.grep = needValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--style") {
      parsed.style = needValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--diff-args") {
      parsed.diffArgs = argv.slice(i + 1);
      break;
    }
    if (arg.startsWith("-")) {
      throw new UsageError(`unknown option "${arg}"`);
    }
    if (parsed.command === null) {
      parsed.command = arg;
    } else {
      parsed.positional.push(arg);
    }
  }

  return parsed;
}

function write(stream, text) {
  stream.write(text.endsWith("\n") ? text : `${text}\n`);
}

export async function main(argv = process.argv.slice(2), io = process) {
  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    io.stderr.write(`wiserepo: ${err.message}\n\n${USAGE}\n`);
    return EXIT_ERROR;
  }

  if (parsed.help) {
    write(io.stdout, USAGE);
    return EXIT_OK;
  }
  if (parsed.command === null) {
    io.stderr.write(`${USAGE}\n`);
    return EXIT_ERROR;
  }

  try {
    switch (parsed.command) {
      case "tools":
        write(io.stdout, TOOLS.map((tool) => `${tool.name}\n  ${tool.description}`).join("\n\n"));
        return EXIT_OK;

      case "context":
        write(io.stdout, await runTool("olympus_context"));
        return EXIT_OK;

      case "circuits":
        write(io.stdout, await runTool("circuit_status"));
        return EXIT_OK;

      case "invariants": {
        const result = await checkInvariants();
        write(io.stdout, JSON.stringify(result, null, 2));
        if (parsed.check) {
          const missing = result.invariants.filter((inv) => inv.found_in_all_files === false);
          if (missing.length > 0) {
            io.stderr.write(
              `wiserepo: invariant missing from an expected file: ${missing
                .map((inv) => inv.id)
                .join(", ")}\n`,
            );
            return EXIT_ERROR;
          }
        }
        return EXIT_OK;
      }

      case "qa": {
        const question = parsed.positional.join(" ").trim();
        if (!question) throw new UsageError("qa requires a question");
        write(
          io.stdout,
          await runTool("repo_qa", {
            question,
            files: parsed.files,
            grep: parsed.grep,
          }),
        );
        return EXIT_OK;
      }

      case "review":
        write(io.stdout, await runTool("review_diff", { diffArgs: parsed.diffArgs }));
        return EXIT_OK;

      case "summarize":
        write(
          io.stdout,
          await runTool("summarize", {
            files: parsed.files,
            diffArgs: parsed.diffArgs,
            style: parsed.style,
          }),
        );
        return EXIT_OK;

      default:
        throw new UsageError(`unknown command "${parsed.command}"`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.stderr.write(`wiserepo: ${err.message}\n\n${USAGE}\n`);
      return EXIT_ERROR;
    }
    if (err instanceof ModelUnavailableError) {
      io.stderr.write(`wiserepo: backend unavailable — ${err.message}\n`);
      return EXIT_BACKEND_UNAVAILABLE;
    }
    if (err instanceof ModelRequestError) {
      io.stderr.write(`wiserepo: request error — ${err.message}\n`);
      return EXIT_ERROR;
    }
    io.stderr.write(`wiserepo: ${err.message}\n`);
    return EXIT_ERROR;
  }
}

// Same guard mcp-server.mjs uses: only run when invoked directly, so tests can
// import parseArgs/main without executing a command as a side effect.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
