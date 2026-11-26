#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * One question, one local answer, policy first.
 *
 * This is the shell-side `local` tier: it asks the machine's Ollama model a
 * question about a handful of repo files, and refuses when
 * `tools/agent-policy` says the request may not reach the local model. The
 * guard is the same module wiserepo's MCP tools and CLI call, so "the wrapper
 * is easier to sneak past" is not a thing that can be true.
 *
 * It deliberately has no second Ollama client. `../wiserepo/src/backend.mjs`
 * already solves the two problems a naive fetch loop gets wrong — Node's own
 * 300 s body timeout on a multi-minute CPU call, and an Ollama `num_ctx` that
 * silently truncates an oversized prompt — and it validates that the
 * destination is loopback. Reusing it keeps one place to be right about both.
 */

import { readFileSync } from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { logUsage } from "../agent-policy/log.mjs";
import {
  PolicyError,
  decideTask,
  loadPolicy,
  modelFor,
  normalizeRepoPath,
  refusalMessage,
} from "../agent-policy/policy.mjs";
import { resolveInRepoFollowingSymlinks } from "../wiserepo/src/repo.mjs";

// Prompt ceilings in characters, not tokens: the ratio varies by file, but a
// cap in the units actually measured is honest about what it enforces. Every
// cut is reported — a silently truncated file is the failure this exists to
// avoid, because the model then answers confidently from a partial view.
export const MAX_FILE_CHARS = 24_000;
export const MAX_PROMPT_CHARS = 48_000;

export const SYSTEM_PROMPT =
  "You answer questions about a software repository from the files you are given. " +
  "Use only those files, and say plainly when they do not contain the answer. " +
  "Cite path:line for claims about code. You are a first-pass helper: never present " +
  "a security, cryptographic, or correctness verdict as if it were verified.";

export const USAGE = `Usage: node tools/qwen-local/ask.mjs [options] "question"

Options:
  -f, --file <path>   repo file to send (repeatable; only allowlisted paths pass)
  --task <class>      task class the request belongs to (default: qa)
  --check             print the policy decision and exit; never calls the model
  --json              print {answer, model, taskClass, files} as JSON
  --help              show this message

Exit codes: 0 answered, 1 usage/request error, 2 backend unavailable,
3 refused by the agent policy (escalate; do not retry).
`;

/** A usage or local-file problem: the caller's request, not the policy. */
export class ToolError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "ToolError";
  }
}

/** The Ollama client, loaded on demand so `--check` needs no dependencies. */
async function loadBackend() {
  try {
    return await import("../wiserepo/src/backend.mjs");
  } catch (error) {
    if (error?.code === "ERR_MODULE_NOT_FOUND") {
      throw new ToolError(
        "the local backend could not be loaded: tools/qwen-local reuses wiserepo's Ollama " +
          "client, so its dependencies must be installed (`npm install --prefix tools/wiserepo`)",
        { cause: error },
      );
    }
    throw error;
  }
}

/**
 * Read one repo file, refusing anything that escapes the repository.
 *
 * `normalizeRepoPath` refuses absolute paths and `..` but also lower-cases,
 * which would break a read on a case-sensitive filesystem — so the original
 * spelling goes to wiserepo's `resolveInRepoFollowingSymlinks`, the realpath
 * confinement its own tools use. Keeping one implementation matters: this is
 * the check that stops a repo-tracked symlink to `~/.ssh/id_rsa` being read as
 * though it were a repo file.
 */
export async function readRepoFile(rawPath) {
  if (normalizeRepoPath(rawPath) === null) {
    throw new ToolError(`refusing to read "${rawPath}": not a plain repo-relative path`);
  }
  let real;
  try {
    real = await resolveInRepoFollowingSymlinks(rawPath);
  } catch (error) {
    throw new ToolError(`cannot read "${rawPath}": ${error.message}`, { cause: error });
  }
  try {
    return readFileSync(real, "utf8");
  } catch (error) {
    throw new ToolError(`cannot read "${rawPath}": ${error.code ?? error.message}`, {
      cause: error,
    });
  }
}

/**
 * Decide whether this request may reach the local model, and which model.
 *
 * Uses `decideTask`, the same entry wiserepo's tools use, so path denials,
 * prose escalation, and unknown task classes all behave identically here, and
 * `refusalMessage` prints the same instruction those tools print.
 */
export function planAsk({ question, paths = [], taskClass = "qa", policy = loadPolicy() }) {
  if (typeof question !== "string" || question.trim() === "") {
    throw new ToolError("a question is required");
  }
  if (!Object.hasOwn(policy.taskClasses, taskClass)) {
    throw new PolicyError(
      `agent policy: unknown task class "${taskClass}" (known: ` +
        `${Object.keys(policy.taskClasses).join(", ")}); add the class to ` +
        `tools/agent-policy/policy.json rather than borrowing another class's reach`,
      { taskClass },
    );
  }
  const decision = decideTask({ taskClass, paths, text: question, policy });
  if (!decision.qwenAllowed) {
    // Same sentence wiserepo's tools print, from the same function.
    throw new PolicyError(refusalMessage(decision.deniedPaths, decision.reason), {
      taskClass,
      denied: decision.deniedPaths,
    });
  }
  return {
    taskClass,
    tier: "local",
    model: process.env.WISEREPO_OLLAMA_MODEL || modelFor("local", "local", policy),
    files: [...paths],
  };
}

/**
 * Assemble the prompt, naming every file it could not fit.
 *
 * Budget is spent in the order given, which is why the caller controls it: the
 * files named last are the ones that lose, and that is reported rather than
 * left for the reader to infer from a confident answer.
 */
export function buildPrompt(question, files) {
  const sections = [];
  const includedPaths = [];
  const droppedPaths = [];
  let used = 0;
  for (const file of files) {
    const remaining = MAX_PROMPT_CHARS - used;
    const cap = Math.min(MAX_FILE_CHARS, remaining);
    // A section needs room for its header, fences and the truncation note; an
    // empty one is worse than an honest omission.
    if (cap < 200) {
      droppedPaths.push(file.path);
      continue;
    }
    const text =
      file.text.length > cap
        ? `${file.text.slice(0, cap)}\n\n[truncated: ${file.text.length - cap} of ` +
          `${file.text.length} characters omitted]`
        : file.text;
    used += text.length;
    sections.push(`File: ${file.path}\n\`\`\`\n${text}\n\`\`\``);
    includedPaths.push(file.path);
  }
  if (droppedPaths.length > 0) {
    sections.push(`[not sent (prompt budget): ${droppedPaths.join(", ")}]`);
  }
  sections.push(`Question: ${question}`);
  return { prompt: sections.join("\n\n"), includedPaths, droppedPaths };
}

/**
 * Ask the local model, after the policy has agreed to it.
 *
 * `backend` exists so tests exercise the whole path without Ollama; it must
 * provide `callModel`, the same shape backends/backends differ in.
 */
export async function ask({ question, paths = [], taskClass = "qa", backend, plan }) {
  const decided = plan ?? planAsk({ question, paths, taskClass });
  const files = await Promise.all(
    paths.map(async (rawPath) => ({ path: rawPath, text: await readRepoFile(rawPath) })),
  );
  const built = buildPrompt(question, files);
  if (files.length > 0 && built.includedPaths.length === 0) {
    throw new ToolError(
      "no file fits the prompt budget; name fewer or smaller files " +
        `(per-file ${MAX_FILE_CHARS} chars, total ${MAX_PROMPT_CHARS})`,
    );
  }
  const client = backend ?? (await loadBackend());
  const startedAt = Date.now();
  // Ollama reports the token counts on its final event; the backend forwards
  // them here so a call can be recorded as measured, not estimated.
  let tokens = null;
  const answer = await client.callModel({
    system: SYSTEM_PROMPT,
    prompt: built.prompt,
    model: decided.model,
    onStats: (stats) => {
      tokens = stats;
    },
  });
  return {
    ...decided,
    answer,
    includedPaths: built.includedPaths,
    droppedPaths: built.droppedPaths,
    tokens,
    durationMs: Date.now() - startedAt,
  };
}

export function parseArgs(argv) {
  const options = { question: "", files: [], taskClass: "qa", check: false, json: false };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined) throw new ToolError(`${arg} needs a value`);
      return next;
    };
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--check") options.check = true;
    else if (arg === "--json") options.json = true;
    else if (arg === "-f" || arg === "--file") options.files.push(value());
    else if (arg.startsWith("--file=")) options.files.push(arg.slice(7));
    else if (arg === "--task") options.taskClass = value();
    else if (arg.startsWith("--task=")) options.taskClass = arg.slice(7);
    else if (arg.startsWith("-") && arg !== "-") throw new ToolError(`unknown option: ${arg}`);
    else positional.push(arg);
  }
  options.question = positional.join(" ").trim();
  return options;
}

export async function main(argv = process.argv.slice(2), { backend } = {}) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`qwen-local: ${error.message}\n${USAGE}`);
    return 1;
  }
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (!options.question) {
    process.stderr.write(USAGE);
    return 1;
  }
  const request = {
    question: options.question,
    paths: options.files,
    taskClass: options.taskClass,
  };
  try {
    const plan = planAsk(request);
    if (options.check) {
      process.stdout.write(`${JSON.stringify({ ...plan, allowed: true }, null, 2)}\n`);
      return 0;
    }
    const result = await ask({ ...request, backend, plan });
    if (options.json) {
      const { answer, model, taskClass, includedPaths, droppedPaths } = result;
      process.stdout.write(
        `${JSON.stringify({ answer, model, taskClass, files: includedPaths, droppedPaths }, null, 2)}\n`,
      );
    } else {
      process.stdout.write(result.answer.endsWith("\n") ? result.answer : `${result.answer}\n`);
    }
    try {
      logUsage({
        model: result.model,
        taskClass: result.taskClass,
        files: result.includedPaths,
        promptTokens: result.tokens?.promptTokens ?? null,
        completionTokens: result.tokens?.completionTokens ?? null,
        durationMs: result.durationMs,
      });
    } catch (error) {
      // A full disk must not discard an answer that already cost minutes.
      process.stderr.write(`qwen-local: could not write the usage log: ${error.message}\n`);
    }
    return 0;
  } catch (error) {
    if (error instanceof PolicyError) {
      process.stderr.write(`${error.message}\n`);
      return 3;
    }
    // Classified by name, not instanceof: the backend module is imported
    // lazily, and a caller-supplied stub may throw the same shape.
    if (error?.name === "ModelUnavailableError") {
      process.stderr.write(`qwen-local: ${error.message}\n`);
      return 2;
    }
    if (error instanceof ToolError) {
      process.stderr.write(`qwen-local: ${error.message}\n`);
      return 1;
    }
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
