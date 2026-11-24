#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Score repo_qa against a small set of questions with known answers.
//
// Without this, every model decision here has been vibes: "is 7B better than
// 4B for review", "does the bigger context budget help", "did the prompt change
// help" were all argued rather than measured. Each question names the files to
// ground on and the strings a correct answer must contain, so a run produces a
// number that can be compared across models, context windows and padding.
//
// Usage:
//   node bin/eval.mjs                    # every question
//   node bin/eval.mjs --limit 2          # first two (smoke test)
//   node bin/eval.mjs --model qwen3.5:4b # override the model for the run
//
// Exit codes: 0 always when the run completed (this is a benchmark, not a gate),
// 2 when the backend was unavailable.

import process from "node:process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { missingExpectations } from "../src/eval-match.mjs";
import { runTool } from "../src/mcp-server.mjs";
import { verifyCitations } from "../src/citations.mjs";
import { ModelUnavailableError, DEFAULT_OLLAMA_MODEL } from "../src/backend.mjs";

const QUESTIONS_PATH = path.join(
  fileURLToPath(new URL("..", import.meta.url)),
  "eval",
  "golden-questions.json",
);

function parseLimit(raw) {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("--limit needs a positive integer");
  }
  return value;
}

function parseArgs(argv) {
  const options = { limit: Infinity, model: undefined };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--limit") {
      options.limit = parseLimit(argv[++i]);
    } else if (arg.startsWith("--limit=")) {
      // Both spellings route through the same validation. Previously only the
      // spaced form was checked, so `--limit=abc` stored NaN and
      // `slice(0, NaN)` silently ran zero questions while printing a 0% score.
      options.limit = parseLimit(arg.slice("--limit=".length));
    } else if (arg === "--model") {
      options.model = argv[++i];
    } else if (arg.startsWith("--model=")) {
      options.model = arg.slice("--model=".length);
    } else {
      throw new Error(`unknown option "${arg}"`);
    }
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const questions = JSON.parse(await readFile(QUESTIONS_PATH, "utf8")).slice(0, options.limit);

  console.log(
    `wiserepo eval — ${questions.length} question(s), model ${options.model ?? DEFAULT_OLLAMA_MODEL}`,
  );
  console.log("─".repeat(72));

  let passed = 0;
  for (const item of questions) {
    const started = Date.now();
    let answer;
    try {
      // WISEREPO_MODEL_QA is read at call time by modelForTool, so setting it
      // here is how --model reaches the request without another code path.
      if (options.model) process.env.WISEREPO_MODEL_QA = options.model;
      answer = await runTool("repo_qa", { question: item.question, files: item.files });
    } catch (err) {
      if (err instanceof ModelUnavailableError) {
        console.error(`\nbackend unavailable — ${err.message}`);
        return 2;
      }
      throw err;
    }

    const seconds = ((Date.now() - started) / 1000).toFixed(0);
    const missing = missingExpectations(answer, item.expect);
    const { missing: badCitations } = await verifyCitations(answer);
    const ok = missing.length === 0;
    if (ok) passed++;

    console.log(
      `${ok ? "PASS" : "FAIL"}  ${item.id}  (${seconds}s, ${badCitations.length} unverified citation(s))`,
    );
    if (!ok) {
      console.log(`      answer never mentioned: ${missing.join(", ")}`);
    }
    if (badCitations.length > 0) {
      console.log(`      invented paths: ${badCitations.map((c) => c.path).join(", ")}`);
    }
  }

  console.log("─".repeat(72));
  console.log(
    `score: ${passed}/${questions.length} (${Math.round((passed / questions.length) * 100)}%)`,
  );
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    console.error(`wiserepo eval failed: ${err.stack || err.message}`);
    process.exitCode = 1;
  });
