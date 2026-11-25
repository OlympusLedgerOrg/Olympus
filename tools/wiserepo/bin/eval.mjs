#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Score the model-backed tools against golden cases: repo_qa, review_diff and
// summarize.
//
// Without this, every model decision here is vibes: "is 7B better than 4B for
// review", "does the bigger context budget help", "did the prompt change help"
// are argued rather than measured. Each case names the strings a correct answer
// must contain, so a run produces a number that can be compared across models,
// context windows, prompt revisions and padding.
//
// repo_qa runs against this repo. review_diff and summarize run against ONE
// THROWAWAY git repo built from eval/fixtures/ for the whole run — see
// withFixtureRepo below, which exists because both tools take `git diff`
// arguments, not diff text.
//
// Usage:
//   node bin/eval.mjs                     # every suite, every case
//   node bin/eval.mjs --task qa           # one suite (the cheap one)
//   node bin/eval.mjs --limit 2           # first 2 cases per suite (smoke test)
//   node bin/eval.mjs --model qwen2.5-coder:3b   # compare tags on the same cases
//   node bin/eval.mjs --write-baseline    # record the scores eval/baseline.json
//   node bin/eval.mjs --show-answers      # print each raw answer under its verdict
//
// --show-answers exists because the score alone cannot say WHY a case moved: a
// prompt change that rewords a correct review trips a positive expectation, and
// a PASS that happens to avoid a forbidden string looks identical to one that
// read the diff. The verdict lines stay the same; the answers go below them.
//
// Exit codes: 0 whenever the run completed (this is a benchmark, not a gate),
// 2 when the backend was unavailable.

import process from "node:process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { missingExpectations, unexpectedMentions } from "../src/eval-match.mjs";
import { gitDiff } from "../src/repo.mjs";
import { runTool } from "../src/mcp-server.mjs";
import { verifyCitations } from "../src/citations.mjs";
import { ModelUnavailableError, DEFAULT_OLLAMA_MODEL } from "../src/backend.mjs";

const execFileAsync = promisify(execFile);

const EVAL_DIR = fileURLToPath(new URL("../eval", import.meta.url));
// tools/wiserepo/bin/eval.mjs -> repo root, where the real AGENTS.md lives.
const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const BASELINE_PATH = path.join(EVAL_DIR, "baseline.json");

const SUITE_NAMES = ["qa", "review", "summarize"];

function needTask(value) {
  if (value === undefined) throw new Error("--task needs a value");
  if (value !== "all" && !SUITE_NAMES.includes(value)) {
    throw new Error(`--task must be one of all, ${SUITE_NAMES.join(", ")}`);
  }
  return value;
}

// Covers both `--model` with no following argument and the empty `--model=`
// form. Validating where the value is read is the only place that can tell
// those apart from a tag; a later `argv.includes("--model")` re-check
// duplicates it and still lets `--model=` through.
function needModel(value) {
  if (!value) throw new Error("--model needs a value");
  return value;
}

export function parseArgs(argv) {
  const options = {
    limit: Infinity,
    model: undefined,
    showAnswers: false,
    task: "all",
    writeBaseline: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--limit") {
      const value = Number(argv[++i]);
      if (!Number.isInteger(value) || value < 1)
        throw new Error("--limit needs a positive integer");
      options.limit = value;
    } else if (arg.startsWith("--limit=")) {
      const value = Number(arg.slice("--limit=".length));
      if (!Number.isInteger(value) || value < 1)
        throw new Error("--limit needs a positive integer");
      options.limit = value;
    } else if (arg === "--model") {
      options.model = needModel(argv[++i]);
    } else if (arg.startsWith("--model=")) {
      options.model = needModel(arg.slice("--model=".length));
    } else if (arg === "--task") {
      options.task = needTask(argv[++i]);
    } else if (arg.startsWith("--task=")) {
      options.task = needTask(arg.slice("--task=".length));
    } else if (arg === "--write-baseline") {
      options.writeBaseline = true;
    } else if (arg === "--show-answers") {
      options.showAnswers = true;
    } else {
      throw new Error(`unknown option "${arg}"`);
    }
  }
  return options;
}

/**
 * Build the fixture repo, run `fn` with WISEREPO_ROOT pointing at it, then
 * restore the previous root and delete the repo.
 *
 * Both fixture suites (`review` and `summarize`) run inside a SINGLE call, so
 * they review and summarize the identical checkout. Building one repo per
 * suite meant paying git setup twice and left a gap where a fixture edit could
 * make the two suites score different trees while the report showed one
 * baseline.
 *
 * `review_diff` and `summarize` accept `git diff` arguments, not diff text, and
 * `repo.mjs` resolves everything through `repoRoot()` — which reads
 * WISEREPO_ROOT on every call. Pointing that at a temp repo is therefore the
 * only way to exercise the REAL tool path against a planted bug without
 * inventing a second code path for the eval to drift from.
 *
 * Both states are COMMITTED and the diff is taken between two revisions
 * (`HEAD~1..HEAD`) rather than from the working tree. That is not stylistic:
 * the two fixture files happen to be the same byte length, so an uncommitted
 * overwrite lands inside git's racy-clean window and `git diff HEAD` reports a
 * CLEAN tree — the eval then scores an empty diff and the failure looks like a
 * model miss. Committed blobs are compared by content, so the fixture diff
 * cannot silently vanish.
 */
async function withFixtureRepo(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "wiserepo-eval-"));
  const previousRoot = process.env.WISEREPO_ROOT;
  try {
    await execFileAsync("git", ["init", "--quiet", dir]);
    await mkdir(path.join(dir, "src"), { recursive: true });
    await copyFile(
      path.join(EVAL_DIR, "fixtures", "pager.before.js"),
      path.join(dir, "src", "pager.js"),
    );
    // review_diff grounds on AGENTS.md (see AGENTS_MD in src/mcp-server.mjs).
    // Give the fixture repo the real one and commit it, so the standards block
    // is authentic while the file itself never appears in the diff.
    await copyFile(path.join(REPO_ROOT, "AGENTS.md"), path.join(dir, "AGENTS.md"));
    await execFileAsync("git", ["-C", dir, "add", "."]);
    await execFileAsync("git", [
      "-C",
      dir,
      "-c",
      "user.name=wiserepo-eval",
      "-c",
      "user.email=eval@localhost",
      "commit",
      "--quiet",
      "-m",
      "fixture: before",
    ]);
    await copyFile(
      path.join(EVAL_DIR, "fixtures", "pager.after.js"),
      path.join(dir, "src", "pager.js"),
    );
    // Stage by CONTENT HASH, not `git add .`. The two fixture files are the same
    // byte length, so a same-second overwrite can stay invisible behind git's
    // stat cache: `git add` then stages nothing and `git commit` fails with a
    // clean tree (the second way this fixture produced no diff). --cacheinfo
    // writes the exact blob into the index, so the commit cannot be a no-op and
    // the diff cannot depend on timestamps.
    const { stdout: afterBlob } = await execFileAsync("git", [
      "-C",
      dir,
      "hash-object",
      "-w",
      "src/pager.js",
    ]);
    await execFileAsync("git", [
      "-C",
      dir,
      "update-index",
      "--add",
      "--cacheinfo",
      `100644,${afterBlob.trim()},src/pager.js`,
    ]);
    await execFileAsync("git", [
      "-C",
      dir,
      "-c",
      "user.name=wiserepo-eval",
      "-c",
      "user.email=eval@localhost",
      "commit",
      "--quiet",
      "-m",
      "fixture: after (planted bug)",
    ]);
    process.env.WISEREPO_ROOT = dir;
    // A fixture that produces no diff would score 0/1 and look like a model
    // regression. Fail as a setup error instead, by name.
    const fixtureDiff = await gitDiff(["HEAD~1", "HEAD"]);
    if (!fixtureDiff.trim()) {
      throw new Error(
        "fixture repo produced an EMPTY diff — eval/fixtures or the repo setup is broken, not the model",
      );
    }
    return await fn(dir);
  } finally {
    if (previousRoot === undefined) delete process.env.WISEREPO_ROOT;
    else process.env.WISEREPO_ROOT = previousRoot;
    await rm(dir, { recursive: true, force: true });
  }
}

const SUITE_SPECS = {
  qa: {
    fileName: "golden-questions.json",
    needsFixture: false,
    call: (item) => runTool("repo_qa", { question: item.question, files: item.files }),
  },
  review: {
    fileName: "golden-review.json",
    needsFixture: true,
    call: (item) => runTool("review_diff", { diffArgs: item.diffArgs }),
  },
  summarize: {
    fileName: "golden-summarize.json",
    needsFixture: true,
    call: (item) => runTool("summarize", { files: item.files, style: item.style }),
  },
};

async function loadCases(fileName, limit) {
  const cases = JSON.parse(await readFile(path.join(EVAL_DIR, fileName), "utf8"));
  return cases.slice(0, limit);
}

/**
 * The answer without fenced code blocks.
 *
 * Expectations ask what the answer CONCLUDED; a pasted diff or file excerpt is
 * input, not a conclusion. Without this the phantom case passed on a review
 * that only discussed `pageCount`, because the `clampPage` identifier it is
 * scored on appeared in the diff the review copied back — the echo the case
 * exists to rule out. Phantom scanning still sees the whole answer (see
 * eval-match.mjs): showing a removed line as live is a failure wherever it is.
 */
function proseOnly(answer) {
  return String(answer ?? "").replace(/```[\s\S]*?```/g, "\n");
}

/**
 * A case passes only when the answer says everything it must, asserts no removed
 * text as current, AND every cited path resolves.
 *
 * The citation check used to be printed beside the verdict rather than part of
 * it, so a review that invented file paths still scored PASS. That is the one
 * failure this repo's whole thesis rules out: an invented citation reads like
 * evidence and is none. It is not a separate suite because it applies to every
 * answer any suite produces, and it is not waived for the fixture repo — a
 * review there that cites a plausible-looking file it never read fails too.
 *
 * Exported so the gate can be tested without a model call.
 */
export function casePassed({ missing, phantom, badCitations }) {
  return missing.length === 0 && phantom.length === 0 && badCitations.length === 0;
}

/**
 * Score one answer against one golden case.
 *
 * Exported so the WIRING is testable without a model call: expectations read
 * the answer's prose, phantom scanning reads the whole answer, and citations are
 * verified against the tree. A test that calls proseOnly and missingExpectations
 * separately still passes if runSuite forgets to compose them.
 */
export async function scoreCase(answer, item) {
  const missing = missingExpectations(proseOnly(answer), item.expect);
  const phantom = unexpectedMentions(answer, item.expect_absent);
  const { missing: badCitations } = await verifyCitations(answer);
  return { missing, phantom, badCitations, ok: casePassed({ missing, phantom, badCitations }) };
}

async function runSuite(name, options) {
  const spec = SUITE_SPECS[name];
  const cases = await loadCases(spec.fileName, options.limit);
  console.log(`\n${name} — ${cases.length} case(s)`);

  let passed = 0;
  let secondsTotal = 0;
  for (const item of cases) {
    const started = Date.now();
    const answer = await spec.call(item);
    const seconds = Math.round((Date.now() - started) / 1000);
    secondsTotal += seconds;

    const { missing, phantom, badCitations, ok } = await scoreCase(answer, item);
    if (ok) passed++;

    console.log(
      `${ok ? "PASS" : "FAIL"}  ${name}/${item.id}  (${seconds}s, ${badCitations.length} unverified citation(s))`,
    );
    if (missing.length > 0) console.log(`      answer never mentioned: ${missing.join(", ")}`);
    if (phantom.length > 0) {
      console.log(`      answer repeated removed text as current: ${phantom.join(", ")}`);
    }
    if (badCitations.length > 0) {
      console.log(
        `      cited paths that do not exist: ${badCitations
          .map((c) => (c.line === null ? c.path : `${c.path}:${c.line}`))
          .join(", ")}`,
      );
    }
    if (options.showAnswers) {
      // Prefixed per line so the transcript stays readable beside the verdicts
      // and is obviously model output rather than harness output.
      console.log(
        answer
          .split("\n")
          .map((line) => `      | ${line}`)
          .join("\n"),
      );
    }
  }
  return { passed, total: cases.length, seconds: secondsTotal };
}

async function readBaseline() {
  try {
    return JSON.parse(await readFile(BASELINE_PATH, "utf8"));
  } catch {
    return null;
  }
}

function formatComparison(baseline, results) {
  const lines = [`baseline (${baseline.recorded_at}, ${baseline.model}):`];
  for (const [name, result] of Object.entries(results)) {
    const before = baseline.suites?.[name];
    lines.push(
      before
        ? `  ${name}: ${before.passed}/${before.total} -> ${result.passed}/${result.total} (${verdict(before, result)})`
        : `  ${name}: no baseline`,
    );
  }
  return lines.join("\n");
}

function verdict(before, after) {
  if (after.passed > before.passed) return "improved";
  // Fewer passes on unchanged cases is the only thing this file calls a
  // regression; a total-count change means the case set moved, not the model.
  if (after.passed < before.passed) return "REGRESSION";
  if ((after.total ?? 0) !== (before.total ?? 0)) return "case set changed";
  return "unchanged";
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const suites = options.task === "all" ? SUITE_NAMES : [options.task];

  console.log(
    `wiserepo eval — ${suites.join(" + ")}, model ${options.model ?? DEFAULT_OLLAMA_MODEL}`,
  );

  // modelForTool reads each suite's override at call time, so setting all three
  // is what makes --model apply to review_diff and summarize too — a comparison
  // across tags is only meaningful when every suite runs the same tag.
  if (options.model) {
    process.env.WISEREPO_MODEL_QA = options.model;
    process.env.WISEREPO_MODEL_REVIEW = options.model;
    process.env.WISEREPO_MODEL_SUMMARIZE = options.model;
  }

  const results = {};
  try {
    const plainSuites = suites.filter((name) => !SUITE_SPECS[name].needsFixture);
    const fixtureSuites = suites.filter((name) => SUITE_SPECS[name].needsFixture);

    // qa stays outside the fixture root on purpose: repo_qa grounds on this
    // repo, and pointing WISEREPO_ROOT at the fixture would make it answer
    // questions about pager.js instead of Olympus.
    for (const name of plainSuites) {
      results[name] = await runSuite(name, options);
    }
    if (fixtureSuites.length > 0) {
      Object.assign(
        results,
        await withFixtureRepo(async () => {
          const fixtureResults = {};
          for (const name of fixtureSuites) fixtureResults[name] = await runSuite(name, options);
          return fixtureResults;
        }),
      );
    }
  } catch (err) {
    if (err instanceof ModelUnavailableError) {
      console.error(`\nbackend unavailable — ${err.message}`);
      return 2;
    }
    throw err;
  }

  const passed = Object.values(results).reduce((sum, r) => sum + r.passed, 0);
  const total = Object.values(results).reduce((sum, r) => sum + r.total, 0);

  console.log("\n" + "─".repeat(72));
  for (const [name, result] of Object.entries(results)) {
    console.log(`${name}: ${result.passed}/${result.total} (${result.seconds}s)`);
  }
  console.log(`overall: ${passed}/${total} (${Math.round((passed / total) * 100)}%)`);

  const baseline = await readBaseline();
  if (baseline) {
    console.log("\n" + formatComparison(baseline, results));
  }

  if (options.writeBaseline) {
    const record = {
      recorded_at: new Date().toISOString(),
      model: options.model ?? DEFAULT_OLLAMA_MODEL,
      suites: results,
    };
    await writeFile(BASELINE_PATH, `${JSON.stringify(record, null, 2)}\n`);
    console.log(`\nbaseline written to eval/baseline.json`);
  }

  return 0;
}

// Same import guard the CLI, the server and the launcher use: tests import
// parseArgs without running a benchmark as a side effect.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      console.error(`wiserepo eval failed: ${err.stack || err.message}`);
      process.exitCode = 1;
    });
}
