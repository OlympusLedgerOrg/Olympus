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
//   node bin/eval.mjs --rescore eval/runs/<stamp>.json   # score a recorded run, no model call
//
// --show-answers exists because the score alone cannot say WHY a case moved: a
// prompt change that rewords a correct review trips a positive expectation, and
// a PASS that happens to avoid a forbidden string looks identical to one that
// read the diff. The verdict lines stay the same; the answers go below them.
//
// Every run also writes its raw answers to eval/runs/, together with provenance:
// the repo HEAD, each model's weights digest and effective num_ctx, and a hash of
// the exact prompt text sent. A score on its own is not reproducible — a
// re-pulled tag changes the weights under an unchanged name, and an edited
// AGENTS.md changes what review_diff was asked to judge — so a baseline that
// records only PASS/FAIL cannot say whether two runs are comparable or whether a
// matcher change, not a model change, moved the number. --rescore re-scores a
// recorded run against the current matchers offline, with no model call.
//
// Exit codes: 0 whenever the run completed (this is a benchmark, not a gate),
// 2 when the backend was unavailable.

import process from "node:process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { missingExpectations, unexpectedMentions } from "../src/eval-match.mjs";
import { gitDiff } from "../src/repo.mjs";
import { runTool } from "../src/mcp-server.mjs";
import { verifyCitations } from "../src/citations.mjs";
import {
  ModelUnavailableError,
  DEFAULT_OLLAMA_MODEL,
  modelProvenance,
} from "../src/backend.mjs";

const execFileAsync = promisify(execFile);

const EVAL_DIR = fileURLToPath(new URL("../eval", import.meta.url));
// tools/wiserepo/bin/eval.mjs -> repo root, where the real AGENTS.md lives.
const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const BASELINE_PATH = path.join(EVAL_DIR, "baseline.json");
// One file per run, gitignored: a baseline points at the run that produced it.
const RUNS_DIR = path.join(EVAL_DIR, "runs");

const SUITE_NAMES = ["qa", "review", "summarize"];

function needTask(value) {
  if (value === undefined) throw new Error("--task needs a value");
  if (value !== "all" && !SUITE_NAMES.includes(value)) {
    throw new Error(`--task must be one of all, ${SUITE_NAMES.join(", ")}`);
  }
  return value;
}

// Shared by `--limit N` and `--limit=N`. Only the spaced form used to be
// validated, so `--limit=abc` stored NaN and `slice(0, NaN)` ran zero questions
// while the report still printed a score.
function parseLimit(raw) {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("--limit needs a positive integer");
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

function needPath(flag, value) {
  if (!value) throw new Error(`${flag} needs a value`);
  return value;
}

export function parseArgs(argv) {
  const options = {
    limit: Infinity,
    model: undefined,
    rescore: undefined,
    showAnswers: false,
    task: "all",
    writeBaseline: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--limit") {
      options.limit = parseLimit(argv[++i]);
    } else if (arg.startsWith("--limit=")) {
      options.limit = parseLimit(arg.slice("--limit=".length));
    } else if (arg === "--model") {
      options.model = needModel(argv[++i]);
    } else if (arg.startsWith("--model=")) {
      options.model = needModel(arg.slice("--model=".length));
    } else if (arg === "--task") {
      options.task = needTask(argv[++i]);
    } else if (arg.startsWith("--task=")) {
      options.task = needTask(arg.slice("--task=".length));
    } else if (arg === "--rescore") {
      options.rescore = needPath("--rescore", argv[++i]);
    } else if (arg.startsWith("--rescore=")) {
      options.rescore = needPath("--rescore", arg.slice("--rescore=".length));
    } else if (arg === "--write-baseline") {
      options.writeBaseline = true;
    } else if (arg === "--show-answers") {
      options.showAnswers = true;
    } else {
      throw new Error(`unknown option "${arg}"`);
    }
  }
  // A rescore reads a finished run; it has no fresh scores to record. Silently
  // ignoring the flag would leave a baseline that looks freshly written.
  if (options.rescore && options.writeBaseline) {
    throw new Error("--rescore reads a recorded run; it cannot also --write-baseline");
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
 * Every state is COMMITTED and each case diffs two revisions rather than the
 * working tree. That is not stylistic: fixture states can be the same byte
 * length, so an uncommitted overwrite lands inside git's racy-clean window and
 * `git diff HEAD` reports a CLEAN tree — the eval then scores an empty diff and
 * the failure looks like a model miss. Committed blobs are compared by content,
 * so a fixture diff cannot silently vanish.
 *
 * Three states, so a case can score a correct change as well as a broken one:
 *
 *   HEAD~2  pager.before.js   correct pageCount, off-by-one clampPage
 *   HEAD~1  pager.after.js    planted bug, clampPage fixed
 *   HEAD    pager.fixed.js    both changes correct
 *
 * Three states, three distinct ranges, one per golden case — so no two review
 * cases send the same prompt (`HEAD~2..HEAD~1` bug + fix, `HEAD~2..HEAD` clamp
 * fix only, `HEAD~1..HEAD` pageCount fix only). Two cases sharing a range scored
 * one answer twice: at temperature 0 the second call returned the first
 * verbatim.
 */
async function withFixtureRepo(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "wiserepo-eval-"));
  const previousRoot = process.env.WISEREPO_ROOT;
  const commit = (message) =>
    execFileAsync("git", [
      "-C",
      dir,
      "-c",
      "user.name=wiserepo-eval",
      "-c",
      "user.email=eval@localhost",
      "commit",
      "--quiet",
      "-m",
      message,
    ]);
  // Stage by CONTENT HASH, not `git add .`. A same-second overwrite can stay
  // invisible behind git's stat cache: `git add` then stages nothing and
  // `git commit` fails with a clean tree (the second way this fixture produced
  // no diff). --cacheinfo writes the exact blob into the index, so a commit
  // cannot be a no-op and the diff cannot depend on timestamps.
  const commitState = async (fileName, message) => {
    await copyFile(
      path.join(EVAL_DIR, "fixtures", fileName),
      path.join(dir, "src", "pager.js"),
    );
    const { stdout: blob } = await execFileAsync("git", [
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
      `100644,${blob.trim()},src/pager.js`,
    ]);
    await commit(message);
  };
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
    await commit("fixture: before");
    await commitState("pager.after.js", "fixture: after (planted bug)");
    await commitState("pager.fixed.js", "fixture: fixed (both changes correct)");
    process.env.WISEREPO_ROOT = dir;
    // A fixture that produces no diff would score 0/1 and look like a model
    // regression. Fail as a setup error instead, by name — for every range a
    // golden case actually diffs.
    for (const range of [
      ["HEAD~2", "HEAD~1"],
      ["HEAD~2", "HEAD"],
      ["HEAD~1", "HEAD"],
    ]) {
      if (!(await gitDiff(range)).trim()) {
        throw new Error(
          `fixture repo produced an EMPTY diff for ${range.join("..")} — eval/fixtures or the repo setup is broken, not the model`,
        );
      }
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
    call: (item, onPrompt) =>
      runTool("repo_qa", { question: item.question, files: item.files }, { onPrompt }),
  },
  review: {
    fileName: "golden-review.json",
    needsFixture: true,
    call: (item, onPrompt) =>
      runTool("review_diff", { diffArgs: item.diffArgs }, { onPrompt }),
  },
  summarize: {
    fileName: "golden-summarize.json",
    needsFixture: true,
    call: (item, onPrompt) =>
      runTool("summarize", { files: item.files, style: item.style }, { onPrompt }),
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

function reportProblems({ missing, phantom, badCitations }) {
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
}

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * The digest of everything one model call was shown.
 *
 * Hashes the system prompt too: the review prompt is mostly AGENTS.md content
 * and framing, so a hash of the user message alone would call two materially
 * different review prompts identical. The NUL separator keeps ("ab","c") from
 * hashing like ("a","bc").
 */
export function promptSha256({ system = "", prompt = "" } = {}) {
  return sha256(`${system}\u0000${prompt}`);
}

/** One digest for a whole run, so two baselines can be compared at a glance. */
function runPromptSha256(cases) {
  return sha256(cases.map((entry) => `${entry.suite}/${entry.id}:${entry.prompt_sha256}`).join("\n"));
}

/**
 * Per-suite totals derived from the case records, so a suite's score and the
 * answers it was computed from can never disagree.
 */
export function suiteScores(cases) {
  const suites = {};
  for (const entry of cases) {
    const suite = (suites[entry.suite] ??= { passed: 0, total: 0, seconds: 0 });
    suite.total += 1;
    suite.seconds += entry.seconds ?? 0;
    if (entry.ok) suite.passed += 1;
  }
  return suites;
}

/** The recorded shape: provenance + scores + the answers those scores came from. */
export function buildRunRecord({ recordedAt, model, provenance, cases }) {
  return { recorded_at: recordedAt, model, provenance, suites: suiteScores(cases), cases };
}

/**
 * The baseline is the comparison point, not the transcript. It keeps provenance
 * and per-suite scores plus a pointer to the run file holding the answers, so
 * eval/baseline.json stays small enough to read in a diff while the evidence
 * behind it is still on disk and still scorable.
 */
export function buildBaselineRecord(record, answersPath) {
  const { recorded_at, model, provenance, suites } = record;
  return { recorded_at, model, provenance, suites, answers: answersPath };
}

/** "suite/id" -> golden case, so a recorded answer can be scored without the model. */
export function indexGoldenCases(entries) {
  const byId = new Map();
  for (const { suite, cases } of entries) {
    for (const item of cases) byId.set(`${suite}/${item.id}`, item);
  }
  return byId;
}

/**
 * Re-score recorded answers against the CURRENT matchers and golden cases.
 *
 * This is what makes a stored run auditable after a scoring change, and what
 * lets a recorded run be compared at all without paying for the model call
 * again. Citations are verified against the tree, so re-scoring a run from a
 * different commit is only faithful on that commit (check out the recorded
 * git_sha first) — see the README.
 */
export async function rescoreRecord(entries, goldenById) {
  const scored = [];
  for (const entry of entries) {
    const item = goldenById.get(`${entry.suite}/${entry.id}`);
    if (!item) {
      throw new Error(
        `run record names ${entry.suite}/${entry.id}, which is not a golden case`,
      );
    }
    const { missing, phantom, badCitations, ok } = await scoreCase(entry.answer, item);
    scored.push({ ...entry, verdict: { missing, phantom, badCitations }, ok });
  }
  return scored;
}

async function runSuite(name, options) {
  const spec = SUITE_SPECS[name];
  const cases = await loadCases(spec.fileName, options.limit);
  console.log(`\n${name} — ${cases.length} case(s)`);

  const scored = [];
  for (const item of cases) {
    const started = Date.now();
    // Captured per case, from the tool path itself: a run-level hash cannot say
    // WHICH case's prompt moved, and rebuilding the prompt here would drift
    // from what was sent the first time the prompt changes.
    let request;
    const answer = await spec.call(item, (captured) => {
      request = captured;
    });
    if (!request) {
      throw new Error(
        `${name}/${item.id} never reported its prompt — the run record cannot prove what was scored`,
      );
    }
    const seconds = Math.round((Date.now() - started) / 1000);

    const verdict = await scoreCase(answer, item);
    console.log(
      `${verdict.ok ? "PASS" : "FAIL"}  ${name}/${item.id}  (${seconds}s, ${verdict.badCitations.length} unverified citation(s))`,
    );
    reportProblems(verdict);
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

    scored.push({
      suite: name,
      id: item.id,
      model: request.model,
      seconds,
      prompt_sha256: promptSha256(request),
      answer,
      verdict: {
        missing: verdict.missing,
        phantom: verdict.phantom,
        badCitations: verdict.badCitations,
      },
      ok: verdict.ok,
    });
  }
  return scored;
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

function shortHash(value) {
  return typeof value === "string" && value ? value.slice(0, 12) : "unknown";
}

/**
 * What changed about the RUN rather than about the answers.
 *
 * A score is only comparable across runs when the same commit, prompt and
 * weights produced both. Without this, a prompt edit that also re-pulled the
 * model reads exactly like a prompt regression, and a "REGRESSION" line gets
 * blamed on the last thing that changed rather than the thing that moved.
 */
export function provenanceDiffs(before, after) {
  const was = before ?? {};
  const now = after ?? {};
  const diffs = [];
  // null, not undefined: a baseline recorded before provenance existed must be
  // reported as unknown once, not as a change from "unknown" to "unknown".
  if ((was.git_sha ?? null) !== (now.git_sha ?? null)) {
    diffs.push(`git ${shortHash(was.git_sha)} -> ${shortHash(now.git_sha)}`);
  }
  if ((was.git_dirty ?? null) !== (now.git_dirty ?? null)) {
    diffs.push(
      `worktree ${was.git_dirty === false ? "clean" : was.git_dirty ? "dirty" : "unknown"} -> ` +
        `${now.git_dirty === false ? "clean" : now.git_dirty ? "dirty" : "unknown"}`,
    );
  }
  if ((was.prompt_sha256 ?? null) !== (now.prompt_sha256 ?? null)) {
    diffs.push(`prompt ${shortHash(was.prompt_sha256)} -> ${shortHash(now.prompt_sha256)}`);
  }
  const models = new Set([
    ...Object.keys(was.models ?? {}),
    ...Object.keys(now.models ?? {}),
  ]);
  for (const model of models) {
    const a = was.models?.[model] ?? {};
    const b = now.models?.[model] ?? {};
    if ((a.digest ?? null) !== (b.digest ?? null)) {
      diffs.push(`${model} weights ${shortHash(a.digest)} -> ${shortHash(b.digest)}`);
    }
    if ((a.num_ctx ?? null) !== (b.num_ctx ?? null)) {
      diffs.push(`${model} num_ctx ${a.num_ctx ?? "unknown"} -> ${b.num_ctx ?? "unknown"}`);
    }
  }
  return diffs;
}

function printProvenanceComparison(baseline, provenance) {
  const diffs = provenanceDiffs(baseline.provenance, provenance);
  if (diffs.length === 0) {
    console.log("provenance matches the baseline (same commit, prompt and weights)");
    return;
  }
  console.log("provenance differs from the baseline:");
  for (const line of diffs) console.log(`  ${line}`);
  console.log("  (a score change above is not attributable to one cause alone)");
}

/**
 * Score a recorded run again -- against the current matchers, the current golden
 * cases and the current tree -- and print the result beside the recorded verdict.
 *
 * No model call: this is for checking a scoring change against real answers, and
 * for comparing two recorded runs after the fact. A verdict that differs from
 * the recorded one is the signal; it is printed, not treated as an error.
 */
async function rescoreRun(file) {
  const record = JSON.parse(await readFile(file, "utf8"));
  if (!Array.isArray(record.cases) || record.cases.length === 0) {
    throw new Error(
      `${file} has no recorded answers — that is a baseline, not a run file (see its "answers" field)`,
    );
  }
  const goldenEntries = [];
  for (const name of SUITE_NAMES) {
    goldenEntries.push({ suite: name, cases: await loadCases(SUITE_SPECS[name].fileName, Infinity) });
  }
  const goldenById = indexGoldenCases(goldenEntries);
  const recordedOk = new Map(
    record.cases.map((entry) => [
      `${entry.suite}/${entry.id}`,
      entry.verdict ? casePassed(entry.verdict) : undefined,
    ]),
  );

  console.log(
    `wiserepo eval — re-scoring ${record.cases.length} recorded answer(s), model ${record.model}`,
  );
  console.log(`  recorded ${record.recorded_at}, git ${shortHash(record.provenance?.git_sha)}`);

  // Same split as a live run: qa is scored on this repo, while the fixture
  // suites need the fixture repo or every citation they made resolves nowhere.
  const plain = record.cases.filter((entry) => !SUITE_SPECS[entry.suite]?.needsFixture);
  const fixture = record.cases.filter((entry) => SUITE_SPECS[entry.suite]?.needsFixture);
  const scored = [...(await rescoreRecord(plain, goldenById))];
  if (fixture.length > 0) {
    scored.push(...(await withFixtureRepo(() => rescoreRecord(fixture, goldenById))));
  }

  for (const entry of scored) {
    const was = recordedOk.get(`${entry.suite}/${entry.id}`);
    const moved =
      was === undefined
        ? ""
        : was === entry.ok
          ? ", same verdict as recorded"
          : ", VERDICT CHANGED since recording";
    console.log(
      `${entry.ok ? "PASS" : "FAIL"}  ${entry.suite}/${entry.id}  (${entry.seconds}s${moved})`,
    );
    reportProblems(entry.verdict);
  }

  const suites = suiteScores(scored);
  const passed = scored.filter((entry) => entry.ok).length;

  console.log("\n" + "─".repeat(72));
  for (const [name, result] of Object.entries(suites)) {
    console.log(`${name}: ${result.passed}/${result.total} (${result.seconds}s)`);
  }
  console.log(`overall: ${passed}/${scored.length} (${Math.round((passed / scored.length) * 100)}%)`);

  const baseline = await readBaseline();
  if (baseline) {
    console.log("\n" + formatComparison(baseline, suites));
    printProvenanceComparison(baseline, record.provenance);
  }

  return 0;
}

/** Every model the run actually used, with the weights and window behind it. */
async function modelsUsed(cases) {
  const models = {};
  for (const model of new Set(cases.map((entry) => entry.model))) {
    models[model] = await modelProvenance(model);
  }
  return models;
}

/**
 * The commit, and whether the files that decide the score match it.
 *
 * A SHA on its own can be a lie: run the eval with an edited prompt or matcher
 * and the record names a commit that never contained them. Only the paths that
 * affect the score are inspected, so an unrelated untracked directory (and the
 * gitignored eval/runs) cannot mark every run dirty.
 */
async function gitState() {
  try {
    const [{ stdout: sha }, { stdout: status }] = await Promise.all([
      execFileAsync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"]),
      execFileAsync("git", [
        "-C",
        REPO_ROOT,
        "status",
        "--porcelain",
        "--",
        "AGENTS.md",
        "tools/wiserepo",
      ]),
    ]);
    return { git_sha: sha.trim() || null, git_dirty: status.trim().length > 0 };
  } catch {
    return { git_sha: null, git_dirty: null };
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.rescore) return rescoreRun(options.rescore);

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

  // One record for the whole run: scores are DERIVED from the per-case records,
  // so the summary can never disagree with the answers stored beside it.
  const caseRecords = SUITE_NAMES.filter((name) => results[name]).flatMap(
    (name) => results[name],
  );
  const record = buildRunRecord({
    recordedAt: new Date().toISOString(),
    model: options.model ?? DEFAULT_OLLAMA_MODEL,
    provenance: {
      ...(await gitState()),
      prompt_sha256: runPromptSha256(caseRecords),
      models: await modelsUsed(caseRecords),
    },
    cases: caseRecords,
  });
  const passed = caseRecords.filter((entry) => entry.ok).length;

  console.log("\n" + "─".repeat(72));
  for (const [name, result] of Object.entries(record.suites)) {
    console.log(`${name}: ${result.passed}/${result.total} (${result.seconds}s)`);
  }
  console.log(`overall: ${passed}/${caseRecords.length} (${Math.round((passed / caseRecords.length) * 100)}%)`);

  const baseline = await readBaseline();
  if (baseline) {
    console.log("\n" + formatComparison(baseline, record.suites));
    printProvenanceComparison(baseline, record.provenance);
  }

  await mkdir(RUNS_DIR, { recursive: true });
  const runFile = path.join(RUNS_DIR, `${record.recorded_at.replace(/[:.]/g, "-")}.json`);
  await writeFile(runFile, `${JSON.stringify(record, null, 2)}\n`);
  console.log(`\nanswers + provenance written to ${path.relative(REPO_ROOT, runFile)}`);

  if (options.writeBaseline) {
    const answersPath = path.relative(EVAL_DIR, runFile).split(path.sep).join("/");
    await writeFile(
      BASELINE_PATH,
      `${JSON.stringify(buildBaselineRecord(record, answersPath), null, 2)}\n`,
    );
    console.log(`baseline written to eval/baseline.json (answers: ${answersPath})`);
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
