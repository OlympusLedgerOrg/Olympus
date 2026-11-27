#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Route one task to a capability tier.
 *
 * The tier ladder is: deterministic tool -> local model -> mid-tier paid
 * model -> top-tier paid model. `tools/agent-policy` owns the decision;
 * this file owns the vocabulary (which task class the prose describes) and
 * the mapping from tier to the words the existing consumers already read.
 *
 * The legacy keys (`route`, `reasoning`, `review`, `basis`, `fallback`) keep
 * their meaning for anything already parsing this output. The new keys
 * (`tier`, `model`, `taskClass`, `allowed`, `deniedPaths`, `escalated`,
 * `policyReason`) are the precise answer; `allowed` means *the local model
 * may do this*, not *the task may be done*.
 *
 * No model is consulted to decide routing. Asking a local model whether the
 * work is safe for the local model is neither cheaper nor safer than a policy
 * file, and it made the answer depend on whether Ollama happened to be up.
 */

import { pathToFileURL } from "node:url";

import { logRoute } from "../agent-policy/log.mjs";
import { decideTask, extractPathMentions, loadPolicy, modelFor } from "../agent-policy/policy.mjs";

export const USAGE = `Usage: node tools/model-router/route.mjs [options] "task description"

Options:
  --paths a,b,c      repo paths the task touches (checked against the policy)
  --task <class>     force a task class (${Object.keys(loadPolicy().taskClasses).join(", ")})
  --probe-local      also report whether Ollama answers, without routing on it
  --help             show this message
`;

const LEGACY_SENSITIVE =
  /crypto|cryptograph|hash|signature|key material|secret|auth(?:entication|orization)?|permission|scope|proof|zk|snark|smt|migration|security|vulnerab|ledger|redaction/;
const LEGACY_IMPLEMENTATION = /implement|change|fix|refactor|write|patch|debug|test|build|modify/;
const LEGACY_REVIEW = /review|audit|threat model|second opinion|independent|check this diff/;

/** Task classes the prose can name, most specific first. */
const TASK_CLASS_RULES = [
  [
    "pr-text",
    /\b(commit message|pr description|pull request (?:description|text)|changelog entry|release note)/i,
  ],
  ["docstring", /\b(docstring|doc comment|jsdoc)\b/i],
  ["test-scaffold", /\b(scaffold (?:a )?test|test scaffold|test skeleton)\b/i],
  ["review", /\b(review (?:this|the) diff|code review|review my changes)\b/i],
  ["summarize", /\b(?:summar\w+|summarise|tl;?dr)\b/i],
];

/** Questions a deterministic tool answers without any model. */
const LOOKUP_HINTS =
  /\b(where is|find (?:all )?(?:callers|usages|references)|list (?:all )?files|which files|grep for)\b/i;

/**
 * The pre-policy heuristic, preserved verbatim so `route`/`reasoning`/`review`
 * do not silently change meaning for existing consumers.
 */
export function legacyHeuristic(task, lower = task.toLowerCase()) {
  const sensitive = LEGACY_SENSITIVE.test(lower);
  const implementation = LEGACY_IMPLEMENTATION.test(lower);
  const review = LEGACY_REVIEW.test(lower);
  if (sensitive) {
    return {
      route: "codex",
      reasoning: "high",
      review: "claude",
      basis: "security-sensitive repository rule",
    };
  }
  if (review) {
    return {
      route: "claude",
      reasoning: "high",
      review: "codex",
      basis: "independent review request",
    };
  }
  if (implementation) {
    return {
      route: "codex",
      reasoning: "medium",
      review: "optional",
      basis: "implementation task",
    };
  }
  return {
    route: "ollama",
    reasoning: "low",
    review: "none",
    basis: "local discovery or explanation",
  };
}

/** Infer the task class from the prose. Returns null for implementation work. */
export function inferTaskClass(task) {
  for (const [name, pattern] of TASK_CLASS_RULES) {
    if (pattern.test(task)) return name;
  }
  return null;
}

/**
 * Decide a route without touching the network.
 *
 * `probeLocal` is optional and only used to fill the `ollama` field; it never
 * changes the decision.
 */
/** Which agent owns a legacy route word. `route` decides the model family. */
const AGENT_FOR_ROUTE = { ollama: "local", codex: "codex", claude: "claude-code" };

/**
 * What a Claude Code session should run this task on, whatever `route` says.
 * `route` names the preferred agent; this answers "if Claude does it, which
 * model and effort". Null when the policy has no `claudeSession` table.
 */
export function claudeSessionFor(tier, policy = loadPolicy()) {
  const entry = policy.claudeSession?.[tier];
  if (!entry) return null;
  return {
    model: entry.model,
    effort: entry.effort,
    suggestion: `${entry.label ?? entry.model} ${entry.effort}`,
  };
}

export function routeTask({ task, paths = [], taskClass = undefined, policy = loadPolicy() } = {}) {
  if (typeof task !== "string" || task.trim() === "") {
    throw new Error("a task description is required");
  }
  const lower = task.toLowerCase();
  const fallback = legacyHeuristic(task, lower);

  let inferredClass = taskClass ?? inferTaskClass(task);
  let deterministic = false;
  if (inferredClass === undefined || inferredClass === null) {
    inferredClass = inferTaskClass(task);
    if (inferredClass === null && LOOKUP_HINTS.test(lower)) deterministic = true;
  }

  const mentioned = extractPathMentions(task);
  const allPaths = [...new Set([...paths, ...mentioned])];
  const decision = decideTask({ taskClass: inferredClass, paths, text: task, policy });

  // A review route with no explicit path list has no evidence of what the
  // diff touches, and a diff can touch anything. Decline local rather than
  // assume, because the alternative is shipping crates/ to a 7B model.
  const needsPathEvidence = inferredClass === "review" && paths.length === 0;
  const localAllowed = decision.qwenAllowed && !deterministic && !needsPathEvidence;

  const tier = deterministic
    ? "deterministic"
    : localAllowed
      ? "local"
      : needsPathEvidence
        ? "mid"
        : decision.tier;
  const policyReason = deterministic
    ? "deterministic tooling answers this"
    : needsPathEvidence
      ? "review route without an explicit path list"
      : decision.reason;

  let route = fallback.route;
  let reasoning = fallback.reasoning;
  let review = fallback.review;
  let basis = fallback.basis;
  if (localAllowed) {
    // `route` names who does the work, so it has to agree with the tier: the
    // legacy heuristic says "claude" for any review, which would send an
    // allowlisted local review straight to a paid model.
    route = "ollama";
    reasoning = "low";
    review = "none";
    basis = `local tier: ${policyReason}`;
  } else if (route === "ollama") {
    // Same shape as the legacy security-sensitive branch: the local answer was
    // overridden, not invented.
    route = "codex";
    reasoning = "high";
    review = "claude";
    basis = `${fallback.basis} -> escalated: ${policyReason}`;
  }

  const agent = AGENT_FOR_ROUTE[route] ?? "cli";
  const localModel = process.env.WISEREPO_OLLAMA_MODEL || modelFor("local", "local", policy);

  return {
    task,
    claude: claudeSessionFor(tier, policy),
    route,
    reasoning,
    review,
    basis,
    fallback,
    tier,
    agent,
    model: tier === "local" ? localModel : modelFor(agent, tier, policy),
    taskClass: inferredClass,
    allowed: localAllowed,
    deniedPaths: decision.deniedPaths,
    escalated: !localAllowed,
    policyReason,
    consideredPaths: allPaths,
  };
}

function parseArgs(argv) {
  const options = { paths: [], taskClass: undefined, probe: false };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--probe-local") {
      options.probe = true;
    } else if (arg === "--paths") {
      options.paths.push(
        ...String(argv[++i] ?? "")
          .split(",")
          .filter(Boolean),
      );
    } else if (arg.startsWith("--paths=")) {
      options.paths.push(...arg.slice(8).split(",").filter(Boolean));
    } else if (arg === "--task") {
      options.taskClass = argv[++i];
    } else if (arg.startsWith("--task=")) {
      options.taskClass = arg.slice(7);
    } else {
      positional.push(arg);
    }
  }
  options.task = positional.join(" ").trim();
  return options;
}

async function probeLocalModel() {
  try {
    const response = await fetch("http://127.0.0.1:11434/api/tags", {
      signal: AbortSignal.timeout(1500),
    });
    return response.ok ? "up" : `http-${response.status}`;
  } catch {
    return "unavailable";
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (!options.task) {
    process.stderr.write(USAGE);
    return 1;
  }
  let result;
  try {
    result = routeTask(options);
  } catch (error) {
    process.stderr.write(`model-router: ${error.message}\n`);
    return 1;
  }
  if (options.probe) result.ollama = await probeLocalModel();
  // A failed write must not fail the routing decision the caller asked for.
  try {
    logRoute(result);
  } catch (error) {
    process.stderr.write(`model-router: could not write the route log: ${error.message}\n`);
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.claude)
    process.stderr.write(`claude: ${result.claude.suggestion} (tier ${result.tier})\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
