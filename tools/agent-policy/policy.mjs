// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The one place that decides whether a piece of work may be handed to the
 * local model, and which paid tier takes it otherwise.
 *
 * Everything here is pure except `loadPolicy`, which reads the adjacent
 * `policy.json` once. There is no network access and no shelling out: callers
 * pass in paths and text, and get a decision back.
 *
 * Design rules, in order of precedence:
 *
 *  1. **Default-deny.** A path must match `allow` and must not match `deny`.
 *     A path that cannot be normalized (absolute, empty, contains `..`) is
 *     refused rather than resolved — resolving is how a `..` gets past a
 *     prefix check.
 *  2. **Deny beats allow**, even when a class-specific allowlist would match.
 *  3. **Unknown task class is a refusal.** A new caller has to be added to
 *     the policy on purpose, not inherit `qa`'s reach by forgetting a string.
 *  4. **Case-folded matching.** Git paths are case-sensitive; the Windows
 *     filesystem is not, so `SRC-TAURI/x.rs` must not slip past `src-tauri/`.
 *     Folding over-denies on case-variant paths, which is the safe direction.
 *  5. **Text never grants access.** Keywords in the task prose can only
 *     escalate; only path matching can authorize.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const POLICY_PATH = fileURLToPath(new URL("./policy.json", import.meta.url));

/** Thrown when a request touches a path the local model may not see. */
export class PolicyError extends Error {
  constructor(message, { taskClass, denied = [] } = {}) {
    super(message);
    this.name = "PolicyError";
    this.taskClass = taskClass;
    this.denied = denied;
  }
}

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Compile a policy glob to an anchored RegExp over a normalized (lower-cased,
 * forward-slash) repo-relative path.
 *
 * Supports `**` (any number of segments, including none), `*` (within one
 * segment) and `?` (one non-slash character). Deliberately not a general glob
 * library: every pattern in policy.json is one of these three forms, and a
 * smaller matcher is a smaller thing to get wrong.
 */
export function compileGlob(rawGlob) {
  // Globals are written the way a human reads them (`README.md`, `Dockerfile`)
  // while subjects are always normalized to lower case. Folding here keeps
  // every pattern in policy.json honest about that instead of silently never
  // matching, which is how an allowlist entry turns into a denial.
  const glob = rawGlob.toLowerCase();
  let source = "";
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i];
    if (char === "*") {
      if (glob[i + 1] === "*") {
        i += 1;
        if (glob[i + 1] === "/") {
          i += 1;
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`^${source}$`);
}

/**
 * Normalize a caller-supplied path to the form the globs are written against.
 *
 * Returns `null` for anything that is not a plain repo-relative path. `null`
 * is a refusal at every call site, never a wildcard.
 */
export function normalizeRepoPath(raw) {
  if (typeof raw !== "string") return null;
  let value = raw.trim().replace(/\\/g, "/");
  if (!value) return null;
  if (value.startsWith("/") || /^[a-zA-Z]:\//.test(value)) return null;
  value = value.replace(/^\.\//, "");
  const segments = [];
  for (const segment of value.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") return null;
    segments.push(segment);
  }
  if (segments.length === 0) return null;
  return segments.join("/").toLowerCase();
}

const keywordRegExp = (words) =>
  words.length === 0 ? null : new RegExp(`\\b(?:${words.map(escapeRegExp).join("|")})\\b`, "i");

function validatePolicy(policy, source) {
  const fail = (detail) => {
    throw new Error(`agent-policy: ${source}: ${detail}`);
  };
  if (!policy || typeof policy !== "object") fail("not a JSON object");
  if (policy.version !== 1) fail(`unsupported version ${JSON.stringify(policy.version)}`);
  for (const key of ["deny", "allow", "escalateKeywords", "criticalKeywords", "criticalPrefixes"]) {
    if (!Array.isArray(policy[key])) fail(`"${key}" must be an array`);
    if (policy[key].some((entry) => typeof entry !== "string" || !entry)) {
      fail(`"${key}" must contain non-empty strings`);
    }
  }
  if (!policy.taskClasses || typeof policy.taskClasses !== "object") {
    fail('"taskClasses" must be an object');
  }
  for (const [name, definition] of Object.entries(policy.taskClasses)) {
    const paths = definition?.paths;
    const valid = paths === "allow" || (Array.isArray(paths) && paths.length > 0);
    if (!valid) fail(`taskClasses.${name}.paths must be "allow" or a non-empty array`);
  }
  if (!policy.models || typeof policy.models !== "object") fail('"models" must be an object');
}

let cachedPolicy = null;

/** Load and compile the policy. Cached for the default path. */
export function loadPolicy(path = POLICY_PATH) {
  if (path === POLICY_PATH && cachedPolicy) return cachedPolicy;
  const source = path === POLICY_PATH ? "policy.json" : path;
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  validatePolicy(parsed, source);
  const compiled = {
    ...parsed,
    denyGlobs: parsed.deny.map(compileGlob),
    allowGlobs: parsed.allow.map(compileGlob),
    escalateRe: keywordRegExp(parsed.escalateKeywords),
    criticalRe: keywordRegExp(parsed.criticalKeywords),
    criticalPrefixes: parsed.criticalPrefixes.map((prefix) => prefix.toLowerCase()),
    taskGlobs: Object.fromEntries(
      Object.entries(parsed.taskClasses).map(([name, definition]) => [
        name,
        definition.paths === "allow" ? null : definition.paths.map(compileGlob),
      ]),
    ),
  };
  if (path === POLICY_PATH) cachedPolicy = compiled;
  return compiled;
}

/** Forget the cached policy. Tests only. */
export function resetPolicyCache() {
  cachedPolicy = null;
}

/**
 * The class-independent half of the decision: normalization, deny, allow.
 *
 * Reported for every candidate path even when the task class itself already
 * refuses the request — otherwise "cannot run locally" would come back with an
 * empty `deniedPaths` and read as if no path were the problem.
 */
export function checkPath(rawPath, policy = loadPolicy()) {
  const normalized = normalizeRepoPath(rawPath);
  if (normalized === null) {
    return {
      path: typeof rawPath === "string" ? rawPath : String(rawPath),
      normalized: null,
      allowed: false,
      reason: "path could not be normalized (absolute, empty, or contains ..)",
    };
  }
  if (policy.denyGlobs.some((re) => re.test(normalized))) {
    return { path: normalized, normalized, allowed: false, reason: "denied path" };
  }
  if (!policy.allowGlobs.some((re) => re.test(normalized))) {
    return { path: normalized, normalized, allowed: false, reason: "not on the allowlist" };
  }
  return { path: normalized, normalized, allowed: true, reason: "allowed by policy" };
}

/** Decide one path for one task class. */
export function decidePath(rawPath, taskClass, policy = loadPolicy()) {
  const base = checkPath(rawPath, policy);
  if (!base.allowed) return base;
  if (!Object.hasOwn(policy.taskClasses, taskClass)) {
    return { ...base, allowed: false, reason: `unknown task class "${taskClass}"` };
  }
  const classGlobs = policy.taskGlobs[taskClass] ?? policy.allowGlobs;
  if (!classGlobs.some((re) => re.test(base.path))) {
    return { ...base, allowed: false, reason: "not on the allowlist" };
  }
  return { ...base, reason: "allowed" };
}

/** Decide every path in a request. The first refusal is enough to refuse all. */
export function decidePaths(rawPaths, taskClass, policy = loadPolicy()) {
  const denied = [];
  const allowed = [];
  for (const rawPath of rawPaths) {
    const decision = decidePath(rawPath, taskClass, policy);
    if (decision.allowed) allowed.push(decision.path);
    else denied.push({ path: decision.path, reason: decision.reason });
  }
  return { allowed, denied, ok: denied.length === 0 };
}

/**
 * The sentence every refusal shows the caller.
 *
 * Kept in one place because four entry points (wiserepo's MCP tools, its CLI,
 * the router's report and the qwen-local wrapper) surface it; three
 * paraphrases of "do not retry" would drift into three different promises.
 */
export function refusalMessage(denied = [], reason = "") {
  const listed = denied.map((entry) => `${entry.path} (${entry.reason})`).join(", ");
  const detail = listed.length > 0 ? `the local model may not see ${listed}` : reason;
  return (
    `agent policy: ${detail}. Read the file directly and continue with a paid tier; ` +
    `do not retry, rephrase, or narrow the request to get around this refusal.`
  );
}

/**
 * Throw a `PolicyError` when any path is refused.
 *
 * The message is written for an agent to read: it says what to do next
 * (read the file directly, once) and what not to do (retry, rephrase, or
 * work around it).
 */
export function assertPathsAllowed(rawPaths, taskClass, policy = loadPolicy()) {
  const { denied } = decidePaths(rawPaths, taskClass, policy);
  if (denied.length === 0) return;
  throw new PolicyError(refusalMessage(denied), { taskClass, denied });
}

/** Skill/task text that matches a protected concern. */
export function textEscalates(text, policy = loadPolicy()) {
  if (typeof text !== "string" || !text) return false;
  return policy.escalateRe ? policy.escalateRe.test(text) : false;
}

/** Skill/task text that names something P0-ish. */
export function textIsCritical(text, policy = loadPolicy()) {
  if (typeof text !== "string" || !text) return false;
  return policy.criticalRe ? policy.criticalRe.test(text) : false;
}

/**
 * Whether a path belongs to a critical subsystem.
 *
 * The one definition of that rule: it decides which tier a refusal escalates
 * to, both in `decideTask` and in the verification gate's verdict.
 */
export function isCriticalPath(rawPath, policy = loadPolicy()) {
  const normalized = normalizeRepoPath(rawPath);
  if (normalized === null) return false;
  return policy.criticalPrefixes.some((prefix) => normalized.startsWith(prefix));
}

/**
 * Paths a diff touches, from `git diff` output.
 *
 * Reads `diff --git a/X b/Y` (both sides, so a rename out of a protected
 * directory is caught) and falls back to the `---`/`+++` headers for diffs
 * that omit it. Git quotes unusual paths; the surrounding quotes are stripped,
 * which is enough to compare them — an unquoted path that still fails to
 * normalize is refused downstream anyway.
 */
export function extractDiffPaths(diffText) {
  const found = new Set();
  const add = (value) => {
    if (!value) return;
    const cleaned = value.replace(/^"|"$/g, "").trim();
    if (!cleaned || cleaned === "/dev/null") return;
    found.add(cleaned);
  };
  for (const line of String(diffText ?? "").split("\n")) {
    const header = /^diff --git a\/(.+) b\/(.+)$/.exec(line);
    if (header) {
      add(header[1]);
      add(header[2]);
      continue;
    }
    const plus = /^\+\+\+ b\/(.+)$/.exec(line);
    if (plus) add(plus[1]);
    const minus = /^--- a\/(.+)$/.exec(line);
    if (minus) add(minus[1]);
  }
  return [...found];
}

/** Paths named by `git grep -n` output (`path:line:text`). */
export function extractGrepPaths(grepText) {
  const found = new Set();
  for (const line of String(grepText ?? "").split("\n")) {
    const match = /^([^:\s][^:]*):\d+:/.exec(line);
    if (match) found.add(match[1]);
  }
  return [...found];
}

// Only these top-level entries count as a path mention in prose. Without it a
// token like "and/or" carries a slash and would be normalized into a bogus
// path; with it, prose can still name `src-tauri/src/api/zk/mod.rs` and be
// caught before the local model sees anything.
const TOP_LEVEL_ENTRIES = new Set([
  "app",
  "clients",
  "crates",
  "docker",
  "docs",
  "migrations",
  "migrations-sqlite",
  "proofs",
  "scripts",
  "secrets",
  "src-tauri",
  "tools",
  "vendor",
  "verifiers",
  ".claude",
  ".github",
  ".githooks",
]);

/** Path-like tokens in a task description, restricted to real top-level dirs. */
export function extractPathMentions(text) {
  const found = new Set();
  for (const rawToken of String(text ?? "").split(/[\s,;:()'"`]+/)) {
    const token = rawToken.replace(/[.,;]+$/, "");
    if (!token.includes("/")) continue;
    const first = token.split("/")[0].toLowerCase();
    if (!TOP_LEVEL_ENTRIES.has(first)) continue;
    found.add(token);
  }
  return [...found];
}

/**
 * Decide a whole task: may the local model do it, and if not, which paid tier.
 *
 * `tier` is one of `local`, `mid`, `top`. A refusal caused by a protected
 * path goes to `top` when the path lives under a critical prefix, `mid`
 * otherwise; a refusal caused only by the task prose follows the same split
 * on `criticalKeywords`. There is no way for prose to *grant* `local`.
 */
export function decideTask({
  taskClass = null,
  paths = [],
  text = "",
  policy = loadPolicy(),
} = {}) {
  const candidates = [...paths, ...extractPathMentions(text)];
  const knownClass = taskClass !== null && Object.hasOwn(policy.taskClasses, taskClass);
  const checks = candidates.map((candidate) =>
    knownClass ? decidePath(candidate, taskClass, policy) : checkPath(candidate, policy),
  );
  const denied = checks
    .filter((entry) => !entry.allowed)
    .map((entry) => ({ path: entry.path, reason: entry.reason }));

  const escalatedByText = textEscalates(text, policy);
  const criticalByText = textIsCritical(text, policy);
  const criticalByPath = denied.some((entry) => isCriticalPath(entry.path, policy));

  let tier;
  let reason;
  let qwenAllowed;

  if (!knownClass) {
    qwenAllowed = false;
    tier = criticalByText || criticalByPath ? "top" : "mid";
    // A refused path is the more useful reason than "wrong kind of task":
    // it is the one the caller can act on.
    reason =
      denied.length > 0
        ? "protected path — local model bypassed"
        : taskClass === null
          ? "not a local-capable task class"
          : "unknown task class";
  } else if (denied.length > 0) {
    qwenAllowed = false;
    tier = criticalByPath || criticalByText ? "top" : "mid";
    reason = "protected path — local model bypassed";
  } else if (escalatedByText) {
    qwenAllowed = false;
    tier = criticalByText ? "top" : "mid";
    reason = "task text names a protected concern";
  } else {
    qwenAllowed = true;
    tier = "local";
    reason = "allowlisted task class and paths";
  }

  return { qwenAllowed, tier, reason, deniedPaths: denied };
}

/** Model id for a client and tier, from the policy table. */
export function modelFor(client, tier, policy = loadPolicy()) {
  if (tier === "deterministic") return null;
  const table = policy.models[client] ?? policy.models.cli;
  return table?.[tier] ?? null;
}
