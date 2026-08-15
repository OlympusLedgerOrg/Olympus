#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Scope-drift gate: compare a PR's *declared* intended paths against the paths
// it actually touched.
//
// The existing review gates score what a diff changed — size, protected paths,
// crypto invariants. None of them ask the prior question: was the author
// supposed to be in this file at all? An agent asked to fix a frontend bug that
// also "helpfully" adds a utility to crates/olympus-crypto scores low on every
// severity heuristic and sails through, even though touching a second subsystem
// unbidden is the clearest drift signal available.
//
// So the PR body declares its scope and the diff is checked against it. What
// this buys is narrow and worth stating exactly: it makes intent *explicit and
// reviewable*, and it makes an unrelated file a hard failure instead of a thing
// a reviewer might notice. It does NOT prove the declaration was honest — an
// author (human or agent) writes both the scope block and the diff, so a
// deliberately wide declaration passes. Over-broad catch-alls are rejected
// (see OVERBROAD_PATTERNS) precisely because they are the cheap way to make
// this check vacuous, but a merely generous declaration still works. This is a
// drift detector, not an authorization boundary.

import { readFileSync, appendFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const OVERRIDE_LABEL = "scope-override";

// Declaring the whole repository is not a scope. These would make the gate
// pass unconditionally, which is worse than not running it — a green check
// that proves nothing reads as a check that proved something.
const OVERBROAD_PATTERNS = new Set(["**", "*", "**/*", "./**", "/**"]);

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Normalize a declared pattern into repo-root-relative form.
 * Throws on constructs this matcher deliberately does not implement, so a
 * pattern that would silently never match is a loud error instead.
 */
export const normalizePattern = (raw) => {
  let pattern = String(raw).trim();
  // Authors reliably wrap paths in backticks in Markdown; strip one layer of
  // backticks or quotes rather than treating them as literal path characters.
  pattern = pattern
    .replace(/^[`'"]+/, "")
    .replace(/[`'"]+$/, "")
    .trim();
  if (pattern.length === 0) return null;

  if (pattern.startsWith("!")) {
    throw new Error(
      `negated pattern "${pattern}" is not supported — list the paths you do intend to touch instead`,
    );
  }
  // Strip a leading "/" (CODEOWNERS habit) and "./" — both mean repo root here.
  pattern = pattern.replace(/^\.\//, "").replace(/^\/+/, "");
  if (pattern.length === 0) {
    throw new Error('pattern "/" is not a scope — list concrete paths');
  }
  if (pattern.split("/").includes("..")) {
    throw new Error(`pattern "${raw}" escapes the repository root`);
  }
  // Comment-stripping runs to a fixpoint, so a surviving marker means the body
  // nests or overlaps them in a way whose rendered form is not what this parser
  // sees. No path glob contains one; refuse rather than guess which view is
  // authoritative.
  if (pattern.includes("<!--") || pattern.includes("-->")) {
    throw new Error(
      `pattern "${raw}" contains an HTML comment marker — unbalanced or nested comments in the Scope block`,
    );
  }
  return pattern;
};

/**
 * Compile a glob to an anchored RegExp over POSIX repo-relative paths.
 *
 * Semantics — every pattern is anchored at the repository root:
 *   - "*" and "?" match within a single path segment; neither crosses "/".
 *   - "**" as a whole segment crosses "/" and may match zero segments, so
 *     "**\/*.rs" matches both "main.rs" and "a/b/main.rs".
 *   - a trailing "/" means "everything under this directory".
 *   - a pattern with no glob metacharacters matches that exact path OR
 *     anything beneath it, so "docs" covers "docs/adr/0001.md".
 *
 * The wildcard rules follow minimatch, but the last two do not, and the
 * difference matters if you are porting patterns: gitignore treats a
 * slash-free "docs" as matching at any depth, while here it is root-anchored,
 * and minimatch's "docs" matches only a file named exactly "docs". Both
 * divergences are deliberate — a scope declaration is a statement about
 * subsystems, and "src-tauri/src/api" should mean the directory.
 */
export const globToRegExp = (pattern) => {
  const normalized = normalizePattern(pattern);
  if (normalized === null) throw new Error("empty pattern");

  if (normalized.endsWith("/")) {
    return globToRegExp(`${normalized}**`);
  }

  // Metacharacter-free patterns get directory-prefix semantics. Without this,
  // declaring "docs" would match only a file literally named "docs".
  if (!/[*?]/.test(normalized)) {
    return new RegExp(`^${escapeRegExp(normalized)}(?:/.*)?$`);
  }

  const segments = normalized.split("/");
  let source = "";
  segments.forEach((segment, index) => {
    const isLast = index === segments.length - 1;
    if (segment === "**") {
      // Zero-or-more whole segments when followed by more pattern; the rest of
      // the path (possibly empty) when trailing.
      source += isLast ? "(?:.*)" : "(?:[^/]+/)*";
      return;
    }
    const segmentSource = segment
      .split("")
      .map((character) => {
        if (character === "*") return "[^/]*";
        if (character === "?") return "[^/]";
        return escapeRegExp(character);
      })
      .join("");
    source += segmentSource;
    if (!isLast) source += "/";
  });
  return new RegExp(`^${source}$`);
};

export const matchesAnyPattern = (file, patterns) =>
  patterns.some((pattern) => globToRegExp(pattern).test(file));

/**
 * Remove HTML comments, repeating until the text stops changing.
 *
 * A single pass is not enough, and not merely in theory: on "<!-<!-- -->- -->"
 * one pass returns "<!-- -->", because deleting an inner match splices its
 * neighbours into a comment marker that was not a comment start in the input.
 * A pass therefore cannot be assumed to leave comment-free text, so proving no
 * crafted body smuggles a list item past it would mean enumerating shapes
 * rather than fixing the primitive.
 *
 * Iterating is deliberately *more* aggressive than a Markdown renderer, which
 * strips comments in one left-to-right pass. That direction is the safe one
 * here: over-removal narrows the parsed scope, so the gate fails and the author
 * fixes an unambiguous body. Under-removal would widen the parsed scope past
 * what the rendered body shows a reviewer — a silent bypass of the whole check.
 *
 * Terminates because every iteration either shortens the string or is a no-op.
 */
const stripHtmlComments = (input) => {
  let text = input;
  let previous;
  do {
    previous = text;
    text = text.replace(/<!--[\s\S]*?-->/g, "");
  } while (text !== previous);
  return text;
};

/**
 * Extract the declared scope from a PR body.
 *
 * The block starts at a "Scope" heading or a bare "Scope:" line and runs to the
 * next Markdown heading (or end of body). Inside it, every list item is one
 * pattern. HTML comments are stripped first so the PR template's own
 * "<!-- list the globs -->" guidance is never parsed as a declaration.
 */
export const parseScopeBlock = (body) => {
  const text = stripHtmlComments(String(body ?? ""));
  const lines = text.split(/\r?\n/);

  let start = -1;
  let inFence = false;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^\s*(?:```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    // Matches "## Scope", "Scope:", "**Scope:**" — but not "Out of scope:",
    // which is a different section authors legitimately write.
    if (/^\s*(?:#{1,6}\s*)?\*{0,2}\s*scope\s*:?\s*\*{0,2}\s*$/i.test(line)) {
      start = index + 1;
      break;
    }
  }
  if (start === -1) return { found: false, patterns: [] };

  const patterns = [];
  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^\s*#{1,6}\s/.test(line)) break;
    const item = line.match(/^\s*(?:[-*+]|\d+[.)])\s+(.*)$/);
    if (item === null) continue;
    const value = item[1].trim();
    if (value.length > 0) patterns.push(value);
  }
  return { found: true, patterns };
};

/**
 * Decide a PR's scope status. Pure — all I/O happens in main().
 *
 * Returned `status` is the reason the check reached its verdict; `ok` says
 * whether the job should pass. An override records the drift it suppressed so
 * the override rate is countable later (that aggregation is not built here —
 * see the workflow comment).
 */
export const evaluateScope = ({
  body,
  changedFiles,
  labels = [],
  overrideLabel = OVERRIDE_LABEL,
  requireScope = true,
}) => {
  const files = changedFiles.map((file) => file.trim()).filter((file) => file.length > 0);
  const overridden = labels.some((label) => label === overrideLabel);
  const finish = (status, extra) => {
    const failing = status !== "in-scope" && status !== "skipped";
    return {
      status: failing && overridden ? "overridden" : status,
      suppressedStatus: failing && overridden ? status : null,
      ok: !failing || overridden,
      overrideLabel,
      files,
      ...extra,
    };
  };

  const { found, patterns: rawPatterns } = parseScopeBlock(body);
  if (!found || rawPatterns.length === 0) {
    if (!requireScope) return finish("skipped", { patterns: [], outOfScope: [] });
    return finish(found ? "empty-scope" : "missing-scope", { patterns: [], outOfScope: [] });
  }

  const overbroad = [];
  const patterns = [];
  const invalid = [];
  for (const raw of rawPatterns) {
    let normalized;
    try {
      normalized = normalizePattern(raw);
    } catch (error) {
      invalid.push({ pattern: raw, reason: error.message });
      continue;
    }
    if (normalized === null) continue;
    if (OVERBROAD_PATTERNS.has(normalized)) {
      overbroad.push(normalized);
      continue;
    }
    patterns.push(normalized);
  }

  if (invalid.length > 0) {
    return finish("invalid-pattern", { patterns, outOfScope: [], invalid, overbroad });
  }
  if (overbroad.length > 0) {
    return finish("overbroad-scope", { patterns, outOfScope: [], invalid, overbroad });
  }
  if (patterns.length === 0) {
    return finish("empty-scope", { patterns, outOfScope: [], invalid, overbroad });
  }

  const outOfScope = files.filter((file) => !matchesAnyPattern(file, patterns));
  // A pattern matching nothing is usually a typo in the declaration, but it is
  // not drift — report it, do not fail on it.
  const unusedPatterns = patterns.filter(
    (pattern) => !files.some((file) => globToRegExp(pattern).test(file)),
  );
  return finish(outOfScope.length > 0 ? "out-of-scope" : "in-scope", {
    patterns,
    outOfScope,
    unusedPatterns,
    invalid,
    overbroad,
  });
};

const SCOPE_HELP = `Declare the paths this PR intends to touch by adding a Scope section to the PR body:

    ## Scope

    - app/public-ui/src/components/**
    - src-tauri/src/api/ledger.rs

Patterns are repo-root-relative globs: "*" and "?" stay within one path
segment, "**" crosses directories, a trailing "/" means everything beneath,
and a plain path with no wildcards covers itself and everything under it.

If the extra paths are genuinely required, say why in the PR body and apply
the "${OVERRIDE_LABEL}" label.`;

export const formatReport = (result) => {
  const lines = [];
  const { status, suppressedStatus, patterns, outOfScope, files } = result;
  const effective = suppressedStatus ?? status;

  if (status === "overridden") {
    lines.push(
      `Scope drift suppressed by the "${result.overrideLabel}" label (would have failed: ${suppressedStatus}).`,
    );
  }

  switch (effective) {
    case "in-scope":
      lines.push(
        `All ${files.length} changed file(s) fall within the ${patterns.length} declared scope pattern(s).`,
      );
      break;
    case "skipped":
      lines.push("No Scope block declared and --require-scope is off; scope check skipped.");
      break;
    case "missing-scope":
      lines.push("This PR declares no Scope block, so there is nothing to check the diff against.");
      lines.push("");
      lines.push(SCOPE_HELP);
      break;
    case "empty-scope":
      lines.push("The Scope block is present but lists no usable patterns.");
      lines.push("");
      lines.push(SCOPE_HELP);
      break;
    case "overbroad-scope":
      lines.push(
        `The Scope block declares the entire repository (${result.overbroad.join(", ")}), which would make this check vacuous.`,
      );
      lines.push("List the subsystems this PR actually intends to touch.");
      break;
    case "invalid-pattern":
      lines.push("The Scope block contains patterns this checker cannot honour:");
      for (const { pattern, reason } of result.invalid) {
        lines.push(`  - ${pattern}: ${reason}`);
      }
      break;
    case "out-of-scope":
      lines.push(
        `${outOfScope.length} of ${files.length} changed file(s) fall outside the declared scope:`,
      );
      for (const file of outOfScope) lines.push(`  - ${file}`);
      lines.push("");
      lines.push("Declared scope:");
      for (const pattern of patterns) lines.push(`  - ${pattern}`);
      lines.push("");
      lines.push(
        `Either drop these changes from the PR, widen the Scope block if they were always part of the task, or apply the "${result.overrideLabel}" label with a justification in the PR body.`,
      );
      break;
    default:
      lines.push(`Unrecognized status: ${effective}`);
  }

  if (effective === "in-scope" && result.unusedPatterns?.length > 0) {
    lines.push("");
    lines.push("Declared but unused patterns (possible typos, not a failure):");
    for (const pattern of result.unusedPatterns) lines.push(`  - ${pattern}`);
  }
  return lines.join("\n");
};

const readListFile = (file) =>
  readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

const parseArgs = (argv) => {
  const options = { requireScope: false, labels: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`${arg} requires a value`);
      index += 1;
      return value;
    };
    switch (arg) {
      case "--body-file":
        options.bodyFile = next();
        break;
      case "--changed-files-file":
        options.changedFilesFile = next();
        break;
      case "--labels-json":
        options.labelsJson = next();
        break;
      case "--override-label":
        options.overrideLabel = next();
        break;
      case "--summary-file":
        options.summaryFile = next();
        break;
      case "--require-scope":
        options.requireScope = true;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
};

const parseLabels = (labelsJson) => {
  if (!labelsJson || labelsJson.trim().length === 0) return [];
  const parsed = JSON.parse(labelsJson);
  if (!Array.isArray(parsed)) throw new Error("--labels-json must be a JSON array");
  return parsed
    .map((label) => (typeof label === "string" ? label : label?.name))
    .filter((label) => typeof label === "string");
};

export const main = (argv = process.argv.slice(2)) => {
  const options = parseArgs(argv);
  if (!options.bodyFile) throw new Error("--body-file is required");
  if (!options.changedFilesFile) throw new Error("--changed-files-file is required");

  const result = evaluateScope({
    body: readFileSync(options.bodyFile, "utf8"),
    changedFiles: readListFile(options.changedFilesFile),
    labels: parseLabels(options.labelsJson),
    overrideLabel: options.overrideLabel ?? OVERRIDE_LABEL,
    requireScope: options.requireScope,
  });

  const report = formatReport(result);
  // One machine-readable line per run so the override rate can be counted from
  // job logs later. Nothing aggregates these yet — that is a separate job.
  const record = JSON.stringify({
    check: "pr-scope-drift",
    status: result.status,
    suppressedStatus: result.suppressedStatus,
    changedFileCount: result.files.length,
    outOfScopeCount: result.outOfScope.length,
    patternCount: result.patterns.length,
  });

  if (options.summaryFile) {
    appendFileSync(
      options.summaryFile,
      `## PR scope drift\n\n\`\`\`\n${report}\n\`\`\`\n\n<!-- ${record} -->\n`,
      "utf8",
    );
  }
  console.log(`scope-drift-record ${record}`);
  if (result.ok) {
    console.log(report);
  } else {
    console.error(report);
  }
  return result.ok;
};

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    if (!main()) process.exitCode = 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
