// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { readFile, stat, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// tools/wiserepo/src/repo.mjs -> repo root is three levels up.
const PACKAGE_ROOT = fileURLToPath(new URL("../../..", import.meta.url));

// A stalled git invocation (large pack, filesystem contention, a hung
// credential/pager helper) must not block the long-lived MCP stdio process
// or the pre-commit hook indefinitely.
const GIT_SUBPROCESS_TIMEOUT_MS = 30_000;

export function repoRoot() {
  // path.resolve normalizes a trailing separator and a relative value.
  // Without this, WISEREPO_ROOT=/srv/Olympus/ makes `root + path.sep` equal
  // `/srv/Olympus//`, which no resolved path can ever start with — every
  // call to resolveInRepo then throws "escapes the repo root" and the MCP
  // server reads nothing. A relative WISEREPO_ROOT=. resolves against cwd
  // while the unresolved comparison uses the literal string ".", which is
  // never equal to anything real either.
  return path.resolve(process.env.WISEREPO_ROOT || PACKAGE_ROOT);
}

// Resolve a repo-relative path and refuse anything that escapes the repo
// root. This check is LEXICAL ONLY (string comparison on path.resolve's
// output) — it does not follow symlinks. Callers that then read file
// contents MUST additionally re-check with resolveInRepoFollowingSymlinks
// below; resolveInRepo alone is not sufficient to bound what gets read.
export function resolveInRepo(relPath) {
  const root = repoRoot();
  const resolved = path.resolve(root, relPath);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(`Path "${relPath}" escapes the repo root`);
  }
  return resolved;
}

// Re-checks confinement AFTER resolving symlinks. A repo-tracked symlink
// (e.g. committed on an untrusted branch) can lexically sit inside the repo
// while pointing at ~/.ssh/id_rsa or /etc/passwd — resolveInRepo's string
// check passes, `stat` follows the link and reports a regular file, and
// `readFile` returns the TARGET's bytes. Those bytes then go straight into
// a prompt sent to Anthropic or OpenAI (see mcp-server.mjs's gatherContext).
// This is a real exfiltration path, not a hypothetical: any file readable
// by the process and reachable via a symlink under the repo becomes
// readable by whoever can get a symlink committed and a wiserepo tool
// invoked against it.
export async function resolveInRepoFollowingSymlinks(relPath) {
  const abs = resolveInRepo(relPath);
  const real = await realpath(abs);
  const root = await realpath(repoRoot());
  if (real !== root && !real.startsWith(root + path.sep)) {
    throw new Error(`Path "${relPath}" resolves outside the repo root (symlink escape)`);
  }
  return real;
}

// Truncate to a character budget, appending a note that says how much was
// cut. Every context-gathering function below routes through this so a
// caller (or a human reading the model's answer) can always tell when the
// model saw a partial view rather than silently guessing on missing content.
export function truncateText(text, maxChars, label) {
  if (text.length <= maxChars) return text;
  const cut = text.length - maxChars;
  return text.slice(0, maxChars) + `\n...[truncated ${cut} of ${text.length} chars from ${label}]`;
}

// Whether truncateText would cut `text` at `maxChars`. Needed as a separate
// structural check because truncateText's output can be LONGER than its
// input for a small overflow (the appended note is ~55 chars), so a naive
// `result.length < input.length` comparison at the call site can miss a
// truncation that actually happened.
export function wouldTruncate(text, maxChars) {
  return text.length > maxChars;
}

export async function readRepoFile(relPath, { maxBytes = 60_000 } = {}) {
  const real = await resolveInRepoFollowingSymlinks(relPath);
  const st = await stat(real);
  if (!st.isFile()) {
    throw new Error(`"${relPath}" is not a file`);
  }
  const buf = await readFile(real);
  const text = buf.toString("utf8");
  return truncateText(text, maxBytes, relPath);
}

// Flags that `git diff` accepts which write files, read attacker-chosen
// paths, or execute external programs. These are the reason diffArgs cannot be
// splatted through unchecked: `git diff --output=/tmp/x HEAD` writes an
// arbitrary file outside the repo with no error, and diffArgs is an MCP tool
// input — i.e. model-chosen, and influenceable by any untrusted content the
// calling agent has read.
//
// This is an ALLOWLIST rather than a denylist by design. git's option surface
// is large and grows; enumerating the dangerous ones is a losing game, so we
// permit only the small set of read-only selectors this tool actually needs.
const ALLOWED_DIFF_FLAGS = new Set([
  "--cached",
  "--staged",
  "--stat",
  "--numstat",
  "--shortstat",
  "--name-only",
  "--name-status",
  "--no-color",
  "--unified",
  "-U",
  "--find-renames",
  "-M",
  "--find-copies",
  "-C",
  "--ignore-all-space",
  "-w",
  "--ignore-space-change",
  "-b",
  "--minimal",
  "--patience",
  "--histogram",
]);

// A revision or revision range: HEAD, main...HEAD, abc123, v1.0..v2.0, etc.
// Deliberately conservative — no `:` (which would allow `rev:path` forms) and
// no leading dash.
const REVISION_RE = /^[A-Za-z0-9._/@^~-]+(\.{2,3}[A-Za-z0-9._/@^~-]+)?$/;

/**
 * Validate caller-supplied `git diff` arguments.
 *
 * Returns a sanitized argv. Throws on anything not clearly safe.
 *
 * @param {string[]} args
 * @returns {string[]}
 */
export function sanitizeDiffArgs(args) {
  const revs = [];
  const flags = [];
  const paths = [];
  let seenDoubleDash = false;

  for (const raw of args) {
    if (typeof raw !== "string") {
      throw new Error("diff arguments must be strings");
    }
    if (raw === "--") {
      seenDoubleDash = true;
      continue;
    }
    if (seenDoubleDash) {
      // Everything after `--` is a pathspec; force it inside the repo.
      resolveInRepo(raw);
      paths.push(raw);
      continue;
    }
    if (raw.startsWith("-")) {
      // Reject `--flag=value` outright: the value is exactly where a path
      // lands (`--output=...`, `--src-prefix=...`), and none of the allowed
      // flags need one in that form.
      if (raw.includes("=")) {
        throw new Error(
          `Disallowed git diff argument "${raw}" — "--flag=value" forms are not permitted`,
        );
      }
      if (!ALLOWED_DIFF_FLAGS.has(raw)) {
        throw new Error(`Disallowed git diff flag "${raw}" — not in wiserepo's allowlist`);
      }
      flags.push(raw);
      continue;
    }
    if (!REVISION_RE.test(raw)) {
      throw new Error(
        `Disallowed git diff revision "${raw}" — does not look like a revision or range`,
      );
    }
    revs.push(raw);
  }

  // Always terminate with `--` so a revision that happens to match a filename
  // cannot be reinterpreted, and so no later arg is parsed as an option.
  return [...flags, ...revs, "--", ...paths];
}

export async function gitDiff(args = ["HEAD"], { maxBytes = 100_000 } = {}) {
  const safe = sanitizeDiffArgs(args);
  const { stdout } = await execFileAsync("git", ["diff", ...safe], {
    cwd: repoRoot(),
    maxBuffer: 20 * 1024 * 1024,
    timeout: GIT_SUBPROCESS_TIMEOUT_MS,
  });
  return truncateText(stdout, maxBytes, `git diff ${args.join(" ")}`);
}

export async function gitGrep(pattern, { globs = [], maxBytes = 30_000 } = {}) {
  if (typeof pattern !== "string") {
    throw new Error("grep pattern must be a string");
  }
  // The `--` before the pattern is what makes this safe against option
  // injection: a pattern like `--output=x` is treated as a pattern, not a
  // flag. It must appear EXACTLY ONCE: git only treats the first `--` as the
  // options/pathspec separator, so a `--` re-inserted before each glob below
  // would make every glob after the first parse as a literal pathspec named
  // `--` instead of the glob itself — silently matching nothing. The
  // leading-dash rejection in the loop is what keeps a glob from being
  // parsed as a flag; the single separator above is what keeps the pattern
  // from being parsed as one.
  const args = ["grep", "-n", "-I", "--", pattern];
  for (const g of globs) {
    if (typeof g !== "string" || g.startsWith("-")) {
      throw new Error(`Disallowed grep pathspec "${g}"`);
    }
    args.push(g);
  }
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd: repoRoot(),
      maxBuffer: 5 * 1024 * 1024,
      timeout: GIT_SUBPROCESS_TIMEOUT_MS,
    });
    return truncateText(stdout, maxBytes, `git grep "${pattern}"`);
  } catch (err) {
    // git grep exits 1 with empty stdout when there are no matches.
    if (err.code === 1) return "";
    throw err;
  }
}
