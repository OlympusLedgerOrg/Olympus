#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// wiserepo: regenerate AGENTS.md from CLAUDE.md so the two never drift.
//
// CLAUDE.md is the source of truth. AGENTS.md is the same guidance reframed
// for OpenAI Codex (different tool names/commands where they genuinely
// differ — e.g. nextest invocations — same invariants and policy sections
// everywhere else). CODEX.md is a short hand-written pointer at both and is
// intentionally NOT regenerated here (see its own text for why).
//
// Sync detection is a content-hash comparison (src/source-trailer.mjs), NOT
// a structural-parity comparison. AGENTS.md carries a trailing
// `<!-- wiserepo:source-sha256:... -->` comment recording the exact
// CLAUDE.md bytes it was generated from; "in sync" means that hash still
// matches. This is fully deterministic and needs no model call — the model
// is only invoked to produce a NEW generation once drift is found. (An
// earlier version of this script treated "AGENTS.md still satisfies
// structural parity against the current CLAUDE.md" as proof of sync — that
// is unsound: a CLAUDE.md edit that rewords a bullet's prose without
// changing its count passes structural parity while genuinely drifting, so
// that version could report "in sync" forever on real, undetected drift.)
//
// Once regeneration DOES run (model-backed), the result is sanitized
// (src/sanitize.mjs strips control/invisible characters — CLAUDE.md and
// AGENTS.md are files future AI sessions read as instructions, so raw
// network-sourced content landing there unfiltered is a real risk, not a
// generic one) and then verified with checkStructuralParity before being
// trusted enough to write — that check is for a different failure mode
// (the model truncating or dropping content mid-generation), not for
// staleness detection.
//
// Exit codes (the pre-commit hook and CI both depend on this distinction):
//   0 — success (written, or already in sync)
//   1 — BLOCKING. --check found the source hash has drifted (or AGENTS.md
//       has no trailer at all), or a regeneration's output failed
//       structural parity, or wiserepo itself is broken (bad request,
//       programming error). All of these need a human.
//   2 — NON-BLOCKING. The backend was unavailable: no API key, network
//       error, timeout, rate limit, auth rejection, empty completion. The
//       check did not run — that is not the same as failing. --check itself
//       never hits this path (see above) — only actual regeneration can.
//
// Usage: node bin/sync-agent-docs.mjs [--check] [--backend claude|openai]
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { callModel, ModelUnavailableError } from "../src/backend.mjs";
import { repoRoot } from "../src/repo.mjs";
import { checkStructuralParity } from "../src/sections.mjs";
import { sanitizeGeneratedMarkdown } from "../src/sanitize.mjs";
import {
  computeSourceHash,
  embedSourceTrailer,
  extractSourceTrailer,
} from "../src/source-trailer.mjs";

const EXIT_BLOCKING = 1;
const EXIT_UNAVAILABLE = 2;

const args = process.argv.slice(2);
const checkOnly = args.includes("--check");
const backendIdx = args.indexOf("--backend");
const backend = backendIdx !== -1 ? args[backendIdx + 1] : undefined;

const ROOT = repoRoot();
const CLAUDE_MD = path.join(ROOT, "CLAUDE.md");
const AGENTS_MD = path.join(ROOT, "AGENTS.md");

const SYSTEM_PROMPT =
  "You regenerate AGENTS.md from CLAUDE.md for the Olympus repo. Both files carry the same " +
  "engineering guidance; AGENTS.md is reframed for OpenAI Codex instead of Claude Code. " +
  "Rules:\n" +
  "1. Preserve every fact, invariant, command, and policy from CLAUDE.md exactly — do not drop, " +
  "   soften, invert, or invent content.\n" +
  "2. Preserve structure exactly: every Markdown heading in the same order at the same '#' depth, " +
  "   the same number of bullets in each section, the same number of table rows, and the same number " +
  "   of fenced code blocks. A structural-parity check enforces all of these and will reject the output.\n" +
  '3. Change only what must differ for Codex: the title/header framing ("guidance to OpenAI Codex" ' +
  '   instead of "guidance to Claude Code"), and any command variant that is genuinely different ' +
  "   (e.g. nextest filters vs plain cargo test), preserving the existing AGENTS.md's variants where " +
  "   CLAUDE.md does not dictate otherwise.\n" +
  "4. Output ONLY the raw Markdown for the new AGENTS.md — no commentary, no code fences around the " +
  "   whole document, and no trailing HTML comments (wiserepo appends its own tracking comment after " +
  "   validating your output).\n" +
  "5. The very first line must be '# AGENTS.md'.";

function fail(message, code) {
  console.error(`[wiserepo] ${message}`);
  process.exit(code);
}

async function main() {
  let claudeMd;
  try {
    claudeMd = await readFile(CLAUDE_MD, "utf8");
  } catch (err) {
    // A missing source doc is a real problem with the repo/invocation, not a
    // transient backend issue — block rather than silently skip.
    fail(`cannot read ${CLAUDE_MD}: ${err.message}`, EXIT_BLOCKING);
  }

  let currentAgentsMd = "";
  try {
    currentAgentsMd = await readFile(AGENTS_MD, "utf8");
  } catch {
    // AGENTS.md doesn't exist yet — fine, we're creating it.
  }

  const currentHash = computeSourceHash(claudeMd);
  const recordedHash = currentAgentsMd ? extractSourceTrailer(currentAgentsMd) : null;

  if (recordedHash === currentHash) {
    console.log(
      "[wiserepo] AGENTS.md content is verified in sync with CLAUDE.md (source hash matches).",
    );
    return;
  }

  // --check is purely detection — deterministic, no model call, so it can
  // never be blocked by an unavailable backend and never needs an API key.
  if (checkOnly) {
    fail(
      recordedHash
        ? `AGENTS.md is STALE: CLAUDE.md changed since AGENTS.md was last generated ` +
            `(recorded source hash ${recordedHash.slice(0, 12)}…, current ${currentHash.slice(0, 12)}…). ` +
            `Run 'node tools/wiserepo/bin/sync-agent-docs.mjs' to regenerate it.`
        : `AGENTS.md has no wiserepo source-hash trailer, so its sync status cannot be verified. ` +
            `Run 'node tools/wiserepo/bin/sync-agent-docs.mjs' to regenerate and stamp it.`,
      EXIT_BLOCKING,
    );
  }

  const prompt =
    `## Current CLAUDE.md (source of truth)\n\`\`\`\`markdown\n${claudeMd}\n\`\`\`\`\n\n` +
    (currentAgentsMd
      ? `## Current AGENTS.md (to be regenerated — reuse its Codex-specific command variants where CLAUDE.md doesn't dictate otherwise)\n\`\`\`\`markdown\n${currentAgentsMd}\n\`\`\`\`\n\n`
      : "") +
    `Regenerate AGENTS.md now.`;

  let raw;
  try {
    raw = await callModel({ system: SYSTEM_PROMPT, prompt, backend, maxTokens: 16384 });
  } catch (err) {
    if (err instanceof ModelUnavailableError) {
      fail(`backend unavailable, skipping AGENTS.md sync: ${err.message}`, EXIT_UNAVAILABLE);
    }
    // ModelRequestError, TypeError, ReferenceError, anything else: a real
    // bug or misconfiguration. Surface it loudly rather than pretending the
    // check merely didn't run.
    fail(`AGENTS.md sync failed: ${err.stack || err.message}`, EXIT_BLOCKING);
  }

  // Sanitize BEFORE structural parity, not after: a stripped invisible/
  // control character can itself change a bullet/heading count, so running
  // sanitization first means the parity check sees exactly what will be
  // written and can catch a sanitization-induced structural change too.
  const generated = sanitizeGeneratedMarkdown(raw.trim()) + "\n";

  const parity = checkStructuralParity(claudeMd, generated, { titleOverride: "# AGENTS.md" });
  if (!parity.ok) {
    fail(
      `REFUSING to write AGENTS.md — regenerated content failed structural parity:\n  ${parity.reason}\n` +
        `This usually means the model truncated or dropped content. Nothing was written.`,
      EXIT_BLOCKING,
    );
  }

  const newAgentsMd = embedSourceTrailer(generated, currentHash);
  // codeql[js/http-to-file-access] CodeQL flags this as network-sourced data
  // reaching a file write, and the flow it traces is real -- `raw` does
  // originate from an HTTP response (callModel, src/backend.mjs). It stays
  // open rather than a false positive because CodeQL's default JS taint
  // model only recognizes a curated list of library-call sanitizers, not
  // sanitizeGeneratedMarkdown (a project-local function it has no model
  // for) -- there is no way to make this specific query pass without
  // either removing the sanitizer call it can't see through or removing
  // the feature. The actual mitigation is real, just invisible to this
  // query: sanitizeGeneratedMarkdown strips control/invisible characters
  // BEFORE this line (see the call above), checkStructuralParity gates the
  // content's shape before this line runs at all, AGENTS_MD is a hardcoded
  // constant path (never attacker-influenced), and this line only executes
  // when the CI ANTHROPIC_API_KEY is present -- which ci.yml scopes to
  // `push` only, never `pull_request` (see that workflow's own comment).
  await writeFile(AGENTS_MD, newAgentsMd, "utf8");
  console.log("[wiserepo] AGENTS.md regenerated from CLAUDE.md and stamped with its source hash.");
}

main().catch((err) => {
  console.error(`[wiserepo] sync-agent-docs failed unexpectedly: ${err.stack || err.message}`);
  process.exit(EXIT_BLOCKING);
});
