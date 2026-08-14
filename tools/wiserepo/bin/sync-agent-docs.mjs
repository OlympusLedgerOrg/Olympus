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
// What the verification actually guarantees, stated honestly: the regenerated
// file preserves CLAUDE.md's heading structure, per-section bullet and
// table-row counts, and code-block count (see src/sections.mjs). That catches
// truncation, dropped sections, deleted invariant bullets, and gutted tables.
// It does NOT prove semantic equivalence — a model could still reword a
// single bullet incorrectly while keeping the count. Treat a regenerated
// AGENTS.md as reviewable output, not as automatically trustworthy.
//
// Exit codes (the pre-commit hook and CI both depend on this distinction):
//   0 — success (written, or already in sync)
//   1 — BLOCKING. The model responded but the result failed structural
//       parity, or --check found real drift, or wiserepo itself is broken
//       (bad request, programming error). All of these need a human.
//   2 — NON-BLOCKING. The backend was unavailable: no API key, network
//       error, timeout, rate limit, auth rejection, empty completion. The
//       check did not run — that is not the same as failing.
//
// Usage: node bin/sync-agent-docs.mjs [--check] [--backend claude|openai]
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { callModel, ModelUnavailableError } from "../src/backend.mjs";
import { repoRoot } from "../src/repo.mjs";
import { checkStructuralParity } from "../src/sections.mjs";

const EXIT_OK = 0;
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
  "   whole document.\n" +
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

  const prompt =
    `## Current CLAUDE.md (source of truth)\n\`\`\`\`markdown\n${claudeMd}\n\`\`\`\`\n\n` +
    (currentAgentsMd
      ? `## Current AGENTS.md (to be regenerated — reuse its Codex-specific command variants where CLAUDE.md doesn't dictate otherwise)\n\`\`\`\`markdown\n${currentAgentsMd}\n\`\`\`\`\n\n`
      : "") +
    `Regenerate AGENTS.md now.`;

  // If AGENTS.md as committed already satisfies parity, there is nothing to
  // check and no reason to spend an API call. This is also what makes
  // --check stable: it compares STRUCTURE, never bytes, so ordinary model
  // wording variance cannot fail the gate.
  if (currentAgentsMd) {
    const existing = checkStructuralParity(claudeMd, currentAgentsMd, {
      titleOverride: "# AGENTS.md",
    });
    if (existing.ok) {
      console.log("[wiserepo] AGENTS.md is structurally in sync with CLAUDE.md.");
      return;
    }
    if (checkOnly) {
      fail(
        `AGENTS.md is OUT OF SYNC with CLAUDE.md:\n  ${existing.reason}\n` +
          `Run 'node tools/wiserepo/bin/sync-agent-docs.mjs' to regenerate it.`,
        EXIT_BLOCKING,
      );
    }
  }

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

  const newAgentsMd = raw.trim() + "\n";

  const parity = checkStructuralParity(claudeMd, newAgentsMd, { titleOverride: "# AGENTS.md" });
  if (!parity.ok) {
    fail(
      `REFUSING to write AGENTS.md — regenerated content failed structural parity:\n  ${parity.reason}\n` +
        `This usually means the model truncated or dropped content. Nothing was written.`,
      EXIT_BLOCKING,
    );
  }

  if (checkOnly) {
    // Reached only when the committed AGENTS.md failed parity but a fresh
    // regeneration passes — i.e. genuine drift that regenerating would fix.
    fail(
      "AGENTS.md is STALE relative to CLAUDE.md. Run without --check to regenerate.",
      EXIT_BLOCKING,
    );
  }

  await writeFile(AGENTS_MD, newAgentsMd, "utf8");
  console.log("[wiserepo] AGENTS.md regenerated from CLAUDE.md.");
}

main().catch((err) => {
  console.error(`[wiserepo] sync-agent-docs failed unexpectedly: ${err.stack || err.message}`);
  process.exit(EXIT_BLOCKING);
});
