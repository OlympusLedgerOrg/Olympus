// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Tracks the exact source content a generated doc was produced from, via a
// trailing HTML-comment hash — closes a real gap in structural-parity-only
// verification.
//
// checkStructuralParity (src/sections.mjs) compares headings, bullet/table
// counts, and code-block counts. That is NOT the same as "AGENTS.md reflects
// the current CLAUDE.md": a CLAUDE.md edit that changes prose inside a
// bullet without changing the bullet COUNT — reword a command, soften an
// invariant, fix a typo — passes structural parity trivially, because
// nothing in that check reads prose. Trusting "structure still matches" as
// proof of "content is in sync" was the actual bug: it let real drift go
// undetected indefinitely, silently, exactly the failure mode this whole
// tool exists to prevent.
//
// The fix: record a hash of the exact CLAUDE.md bytes AGENTS.md was
// generated from. "In sync" now means "byte-identical source", not "same
// shape". This also makes sync detection fully deterministic — no model
// call needed to answer "has anything changed since last generation", only
// to actually produce a new generation once drift is found.

import { createHash } from "node:crypto";

const TRAILER_RE = /\n?<!--\s*wiserepo:source-sha256:([0-9a-f]{64})\s*-->\s*$/;

export function computeSourceHash(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Extracts the recorded source hash from a generated doc, or null if absent/malformed. */
export function extractSourceTrailer(markdown) {
  const m = TRAILER_RE.exec(markdown);
  return m ? m[1] : null;
}

/** Returns `markdown` with any existing trailer removed, its content otherwise untouched. */
export function stripSourceTrailer(markdown) {
  return markdown.replace(TRAILER_RE, "");
}

/** Returns `markdown` with a fresh trailer for `sourceHash` appended (replacing any existing one). */
export function embedSourceTrailer(markdown, sourceHash) {
  const stripped = stripSourceTrailer(markdown).replace(/\n+$/, "");
  return `${stripped}\n\n<!-- wiserepo:source-sha256:${sourceHash} -->\n`;
}
