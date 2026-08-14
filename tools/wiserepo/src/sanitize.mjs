// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Strips characters from model output that have no legitimate place in
// Markdown documentation but are exactly the vectors used to smuggle hidden
// instructions into text a reader (human or AI) skims past visually.
//
// This matters more than it would in most tools: CLAUDE.md and AGENTS.md are
// not just docs, they are files future Claude Code / Codex sessions read and
// treat as authoritative instructions. checkStructuralParity validates
// counts (headings/bullets/tables/code-blocks); it says nothing about the
// BYTES of what gets written, and neither did anything else before this --
// raw model output flowed straight from an HTTP response into a file this
// repo's own tooling later trusts. Flagged by CodeQL (js/http-to-file-access)
// as untrusted network data reaching a file write, and -- independent of
// CodeQL -- a real prompt-injection-smuggling concern for this specific pair
// of files. Applied to every regeneration before the structural-parity check
// runs, so a stripped character can also change counts and get caught there.
//
// Every codepoint below is a numeric \u escape and named in a plain-English
// comment, deliberately -- this file's entire job is stripping invisible and
// control characters, so it must not itself contain any literal ones. A
// literal zero-width or bidi-override character pasted into this source
// would be exactly the kind of bug nobody could see in a code review, and
// would defeat the file's own purpose from the inside.
//
// What this does NOT do: validate semantic content, or catch an attack that
// uses only ordinary printable characters (e.g. English text arguing for a
// bad instruction) -- see sections.mjs's own caveat about what structural
// checks can't catch. This closes the invisible-character class of attack,
// not the "convincingly-worded" class; nothing here removes the need to read
// a regenerated AGENTS.md before trusting it.

// C0 controls, excluding U+0009 (tab) and U+000A (line feed) which are kept.
// U+000D (carriage return) is deliberately included: this repo's Markdown is
// LF-only, and a raw CR is itself a vector some renderers/terminals treat as
// a cursor-return that can make text appear different from its underlying
// bytes -- stripped so "read the diff" (the safeguard this tool leans on
// everywhere else) actually shows what is there. Also strips U+007F (DEL).
const CONTROL_RANGES = "\\u0000-\\u0008\\u000B-\\u001F\\u007F";

// Zero-width and bidi-override characters. These render as nothing, or as
// an invisible direction change, which is precisely how "trojan source"
// -style attacks hide text that reads differently to a human skimming the
// file than to whatever actually parses it.
//   U+200B         ZERO WIDTH SPACE
//   U+200C         ZERO WIDTH NON-JOINER
//   U+200D         ZERO WIDTH JOINER
//   U+200E         LEFT-TO-RIGHT MARK
//   U+200F         RIGHT-TO-LEFT MARK
//   U+202A-U+202E  bidi embedding/override controls (LRE/RLE/PDF/LRO/RLO)
//   U+2060         WORD JOINER
//   U+2061-U+2064  invisible math operators (function-application/times/
//                  invisible-separator/invisible-plus)
//   U+2066-U+2069  bidi isolate controls (LRI/RLI/FSI/PDI)
//   U+FEFF         BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
const INVISIBLE_RANGES = "\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\uFEFF";

const SANITIZE_RE = new RegExp(`[${CONTROL_RANGES}${INVISIBLE_RANGES}]`, "g");

export function sanitizeGeneratedMarkdown(text) {
  return text.replace(SANITIZE_RE, "");
}
