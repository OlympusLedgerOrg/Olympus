// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeGeneratedMarkdown } from "../src/sanitize.mjs";

// Every test input below is built from \u escapes / String.fromCharCode,
// never a literal character in this source file, for the same reason
// src/sanitize.mjs itself avoids literal control/invisible characters: they
// would be invisible bugs in a file whose entire job is catching exactly
// that class of thing.

test("sanitizeGeneratedMarkdown leaves ordinary Markdown untouched", () => {
  const md = "# Title\n\n- bullet one\n- bullet two\n\n```bash\ncargo test\n```\n";
  assert.equal(sanitizeGeneratedMarkdown(md), md);
});

test("sanitizeGeneratedMarkdown preserves tab and newline", () => {
  const text = "a\tb\nc";
  assert.equal(sanitizeGeneratedMarkdown(text), text);
});

test("sanitizeGeneratedMarkdown strips C0 control characters other than tab/newline", () => {
  const withNull = "before" + String.fromCharCode(0x00) + "after";
  assert.equal(sanitizeGeneratedMarkdown(withNull), "beforeafter");
});

test("sanitizeGeneratedMarkdown strips carriage return", () => {
  const withCr = "line one\r\nline two";
  assert.equal(sanitizeGeneratedMarkdown(withCr), "line one\nline two");
});

test("sanitizeGeneratedMarkdown strips DEL (U+007F)", () => {
  const withDel = "before" + String.fromCharCode(0x7f) + "after";
  assert.equal(sanitizeGeneratedMarkdown(withDel), "beforeafter");
});

test("sanitizeGeneratedMarkdown strips zero-width space (the basic hidden-text vector)", () => {
  const zwsp = String.fromCharCode(0x200b);
  const withZwsp = "shard creation is" + zwsp + " operator-controlled";
  assert.equal(sanitizeGeneratedMarkdown(withZwsp), "shard creation is operator-controlled");
});

test("sanitizeGeneratedMarkdown strips bidi override characters (trojan-source vector)", () => {
  // U+202E RIGHT-TO-LEFT OVERRIDE — the character class behind CVE-2021-42574
  // ("Trojan Source"): text between an RLO and the next control renders
  // right-to-left, letting an attacker make a line read differently on
  // screen than its actual token order.
  const rlo = String.fromCharCode(0x202e);
  const withRlo = "safe text" + rlo + "hidden reversed segment";
  const result = sanitizeGeneratedMarkdown(withRlo);
  assert.equal(result, "safe texthidden reversed segment");
  assert.ok(!result.includes(rlo));
});

test("sanitizeGeneratedMarkdown strips the BOM / zero-width no-break space", () => {
  const bom = String.fromCharCode(0xfeff);
  assert.equal(sanitizeGeneratedMarkdown(bom + "# Title"), "# Title");
});

test("sanitizeGeneratedMarkdown strips bidi isolate controls", () => {
  const lri = String.fromCharCode(0x2066);
  const pdi = String.fromCharCode(0x2069);
  assert.equal(sanitizeGeneratedMarkdown(`a${lri}b${pdi}c`), "abc");
});

test("sanitizeGeneratedMarkdown handles empty string", () => {
  assert.equal(sanitizeGeneratedMarkdown(""), "");
});

test("sanitizeGeneratedMarkdown is idempotent", () => {
  const dirty = "text" + String.fromCharCode(0x200b) + String.fromCharCode(0x00);
  const once = sanitizeGeneratedMarkdown(dirty);
  const twice = sanitizeGeneratedMarkdown(once);
  assert.equal(once, twice);
});
