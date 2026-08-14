// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { chunkFile } from "../src/chunk.mjs";

// Bodies below are deliberately padded past the 40-char merge floor (see
// chunk.mjs's MIN_CHUNK_CHARS) so these tests isolate boundary DETECTION
// from the small-chunk MERGE behavior, which has its own dedicated tests
// further down. A test built from genuinely tiny snippets (the first
// version of this file) can't tell the two apart -- it was asserting 3
// separate chunks for content that, correctly, merges into 1.
test("chunkFile splits Rust at top-level fn/struct/impl boundaries", () => {
  const src = [
    "use std::fmt;",
    "use std::collections::HashMap;",
    "use std::sync::Arc;",
    "",
    "struct Foo {",
    "    x: u8,",
    "    y: u8,",
    "    z: u8,",
    "}",
    "",
    "fn bar() -> u8 {",
    "    let value = 1;",
    "    value + value",
    "}",
    "",
    "impl Foo {",
    "    fn method(&self) -> u8 {",
    "        self.x + self.y + self.z",
    "    }",
    "}",
  ].join("\n");
  const chunks = chunkFile("x.rs", src);
  // Four top-level sections: the leading use-block (everything before the
  // first fn/struct/impl/etc. boundary), struct Foo, fn bar, impl Foo.
  assert.equal(chunks.length, 4);
  assert.match(chunks[0].text, /^use std::fmt/);
  assert.match(chunks[1].text, /^struct Foo/);
  assert.match(chunks[2].text, /^fn bar/);
  assert.match(chunks[3].text, /^impl Foo/);
});

test("chunkFile does not split nested items inside an impl block", () => {
  const src = [
    "impl Foo {",
    "    fn a(&self) -> u8 {",
    "        self.x",
    "    }",
    "",
    "    fn b(&self) -> u8 {",
    "        self.y",
    "    }",
    "}",
  ].join("\n");
  const chunks = chunkFile("x.rs", src);
  assert.equal(chunks.length, 1);
  assert.match(chunks[0].text, /fn a/);
  assert.match(chunks[0].text, /fn b/);
});

test("chunkFile splits Markdown at headings", () => {
  const src =
    "# Title\n\nSome introductory text explaining what this document covers overall.\n\n" +
    "## Section A\n\nBody text for section A, long enough to clear the merge floor.\n\n" +
    "## Section B\n\nBody text for section B, also long enough to clear the merge floor.\n";
  const chunks = chunkFile("x.md", src);
  assert.equal(chunks.length, 3);
  assert.match(chunks[0].text, /^# Title/);
  assert.match(chunks[1].text, /^## Section A/);
  assert.match(chunks[2].text, /^## Section B/);
});

test("chunkFile splits JS at function/class/export boundaries", () => {
  const src = [
    "export function a() {",
    "    return 1 + 1 + 1;",
    "}",
    "",
    "class B {",
    "    constructor() {",
    "        this.value = 1;",
    "    }",
    "}",
    "",
    "export default function c() {",
    "    return 2 + 2 + 2;",
    "}",
  ].join("\n");
  const chunks = chunkFile("x.mjs", src);
  assert.equal(chunks.length, 3);
});

test("chunkFile falls back to fixed-size chunks for unrecognized extensions", () => {
  const src = Array.from({ length: 500 }, (_, i) => `line ${i} of a config file`).join("\n");
  const chunks = chunkFile("x.toml", src);
  assert.ok(chunks.length > 1, "long unrecognized-extension content should still be chunked");
  for (const c of chunks)
    assert.ok(c.text.length <= 4000 + 200, "chunks should respect the size cap");
});

test("chunkFile re-splits an oversized boundary-delimited section", () => {
  const bigFn = "fn huge() {\n" + "    let x = 1;\n".repeat(500) + "}\n";
  const chunks = chunkFile("x.rs", bigFn);
  assert.ok(chunks.length > 1, "a single function far over the size cap should still be split");
});

test("chunkFile merges small boundary-delimited sections rather than dropping them", () => {
  // Regression test for a real bug: two short functions, each well under
  // the 40-char floor, used to vanish entirely -- a chunker whose whole
  // job is "make code findable" was silently making some code unfindable.
  // Real content must never disappear; it may only be merged into a
  // neighboring chunk.
  const chunks = chunkFile("x.rs", "fn a() {}\n\n\n\nfn b() {}\n");
  assert.ok(chunks.length >= 1, "small real content must not vanish");
  const combined = chunks.map((c) => c.text).join("\n");
  assert.match(combined, /fn a/);
  assert.match(combined, /fn b/);
});

test("chunkFile drops genuinely empty sections (whitespace only) between boundaries", () => {
  // A run of blank lines between two boundaries IS real noise -- unlike the
  // small-but-real-content case above, there is nothing here to merge.
  const chunks = chunkFile("x.rs", "fn a() {\n    1\n}\n\n\n\n\nfn b() {\n    2\n}\n");
  const combined = chunks.map((c) => c.text).join("");
  assert.ok(!/^\s*$/.test(combined));
});

test("chunkFile reports 1-indexed, inclusive line ranges", () => {
  const src =
    "fn a() -> u8 {\n    let value = 1;\n    value\n}\n\nfn b() -> u8 {\n    let value = 2;\n    value\n}\n";
  const chunks = chunkFile("x.rs", src);
  assert.equal(chunks.length, 2);
  assert.equal(chunks[0].startLine, 1);
  assert.equal(chunks[1].startLine, 6);
});
