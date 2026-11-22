// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { gatherContext, budgetCharsFor, orderFilesForQuestion } from "../src/mcp-server.mjs";

// gatherContext is exported (rather than a module-private function) so
// these can exercise it directly instead of trusting the code by
// inspection. Importing this module does not hang on stdio — see the
// import.meta.url-guarded bootstrap at the bottom of mcp-server.mjs.

test("gatherContext rejects a files array over the per-request cap", async () => {
  const files = Array.from({ length: 41 }, () => "AGENTS.md");
  await assert.rejects(() => gatherContext({ files }), /per-request cap is 40/);
});

test("gatherContext accepts a files array at the cap", async () => {
  const files = Array.from({ length: 40 }, () => "AGENTS.md");
  // Should not throw the cap error; content is real AGENTS.md repeated 40x,
  // so this also exercises the budget-truncation path below.
  const result = await gatherContext({ files });
  assert.equal(typeof result, "string");
});

test("gatherContext notes when the combined context budget is exceeded", async () => {
  // AGENTS.md is tens of KB; repeating it is the cheapest way to blow past
  // the combined budget without needing a synthetic huge fixture file.
  const files = Array.from({ length: 40 }, () => "AGENTS.md");
  const result = await gatherContext({ files });
  // Asserted as a shape, not a literal: the budget is derived from the model's
  // effective window, so a hardcoded number here would encode one machine's
  // model and fail on any other.
  assert.match(result, /combined context exceeded \d+ chars/);
});

// The files that lost out used to vanish silently — the model answered from a
// partial view and the caller had no way to know which file it never saw.
test("gatherContext names the files it dropped for budget", async () => {
  const files = Array.from({ length: 40 }, () => "AGENTS.md");
  const result = await gatherContext({ files });
  assert.match(result, /dropped \d+ file\(s\) that did not fit: /);
});

test("gatherContext with no files/grep/diffArgs returns an empty string, not an error", async () => {
  const result = await gatherContext({});
  assert.equal(result, "");
});

// The budget must leave room for the answer inside the same window; if it ever
// consumed the whole context the model would be asked to generate with none.
test("budgetCharsFor reserves output space inside the window", () => {
  assert.ok(budgetCharsFor(16_384) < 16_384 * 3, "budget must leave output headroom");
  assert.ok(budgetCharsFor(16_384) > 30_000, "budget should still be usable in practice");
  // Degenerate windows must not produce a negative or zero budget.
  assert.ok(budgetCharsFor(2_048) > 0);
});

// Relevance ordering exists because budget is spent in list order: with a small
// window, whichever file is named last disappears.
test("orderFilesForQuestion floats path-matching files ahead of the rest", () => {
  const files = ["docs/README.md", "src-tauri/src/smt/tree.rs", "AGENTS.md"];
  const ordered = orderFilesForQuestion(files, "what is the smt tree depth?");
  assert.equal(ordered[0], "src-tauri/src/smt/tree.rs");
});

test("orderFilesForQuestion preserves caller order when the question says nothing matchable", () => {
  const files = ["b.md", "a.md"];
  assert.deepEqual(orderFilesForQuestion(files, ""), files);
  assert.deepEqual(orderFilesForQuestion(files, "of to"), files);
});
