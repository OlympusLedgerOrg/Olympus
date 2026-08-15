// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { gatherContext } from "../src/mcp-server.mjs";

// gatherContext is exported (rather than a module-private function) so
// these can exercise it directly instead of trusting the code by
// inspection. Importing this module does not hang on stdio — see the
// import.meta.url-guarded bootstrap at the bottom of mcp-server.mjs.

test("gatherContext rejects a files array over the per-request cap", async () => {
  const files = Array.from({ length: 41 }, () => "CLAUDE.md");
  await assert.rejects(() => gatherContext({ files }), /per-request cap is 40/);
});

test("gatherContext accepts a files array at the cap", async () => {
  const files = Array.from({ length: 40 }, () => "CLAUDE.md");
  // Should not throw the cap error; content is real CLAUDE.md repeated 40x,
  // so this also exercises the budget-truncation path below.
  const result = await gatherContext({ files });
  assert.equal(typeof result, "string");
});

test("gatherContext notes when the combined context budget is exceeded", async () => {
  // CLAUDE.md is tens of KB; repeating it is the cheapest way to blow past
  // the 300k combined budget without needing a synthetic huge fixture file.
  const files = Array.from({ length: 40 }, () => "CLAUDE.md");
  const result = await gatherContext({ files });
  assert.match(result, /total context exceeded 300000 chars/);
});

test("gatherContext with no files/grep/diffArgs returns an empty string, not an error", async () => {
  const result = await gatherContext({});
  assert.equal(result, "");
});
