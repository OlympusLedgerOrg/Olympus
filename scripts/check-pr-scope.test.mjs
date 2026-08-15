#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  OVERRIDE_LABEL,
  evaluateScope,
  formatReport,
  globToRegExp,
  matchesAnyPattern,
  normalizePattern,
  parseScopeBlock,
  stripHtmlComments,
} from "./check-pr-scope.mjs";

// ── glob semantics ──────────────────────────────────────────────────────────
// Each case asserts both directions. A matcher tested only on paths it should
// accept passes trivially if it returns true for everything.

test("'*' and '?' stay inside one path segment", () => {
  assert.equal(globToRegExp("*.md").test("README.md"), true);
  assert.equal(globToRegExp("*.md").test("docs/README.md"), false);
  assert.equal(globToRegExp("docs/*.md").test("docs/a.md"), true);
  assert.equal(globToRegExp("docs/*.md").test("docs/adr/a.md"), false);
  assert.equal(globToRegExp("v?.rs").test("v1.rs"), true);
  assert.equal(globToRegExp("v?.rs").test("v10.rs"), false);
  assert.equal(globToRegExp("a/v?.rs").test("a/b/v1.rs"), false);
});

test("'**' crosses directories and may match zero segments", () => {
  assert.equal(globToRegExp("src-tauri/**").test("src-tauri/src/api/ledger.rs"), true);
  assert.equal(globToRegExp("src-tauri/**").test("src-tauri/Cargo.toml"), true);
  assert.equal(globToRegExp("src-tauri/**").test("crates/olympus-crypto/src/lib.rs"), false);
  // Zero-segment case: "**/" must not require an intermediate directory.
  assert.equal(globToRegExp("**/*.rs").test("main.rs"), true);
  assert.equal(globToRegExp("**/*.rs").test("a/b/main.rs"), true);
  assert.equal(globToRegExp("**/*.rs").test("a/b/main.ts"), false);
  assert.equal(globToRegExp("app/**/index.ts").test("app/index.ts"), true);
  assert.equal(globToRegExp("app/**/index.ts").test("app/a/b/index.ts"), true);
  assert.equal(globToRegExp("app/**/index.ts").test("other/a/index.ts"), false);
});

test("a trailing slash means everything beneath the directory", () => {
  assert.equal(globToRegExp("docs/").test("docs/adr/0001.md"), true);
  assert.equal(globToRegExp("docs/").test("docsite/a.md"), false);
});

test("a wildcard-free pattern covers itself and everything under it", () => {
  assert.equal(globToRegExp("docs").test("docs"), true);
  assert.equal(globToRegExp("docs").test("docs/adr/0001.md"), true);
  // Sibling-prefix guard: "docs" must not swallow "docs-internal".
  assert.equal(globToRegExp("docs").test("docs-internal/a.md"), false);
  // Root-anchored, unlike a slash-free gitignore pattern: a nested directory
  // of the same name is a different subsystem and must not be covered.
  assert.equal(globToRegExp("docs").test("app/docs/a.md"), false);
  assert.equal(
    globToRegExp("src-tauri/src/api/ledger.rs").test("src-tauri/src/api/ledger.rs"),
    true,
  );
  assert.equal(
    globToRegExp("src-tauri/src/api/ledger.rs").test("src-tauri/src/api/shards.rs"),
    false,
  );
});

test("regex metacharacters in paths are matched literally", () => {
  // A naive implementation compiles "." to "any character" and matches both.
  assert.equal(globToRegExp("a.b.rs").test("a.b.rs"), true);
  assert.equal(globToRegExp("a.b.rs").test("axbyrs"), false);
  assert.equal(globToRegExp("app/(group)/page.tsx").test("app/(group)/page.tsx"), true);
  assert.equal(globToRegExp("app/(group)/page.tsx").test("app/group/page.tsx"), false);
  assert.equal(globToRegExp("a+b").test("a+b"), true);
  assert.equal(globToRegExp("a+b").test("aab"), false);
});

test("patterns are anchored at both ends", () => {
  assert.equal(globToRegExp("docs/a.md").test("prefix-docs/a.md"), false);
  assert.equal(globToRegExp("docs/a.md").test("docs/a.md.bak"), false);
});

test("normalizePattern strips decoration and root-relative prefixes", () => {
  assert.equal(normalizePattern("  `docs/**`  "), "docs/**");
  assert.equal(normalizePattern('"src-tauri/src/**"'), "src-tauri/src/**");
  assert.equal(normalizePattern("/crates/**"), "crates/**");
  assert.equal(normalizePattern("./crates/**"), "crates/**");
  assert.equal(normalizePattern("   "), null);
});

test("unsupported pattern forms are rejected by name, not silently ignored", () => {
  // Each assertion names the expected reason: a bare `throws` would also pass
  // on an unrelated failure inside the matcher.
  assert.throws(() => normalizePattern("!docs/**"), /negated pattern .* is not supported/);
  assert.throws(() => normalizePattern("../outside/**"), /escapes the repository root/);
  assert.throws(() => normalizePattern("/"), /is not a scope/);
});

test("matchesAnyPattern is a union across declared patterns", () => {
  const patterns = ["app/public-ui/src/**", "docs/**"];
  assert.equal(matchesAnyPattern("app/public-ui/src/App.tsx", patterns), true);
  assert.equal(matchesAnyPattern("docs/adr/0001.md", patterns), true);
  assert.equal(matchesAnyPattern("crates/olympus-crypto/src/lib.rs", patterns), false);
});

// ── PR body parsing ─────────────────────────────────────────────────────────

test("parses a '## Scope' section and stops at the next heading", () => {
  const body = [
    "## Summary",
    "",
    "- not a scope entry",
    "",
    "## Scope",
    "",
    "- app/public-ui/src/**",
    "- `docs/**`",
    "",
    "## Checklist",
    "",
    "- [ ] tests pass",
  ].join("\n");
  assert.deepEqual(parseScopeBlock(body), {
    found: true,
    patterns: ["app/public-ui/src/**", "`docs/**`"],
  });
});

test("accepts bare and bold 'Scope:' markers", () => {
  for (const marker of ["Scope:", "Scope", "**Scope:**", "**Scope**", "#### scope"]) {
    const parsed = parseScopeBlock(`${marker}\n- docs/**\n`);
    assert.deepEqual(parsed, { found: true, patterns: ["docs/**"] }, `marker: ${marker}`);
  }
});

test("'Out of scope:' is not mistaken for a scope declaration", () => {
  const parsed = parseScopeBlock("Out of scope:\n- everything else\n");
  assert.deepEqual(parsed, { found: false, patterns: [] });
});

test("HTML comments never contribute patterns", () => {
  // The PR template ships "<!-- ... -->" guidance inside the Scope section; if
  // it parsed, every PR would inherit a placeholder pattern.
  const body = "## Scope\n\n<!--\n- placeholder/**\n-->\n\n- docs/**\n";
  assert.deepEqual(parseScopeBlock(body), { found: true, patterns: ["docs/**"] });
});

test("comment stripping reaches a fixpoint instead of one pass", () => {
  // Overlapping markers: a single removal pass over "<!-<!-- -->" splices the
  // surviving "<!-" onto the following "-" and reconstitutes a "<!--" that was
  // never a comment start in the input, which is what CodeQL reports as
  // incomplete multi-character sanitization. The fixture is asserted by shape
  // rather than by re-running a one-pass strip here: a test that reimplements
  // the buggy sanitizer to prove it is buggy earns its own CodeQL alert, and
  // asserting against the real exported function is the stronger check anyway.
  const crafted = "## Scope\n\n<!-<!-- -->- crates/olympus-crypto/**\n-->\n";
  assert.ok(crafted.includes("<!-<!--"), "fixture no longer overlaps comment markers");
  assert.ok(!stripHtmlComments(crafted).includes("<!--"), "residual comment marker survived");
  assert.ok(!stripHtmlComments(crafted).includes("-->"), "residual comment terminator survived");

  // Whatever the crafted body renders as, the parser must not silently adopt a
  // pattern from it: over-removal narrows the scope and fails the gate, which
  // is the safe direction.
  const parsed = parseScopeBlock(crafted);
  assert.deepEqual(parsed.patterns, []);
  const result = evaluateScope({ body: crafted, changedFiles: ["crates/olympus-crypto/src/x.rs"] });
  assert.equal(result.status, "empty-scope");
  assert.equal(result.ok, false);
});

test("a surviving comment marker in a list item is rejected, not treated as a path", () => {
  assert.throws(() => normalizePattern("crates/**<!--"), /contains an HTML comment marker/);
  assert.throws(() => normalizePattern("-->"), /contains an HTML comment marker/);
  // And it fails the whole check rather than dropping that one entry, so a
  // narrowed scope can never pass unnoticed.
  const result = evaluateScope({
    body: "## Scope\n\n- docs/**\n- crates/**-->\n",
    changedFiles: ["docs/a.md"],
  });
  assert.equal(result.status, "invalid-pattern");
  assert.equal(result.ok, false);
});

test("well-formed comments still strip in a single logical step", () => {
  // The fixpoint loop must not disturb the ordinary case: a comment that ends
  // at its first "-->" hides exactly what a renderer hides, no more.
  const body = "## Scope\n\n<!-- guidance: - placeholder/** -->\n\n- docs/**\n";
  assert.deepEqual(parseScopeBlock(body).patterns, ["docs/**"]);
});

test("a 'Scope' line inside a fenced block does not start the section", () => {
  const body = ["```", "Scope:", "- fake/**", "```", "", "## Scope", "", "- real/**"].join("\n");
  assert.deepEqual(parseScopeBlock(body), { found: true, patterns: ["real/**"] });
});

test("numbered lists and prose in the section are handled", () => {
  const body =
    "## Scope\n\nOnly the ingest path:\n\n1. src-tauri/src/api/ingest/**\n2) migrations/**\n";
  assert.deepEqual(parseScopeBlock(body), {
    found: true,
    patterns: ["src-tauri/src/api/ingest/**", "migrations/**"],
  });
});

test("a missing or empty body yields no declaration rather than throwing", () => {
  assert.deepEqual(parseScopeBlock(null), { found: false, patterns: [] });
  assert.deepEqual(parseScopeBlock(""), { found: false, patterns: [] });
  assert.deepEqual(parseScopeBlock("## Scope\n\n"), { found: true, patterns: [] });
});

test("the real PR template parses as a present-but-unfilled scope", () => {
  // Against the actual template, not a fixture: this repo has already shipped a
  // checker that passed its synthetic tests while failing on both real
  // documents it would ever see (see tools/wiserepo/README.md).
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const template = readFileSync(path.join(repoRoot, ".github", "PULL_REQUEST_TEMPLATE.md"), "utf8");
  const parsed = parseScopeBlock(template);
  // Found, so authors get "fill this in", not "you forgot a Scope block"...
  assert.equal(parsed.found, true);
  // ...and the worked example inside the guidance comment contributes nothing.
  assert.deepEqual(parsed.patterns, []);

  const result = evaluateScope({ body: template, changedFiles: ["src-tauri/src/main.rs"] });
  assert.equal(result.status, "empty-scope");
  assert.equal(result.ok, false);
});

// ── verdicts ────────────────────────────────────────────────────────────────

const bodyWithScope = (...patterns) =>
  `## Summary\n\nA change.\n\n## Scope\n\n${patterns.map((p) => `- ${p}`).join("\n")}\n`;

test("an in-scope diff passes", () => {
  const result = evaluateScope({
    body: bodyWithScope("app/public-ui/src/**"),
    changedFiles: ["app/public-ui/src/App.tsx", "app/public-ui/src/lib/api/index.ts"],
  });
  assert.equal(result.status, "in-scope");
  assert.equal(result.ok, true);
  assert.deepEqual(result.outOfScope, []);
});

test("the motivating case fails: a frontend task that reaches into shared crypto", () => {
  const result = evaluateScope({
    body: bodyWithScope("app/public-ui/src/**"),
    changedFiles: ["app/public-ui/src/App.tsx", "crates/olympus-crypto/src/util.rs"],
  });
  assert.equal(result.status, "out-of-scope");
  assert.equal(result.ok, false);
  assert.deepEqual(result.outOfScope, ["crates/olympus-crypto/src/util.rs"]);
  assert.match(formatReport(result), /crates\/olympus-crypto\/src\/util\.rs/);
});

test("a missing Scope block fails when scope is required and skips when it is not", () => {
  const changedFiles = ["src-tauri/src/main.rs"];
  const required = evaluateScope({ body: "## Summary\n\nNo scope here.\n", changedFiles });
  assert.equal(required.status, "missing-scope");
  assert.equal(required.ok, false);

  const optional = evaluateScope({
    body: "## Summary\n\nNo scope here.\n",
    changedFiles,
    requireScope: false,
  });
  assert.equal(optional.status, "skipped");
  assert.equal(optional.ok, true);
});

test("a repo-wide catch-all is rejected rather than passing vacuously", () => {
  for (const pattern of ["**", "*", "**/*", "/**", "./**"]) {
    const result = evaluateScope({
      body: bodyWithScope(pattern),
      changedFiles: ["anything/at/all.rs"],
    });
    assert.equal(result.status, "overbroad-scope", `pattern: ${pattern}`);
    assert.equal(result.ok, false, `pattern: ${pattern}`);
  }
});

test("an unsupported pattern fails the check instead of being dropped", () => {
  // Dropping "!x" silently would narrow the declared scope without telling
  // anyone, turning a typo into a passing check.
  const result = evaluateScope({
    body: bodyWithScope("docs/**", "!docs/secret.md"),
    changedFiles: ["docs/a.md"],
  });
  assert.equal(result.status, "invalid-pattern");
  assert.equal(result.ok, false);
  assert.equal(result.invalid.length, 1);
  assert.match(result.invalid[0].reason, /negated pattern/);
});

test("the override label suppresses a failure and records what it suppressed", () => {
  const result = evaluateScope({
    body: bodyWithScope("app/public-ui/src/**"),
    changedFiles: ["crates/olympus-crypto/src/util.rs"],
    labels: ["security", OVERRIDE_LABEL],
  });
  assert.equal(result.ok, true);
  assert.equal(result.status, "overridden");
  assert.equal(result.suppressedStatus, "out-of-scope");
  // The drift itself is still reported — an override must not erase the signal.
  assert.deepEqual(result.outOfScope, ["crates/olympus-crypto/src/util.rs"]);
  assert.match(formatReport(result), /suppressed by the "scope-override" label/);
});

test("an unrelated label does not override", () => {
  const result = evaluateScope({
    body: bodyWithScope("app/public-ui/src/**"),
    changedFiles: ["crates/olympus-crypto/src/util.rs"],
    labels: ["security", "dependencies"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.status, "out-of-scope");
  assert.equal(result.suppressedStatus, null);
});

test("the override label does not mark a clean PR as overridden", () => {
  const result = evaluateScope({
    body: bodyWithScope("docs/**"),
    changedFiles: ["docs/a.md"],
    labels: [OVERRIDE_LABEL],
  });
  assert.equal(result.status, "in-scope");
  assert.equal(result.suppressedStatus, null);
});

test("an empty diff passes any declared scope", () => {
  const result = evaluateScope({ body: bodyWithScope("docs/**"), changedFiles: [] });
  assert.equal(result.status, "in-scope");
  assert.equal(result.ok, true);
});

test("a pattern matching no changed file is reported but does not fail", () => {
  const result = evaluateScope({
    body: bodyWithScope("docs/**", "migrations/**"),
    changedFiles: ["docs/a.md"],
  });
  assert.equal(result.status, "in-scope");
  assert.equal(result.ok, true);
  assert.deepEqual(result.unusedPatterns, ["migrations/**"]);
  assert.match(formatReport(result), /Declared but unused patterns/);
});

test("every failing status renders an actionable report", () => {
  const cases = [
    evaluateScope({ body: "no scope", changedFiles: ["a.rs"] }),
    evaluateScope({ body: "## Scope\n\n", changedFiles: ["a.rs"] }),
    evaluateScope({ body: bodyWithScope("**"), changedFiles: ["a.rs"] }),
    evaluateScope({ body: bodyWithScope("!a"), changedFiles: ["a.rs"] }),
    evaluateScope({ body: bodyWithScope("docs/**"), changedFiles: ["a.rs"] }),
  ];
  for (const result of cases) {
    assert.equal(result.ok, false, `expected failure for ${result.status}`);
    const report = formatReport(result);
    assert.ok(report.length > 0, `empty report for ${result.status}`);
    assert.doesNotMatch(report, /Unrecognized status/, `unhandled status ${result.status}`);
  }
});
