// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  PolicyError,
  assertPathsAllowed,
  compileGlob,
  decidePath,
  decidePaths,
  decideTask,
  extractDiffPaths,
  extractGrepPaths,
  extractPathMentions,
  isCriticalPath,
  loadPolicy,
  modelFor,
  normalizeRepoPath,
} from "./policy.mjs";

describe("normalizeRepoPath", () => {
  it("normalizes separators, leading ./ and case", () => {
    assert.equal(normalizeRepoPath(".\\app\\public-ui\\src\\App.tsx"), "app/public-ui/src/app.tsx");
    assert.equal(normalizeRepoPath("docs//a.md"), "docs/a.md");
    assert.equal(normalizeRepoPath("SRC-TAURI/src/main.rs"), "src-tauri/src/main.rs");
  });

  it("refuses anything that cannot be resolved as a plain repo path", () => {
    for (const value of [
      "",
      "   ",
      "/etc/passwd",
      "C:/Windows/win.ini",
      "a/../../b",
      "..",
      "docs/..",
    ]) {
      assert.equal(normalizeRepoPath(value), null, `expected null for ${JSON.stringify(value)}`);
    }
    assert.equal(normalizeRepoPath(undefined), null);
  });
});

describe("compileGlob", () => {
  it("supports ** across segments", () => {
    const re = compileGlob("**/*.pem");
    assert.ok(re.test("server.pem"));
    assert.ok(re.test("a/b/server.pem"));
    assert.ok(!re.test("server.pemx"));
  });

  it("keeps * inside one segment", () => {
    const re = compileGlob("docs/*.md");
    assert.ok(re.test("docs/a.md"));
    assert.ok(!re.test("docs/adr/a.md"));
  });

  it("matches a substring pattern in a file name", () => {
    const re = compileGlob("app/**/*verify*");
    assert.ok(re.test("app/public-ui/src/verify/verifypanel.tsx"));
    assert.ok(re.test("app/public-ui/src/components/verifybadge.tsx"));
    assert.ok(!re.test("docs/verify.md"));
  });

  it("folds the pattern so capitalized entries still match normalized paths", () => {
    assert.ok(compileGlob("README.md").test("readme.md"));
    assert.ok(compileGlob("**/Dockerfile").test("docker/dockerfile"));
    assert.ok(compileGlob("AGENTS.md").test("agents.md"));
  });
});

describe("decidePath", () => {
  it("denies protected trees even though they are never allowlisted", () => {
    for (const path of [
      "src-tauri/src/api/zk/mod.rs",
      "crates/olympus-core/src/lib.rs",
      "proofs/leaf.circom",
      "tools/wiserepo/src/mcp-server.mjs",
      "scripts/check-pr-scope.mjs",
      "AGENTS.md",
      ".claude/settings.json",
      ".github/workflows/ci.yml",
      "Cargo.toml",
      "app/public-ui/package.json",
      "docs/adr/ADR-0030-redaction.md",
      "docs/audits/2025-audit.md",
      "secrets/keys.json",
      "app/public-ui/src/components/VerifyPanel.tsx",
    ]) {
      const decision = decidePath(path, "summarize");
      assert.equal(decision.allowed, false, `expected ${path} to be denied`);
      assert.match(decision.reason, /denied path|not on the allowlist/);
    }
  });

  it("allows only prose and non-protected app UI sources", () => {
    for (const path of [
      "docs/architecture.md",
      "docs/engines/vault/README.md",
      "README.md",
      "app/public-ui/src/App.tsx",
      "app/public-ui/src/components/SettingsPanel.tsx",
      "app/public-ui/index.html",
    ]) {
      assert.equal(decidePath(path, "summarize").allowed, true, `expected ${path} to be allowed`);
    }
  });

  it("refuses unknown paths and unknown task classes", () => {
    assert.equal(decidePath("src/main.rs", "summarize").allowed, false);
    assert.match(decidePath("docs/a.md", "not-a-class").reason, /unknown task class/);
    assert.equal(decidePath("docs/a.md", undefined).allowed, false);
  });

  it("applies a class allowlist on top of the global one", () => {
    assert.equal(decidePath("app/public-ui/src/App.tsx", "docstring").allowed, true);
    assert.equal(decidePath("docs/architecture.md", "docstring").allowed, false);
  });

  it("folds case so a Windows path cannot dodge a deny prefix", () => {
    assert.equal(decidePath("SRC-TAURI/src/main.rs", "summarize").allowed, false);
    assert.equal(decidePath("DOCS/ADR/ADR-0030-redaction.md", "summarize").allowed, false);
  });
});

describe("decidePaths and assertPathsAllowed", () => {
  it("refuses the whole request when one path is denied", () => {
    const result = decidePaths(["docs/a.md", "src-tauri/src/main.rs"], "summarize");
    assert.equal(result.ok, false);
    assert.deepEqual(result.allowed, ["docs/a.md"]);
    assert.deepEqual(
      result.denied.map((entry) => entry.path),
      ["src-tauri/src/main.rs"],
    );
  });

  it("throws a message that tells the agent what to do instead", () => {
    assert.throws(
      () => assertPathsAllowed(["crates/olympus-core/src/lib.rs"], "review"),
      (error) => {
        assert.ok(error instanceof PolicyError);
        assert.match(error.message, /may not see crates\/olympus-core\/src\/lib\.rs/);
        assert.match(error.message, /Read the file directly/);
        assert.match(error.message, /do not retry, rephrase/);
        assert.equal(error.denied.length, 1);
        return true;
      },
    );
  });

  it("does not throw when every path is allowed", () => {
    assert.doesNotThrow(() => assertPathsAllowed(["docs/a.md"], "qa"));
  });
});

describe("extractDiffPaths", () => {
  it("collects both sides of a rename out of a protected tree", () => {
    const diff = [
      "diff --git a/crates/core/src/a.rs b/app/public-ui/src/a.ts",
      "similarity index 90%",
      "rename from crates/core/src/a.rs",
      "rename to app/public-ui/src/a.ts",
      "diff --git a/docs/b.md b/docs/b.md",
      "--- a/docs/b.md",
      "+++ b/docs/b.md",
    ].join("\n");
    assert.deepEqual(extractDiffPaths(diff).sort(), [
      "app/public-ui/src/a.ts",
      "crates/core/src/a.rs",
      "docs/b.md",
    ]);
  });

  it("ignores /dev/null and empty input", () => {
    const diff = ["diff --git a/new.md b/new.md", "--- /dev/null", "+++ b/new.md"].join("\n");
    assert.deepEqual(extractDiffPaths(diff), ["new.md"]);
    assert.deepEqual(extractDiffPaths(""), []);
    assert.deepEqual(extractDiffPaths(undefined), []);
  });
});

describe("extractGrepPaths", () => {
  it("reads path:line:text hits and skips prose", () => {
    const hits = [
      "crates/core/src/merkle.rs:42:pub fn hash_leaf() {}",
      "docs/architecture.md:7:the merkle tree",
      "",
      "Binary file crates/core/logo.png matches",
    ].join("\n");
    assert.deepEqual(extractGrepPaths(hits), ["crates/core/src/merkle.rs", "docs/architecture.md"]);
  });
});

describe("extractPathMentions", () => {
  it("only treats real top-level entries as paths", () => {
    assert.deepEqual(extractPathMentions("fix and/or src-tauri/src/api/zk/mod.rs, thanks."), [
      "src-tauri/src/api/zk/mod.rs",
    ]);
    assert.deepEqual(extractPathMentions("read app/public-ui/src/App.tsx"), [
      "app/public-ui/src/App.tsx",
    ]);
  });
});

describe("decideTask", () => {
  const policy = loadPolicy();

  it("runs allowlisted prose work locally", () => {
    const decision = decideTask({
      taskClass: "summarize",
      text: "summarize docs/architecture.md",
      policy,
    });
    assert.equal(decision.qwenAllowed, true);
    assert.equal(decision.tier, "local");
    assert.deepEqual(decision.deniedPaths, []);
  });

  it("refuses a protected path named only in the prose", () => {
    const decision = decideTask({
      taskClass: "summarize",
      text: "summarize src-tauri/src/api/zk/mod.rs",
      policy,
    });
    assert.equal(decision.qwenAllowed, false);
    assert.equal(decision.tier, "top");
    assert.equal(decision.deniedPaths.length, 1);
  });

  it("sends a denied non-critical path to the mid tier", () => {
    const decision = decideTask({
      taskClass: "qa",
      paths: ["docs/adr/ADR-0030-redaction.md"],
      policy,
    });
    assert.equal(decision.qwenAllowed, false);
    assert.equal(decision.tier, "mid");
  });

  it("escalates on a protected concern even with allowed paths", () => {
    const decision = decideTask({
      taskClass: "qa",
      paths: ["docs/architecture.md"],
      text: "explain the hash chain",
      policy,
    });
    assert.equal(decision.qwenAllowed, false);
    assert.equal(decision.tier, "top");
  });

  it("treats implementation work as paid work, not local work", () => {
    const decision = decideTask({ text: "add a settings page to the UI", policy });
    assert.equal(decision.qwenAllowed, false);
    assert.equal(decision.tier, "mid");
  });

  it("never lets prose grant local access to an unknown class", () => {
    const decision = decideTask({
      taskClass: "made-up",
      text: "summarize docs/architecture.md",
      policy,
    });
    assert.equal(decision.qwenAllowed, false);
    assert.equal(decision.tier, "mid");
  });

  it("names critical prefixes once, for both the refusal and the gate", () => {
    assert.equal(isCriticalPath("crates/olympus-crypto/src/lib.rs"), true);
    assert.equal(isCriticalPath("SRC-TAURI/src/main.rs"), true);
    assert.equal(isCriticalPath("app/public-ui/src/App.tsx"), false);
    assert.equal(isCriticalPath("../../etc/passwd"), false);
  });

  it("maps capability labels to model ids per client", () => {
    assert.equal(modelFor("claude-code", "top", policy), "claude-opus-5-5");
    assert.equal(modelFor("codex", "mid", policy), "GPT-6.2 Astra");
    assert.equal(modelFor("unknown-client", "local", policy), "qwen2.5-coder:7b-instruct");
    assert.equal(modelFor("cli", "deterministic", policy), null);
  });
});
