// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { inferTaskClass, legacyHeuristic, routeTask } from "./route.mjs";

describe("routeTask", () => {
  it("routes allowlisted prose work to the local model", () => {
    const result = routeTask({ task: "summarize docs/architecture.md" });
    assert.equal(result.tier, "local");
    assert.equal(result.route, "ollama");
    assert.equal(result.allowed, true);
    assert.equal(result.escalated, false);
    assert.equal(result.taskClass, "summarize");
    assert.equal(result.model, "qwen2.5-coder:7b-instruct");
    assert.deepEqual(result.deniedPaths, []);
  });

  it("bypasses the local model when the prose names a protected path", () => {
    const result = routeTask({ task: "explain src-tauri/src/api/zk/mod.rs" });
    assert.equal(result.allowed, false);
    assert.equal(result.escalated, true);
    assert.equal(result.tier, "top");
    assert.equal(result.route, "codex");
    assert.equal(result.deniedPaths.length, 1);
    assert.match(result.deniedPaths[0].path, /^src-tauri\//);
  });

  it("bypasses the local model when a caller passes a protected path", () => {
    const result = routeTask({ task: "explain this module", paths: ["crates/core/src/lib.rs"] });
    assert.notEqual(result.tier, "local");
    assert.equal(result.allowed, false);
    assert.equal(result.tier, "top");
  });

  it("sends a denied but non-critical path to the mid tier", () => {
    const result = routeTask({
      task: "summarize this decision",
      paths: ["docs/adr/ADR-0030-redaction.md"],
    });
    assert.equal(result.allowed, false);
    assert.equal(result.tier, "mid");
  });

  it("treats implementation work as paid work", () => {
    const result = routeTask({ task: "add a settings page to the UI" });
    assert.equal(result.taskClass, null);
    assert.equal(result.tier, "mid");
    assert.equal(result.route, "codex");
    assert.equal(result.model, "gpt-5-codex");
  });

  it("maps the tier to the routed agent's model table", () => {
    const result = routeTask({ task: "rotate the signing key" });
    assert.equal(result.tier, "top");
    assert.equal(result.route, "codex");
    assert.equal(result.agent, "codex");
    assert.equal(result.model, "gpt-5-codex-max");
  });

  it("declines a review with no path list, because a diff can touch anything", () => {
    const result = routeTask({ task: "review this diff" });
    assert.equal(result.allowed, false);
    assert.equal(result.tier, "mid");
    assert.match(result.policyReason, /without an explicit path list/);
  });

  it("runs a review locally once every touched path is allowlisted", () => {
    const result = routeTask({ task: "review this diff", paths: ["docs/architecture.md"] });
    assert.equal(result.allowed, true);
    assert.equal(result.tier, "local");
    assert.equal(result.route, "ollama");
  });

  it("sends pure lookups to deterministic tooling instead of a model", () => {
    const result = routeTask({ task: "where is the leaf hash computed" });
    assert.equal(result.tier, "deterministic");
    assert.equal(result.model, null);
    assert.equal(result.allowed, false);
  });

  it("never consults a model to decide routing", () => {
    const result = routeTask({ task: "summarize docs/architecture.md" });
    assert.equal(typeof result?.then, "undefined");
    assert.equal(result.fallback.basis, "local discovery or explanation");
  });

  it("rejects an empty task", () => {
    assert.throws(() => routeTask({ task: "   " }), /task description is required/);
  });
});

describe("legacyHeuristic", () => {
  it("keeps the pre-policy answers for existing consumers", () => {
    assert.deepEqual(legacyHeuristic("update the signature verification path"), {
      route: "codex",
      reasoning: "high",
      review: "claude",
      basis: "security-sensitive repository rule",
    });
    assert.equal(legacyHeuristic("implement a settings page").route, "codex");
    assert.equal(legacyHeuristic("check this diff").route, "claude");
    assert.equal(legacyHeuristic("what does this do").route, "ollama");
  });
});

describe("inferTaskClass", () => {
  it("recognizes the local-capable classes only", () => {
    assert.equal(inferTaskClass("write a commit message for this branch"), "pr-text");
    assert.equal(inferTaskClass("add a docstring to this function"), "docstring");
    assert.equal(inferTaskClass("scaffold a test for the parser"), "test-scaffold");
    assert.equal(inferTaskClass("review this diff"), "review");
    assert.equal(inferTaskClass("summarize the vault docs"), "summarize");
    assert.equal(inferTaskClass("add a settings page to the UI"), null);
  });
});
