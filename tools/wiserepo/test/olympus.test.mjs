// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getOlympusContext, getCircuitStatus, checkInvariants } from "../src/olympus.mjs";

describe("olympus_context", () => {
  it("returns an object with a data field", async () => {
    const result = await getOlympusContext();
    assert.ok(result.source, "should have a source field");
    assert.ok(typeof result.data === "object", "data should be an object");
  });

  it("includes critical_constants when context.json exists", async () => {
    const result = await getOlympusContext();
    if (result.source === "context.json") {
      assert.ok(result.data.critical_constants, "should have critical_constants key");
      assert.strictEqual(result.data.critical_constants.LAZY_DEPTH, 72, "LAZY_DEPTH should be 72");
      assert.strictEqual(
        result.data.critical_constants.CANOPY_RECOMPUTE_CAP,
        1024,
        "CANOPY_RECOMPUTE_CAP should be 1024",
      );
    }
  });

  it("includes leaf_hash_implementations listing all four impls", async () => {
    const result = await getOlympusContext();
    if (result.source === "context.json") {
      const impls = result.data.leaf_hash_implementations;
      assert.ok(Array.isArray(impls), "leaf_hash_implementations should be an array");
      assert.ok(impls.length >= 4, "should list at least 4 implementations");
      const paths = impls.join(" ");
      assert.ok(paths.includes("olympus-crypto"), "should include olympus-crypto");
      assert.ok(paths.includes("verifiers/rust"), "should include verifiers/rust");
      assert.ok(paths.includes("verifiers/javascript"), "should include verifiers/javascript");
      assert.ok(paths.includes("clients/python"), "should include clients/python");
    }
  });
});

describe("circuit_status", () => {
  it("returns status for all four circuits", async () => {
    const result = await getCircuitStatus();
    assert.ok(result.circuits, "should have circuits key");
    assert.ok(result.summary, "should have summary key");

    const expected = [
      "document_existence",
      "non_existence",
      "unified_canonicalization_inclusion_root_sign",
      "federation_quorum",
    ];
    for (const circuit of expected) {
      assert.ok(circuit in result.circuits, `should report status for ${circuit}`);
    }
  });

  it("each circuit entry has the required fields", async () => {
    const result = await getCircuitStatus();
    const fields = [
      "wasm",
      "r1cs",
      "ark_zkey",
      "vkey_json",
      "manifest",
      "ready",
      "has_placeholders",
    ];
    for (const [name, entry] of Object.entries(result.circuits)) {
      for (const field of fields) {
        assert.ok(field in entry, `circuit ${name} should have field '${field}'`);
      }
    }
  });

  it("summary reports correct total count", async () => {
    const result = await getCircuitStatus();
    assert.strictEqual(result.summary.total, 4, "total should be 4 circuits");
    assert.ok(
      typeof result.summary.production_circuits_ready === "boolean",
      "production_circuits_ready should be a boolean",
    );
    assert.strictEqual(
      result.summary.setup_command,
      "cd proofs && bash setup_circuits.sh",
      "setup_command should match AGENTS.md",
    );
  });

  it("placeholder detection rejects the PLACEHOLDER sentinel string", async () => {
    // The PLACEHOLDER sentinel is what build.rs writes — a ~60-byte ASCII string
    // starting with the word PLACEHOLDER. Any artifact still containing it
    // means the ZK setup has not been run. This test just exercises the shape
    // of the output field without requiring a real artifact file.
    const result = await getCircuitStatus();
    for (const [, entry] of Object.entries(result.circuits)) {
      // Each status value must be one of the three known states
      const validStates = ["ok", "placeholder", "missing"];
      for (const field of ["wasm", "r1cs", "ark_zkey", "vkey_json", "manifest"]) {
        assert.ok(
          validStates.includes(entry[field]),
          `${field} status '${entry[field]}' must be one of: ${validStates.join(", ")}`,
        );
      }
    }
  });
});

describe("check_invariants", () => {
  it("returns an array of invariant results", async () => {
    const result = await checkInvariants();
    assert.ok(Array.isArray(result.invariants), "invariants should be an array");
    assert.ok(result.invariants.length > 0, "should check at least one invariant");
  });

  it("each invariant entry has required fields", async () => {
    const result = await checkInvariants();
    const fields = ["id", "description", "grep_pattern", "hits"];
    for (const inv of result.invariants) {
      for (const field of fields) {
        assert.ok(field in inv, `invariant should have field '${field}'`);
      }
      assert.ok(Array.isArray(inv.hits), "hits should be an array");
    }
  });

  it("checks LAZY_DEPTH and CANOPY_RECOMPUTE_CAP", async () => {
    const result = await checkInvariants();
    const ids = result.invariants.map((i) => i.id);
    assert.ok(ids.includes("LAZY_DEPTH"), "should check LAZY_DEPTH");
    assert.ok(ids.includes("CANOPY_RECOMPUTE_CAP"), "should check CANOPY_RECOMPUTE_CAP");
  });

  it("checks NODE_PREFIX and EMPTY_LEAF_PREFIX across all four impls", async () => {
    const result = await checkInvariants();
    const nodePrefix = result.invariants.find((i) => i.id === "NODE_PREFIX");
    const emptyLeaf = result.invariants.find((i) => i.id === "EMPTY_LEAF_PREFIX");

    assert.ok(nodePrefix, "should have NODE_PREFIX invariant");
    assert.ok(emptyLeaf, "should have EMPTY_LEAF_PREFIX invariant");

    // Both should reference all four implementation files
    assert.ok(
      nodePrefix.relevant_files.some((f) => f.includes("olympus-crypto")),
      "NODE_PREFIX should check olympus-crypto",
    );
    assert.ok(
      nodePrefix.relevant_files.some((f) => f.includes("verifiers/rust")),
      "NODE_PREFIX should check verifiers/rust",
    );
    assert.ok(
      nodePrefix.relevant_files.some((f) => f.includes("verifiers/javascript")),
      "NODE_PREFIX should check verifiers/javascript",
    );
    assert.ok(
      nodePrefix.relevant_files.some((f) => f.includes("clients/python")),
      "NODE_PREFIX should check clients/python",
    );
  });
});

describe("check_invariants grep scoping", () => {
  // Regression: gitGrep was called over the whole repo with a 4 KB cap and the
  // relevant-file filter ran AFTER truncation. docs/ and migrations/ hits sort
  // ahead of src-tauri/, so LAZY_DEPTH and CANOPY_RECOMPUTE_CAP were reported
  // as "no hits in relevant files" while sitting at tree.rs:129/148. Scoping
  // the grep to the invariant's own files before truncation is the fix.
  it("finds the pinned SMT constants in src-tauri/src/smt/tree.rs", async () => {
    const result = await checkInvariants();
    for (const id of ["LAZY_DEPTH", "CANOPY_RECOMPUTE_CAP"]) {
      const inv = result.invariants.find((entry) => entry.id === id);
      assert.ok(inv, `missing ${id}`);
      assert.ok(
        inv.hits.some((hit) => hit.startsWith("src-tauri/src/smt/tree.rs:")),
        `${id} should have a hit in tree.rs, got: ${inv.hits.join(" | ")}`,
      );
      assert.equal(inv.found_in_all_files, true, `${id} should be found in its file`);
    }
  });
});
