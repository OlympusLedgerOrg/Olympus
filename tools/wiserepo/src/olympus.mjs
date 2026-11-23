// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Olympus-specific structured tools for wiserepo.
// These return structured data about the repo state WITHOUT calling the model —
// they are fast, deterministic, and work offline.

import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { repoRoot, resolveInRepoFollowingSymlinks, gitGrep } from "./repo.mjs";

// ---------------------------------------------------------------------------
// olympus_context — machine-readable project facts from context.json
// ---------------------------------------------------------------------------

/**
 * Read and return context.json as a parsed object.
 * Falls back to a minimal hardcoded summary if the file is missing.
 */
export async function getOlympusContext() {
  const root = repoRoot();
  try {
    const contextPath = await resolveInRepoFollowingSymlinks("context.json");
    const raw = await readFile(contextPath, "utf8");
    return { source: "context.json", data: JSON.parse(raw) };
  } catch (err) {
    if (err.code === "ENOENT") {
      return {
        source: "hardcoded-fallback (context.json missing)",
        data: {
          project: "Olympus",
          version: "unknown — read AGENTS.md",
          note: "context.json not found in repo root. Run wiserepo to regenerate.",
        },
      };
    }
    if (err instanceof SyntaxError) {
      throw new Error(`context.json is malformed JSON: ${err.message}`);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// circuit_status — per-circuit artifact presence check
// ---------------------------------------------------------------------------

const CIRCUITS = [
  "document_existence",
  "non_existence",
  "unified_canonicalization_inclusion_root_sign",
  "federation_quorum",
];

// The ~60-byte PLACEHOLDER sentinel that build.rs writes for pre-setup stubs.
// A file whose content starts with this string (ASCII) is a placeholder.
const PLACEHOLDER_SENTINEL = "PLACEHOLDER";

async function fileStatus(absPath) {
  try {
    // Only read the first 64 bytes to check for the placeholder sentinel —
    // we do NOT want to buffer potentially large binary files.
    const handle = await (await import("node:fs/promises")).open(absPath, "r");
    try {
      const st = await handle.stat();
      if (!st.isFile()) return { exists: false, size: 0, isPlaceholder: false };
      const buf = Buffer.alloc(64);
      await handle.read(buf, 0, 64, 0);
      const preview = buf.toString("ascii");
      return {
        exists: true,
        size: st.size,
        isPlaceholder: preview.startsWith(PLACEHOLDER_SENTINEL),
      };
    } finally {
      await handle.close();
    }
  } catch {
    return { exists: false, size: 0, isPlaceholder: false };
  }
}

/**
 * Returns per-circuit artifact status: which files exist, which are placeholders.
 */
export async function getCircuitStatus() {
  const root = repoRoot();
  const keysDir = path.join(root, "proofs", "keys");
  const vkeysDir = path.join(keysDir, "verification_keys");
  const manifestsDir = path.join(keysDir, "manifests");

  const results = {};

  for (const circuit of CIRCUITS) {
    const wasm = await fileStatus(path.join(keysDir, `${circuit}.wasm`));
    const r1cs = await fileStatus(path.join(keysDir, `${circuit}.r1cs`));
    const arkzkey = await fileStatus(path.join(keysDir, `${circuit}.ark.zkey`));
    const vkey = await fileStatus(path.join(vkeysDir, `${circuit}_vkey.json`));
    const manifest = await fileStatus(path.join(manifestsDir, `${circuit}_manifest.json`));

    const anyPlaceholder = [wasm, r1cs, arkzkey, vkey, manifest].some((f) => f.isPlaceholder);
    const allPresent = [wasm, r1cs, arkzkey, vkey, manifest].every((f) => f.exists);

    results[circuit] = {
      wasm: wasm.exists ? (wasm.isPlaceholder ? "placeholder" : "ok") : "missing",
      r1cs: r1cs.exists ? (r1cs.isPlaceholder ? "placeholder" : "ok") : "missing",
      ark_zkey: arkzkey.exists ? (arkzkey.isPlaceholder ? "placeholder" : "ok") : "missing",
      vkey_json: vkey.exists ? (vkey.isPlaceholder ? "placeholder" : "ok") : "missing",
      manifest: manifest.exists ? (manifest.isPlaceholder ? "placeholder" : "ok") : "missing",
      ready: allPresent && !anyPlaceholder,
      has_placeholders: anyPlaceholder,
    };
  }

  const allReady = Object.values(results).filter((c) => c.ready).length;
  const productionCircuits = [
    "document_existence",
    "non_existence",
    "unified_canonicalization_inclusion_root_sign",
  ];
  const productionReady = productionCircuits.every((c) => results[c]?.ready);

  return {
    circuits: results,
    summary: {
      total: CIRCUITS.length,
      ready: allReady,
      production_circuits_ready: productionReady,
      setup_needed: !productionReady,
      setup_command: "cd proofs && bash setup_circuits.sh",
    },
  };
}

// ---------------------------------------------------------------------------
// check_invariants — grep each leaf-hash implementation for the ADR-0005
// constants and confirm they agree
// ---------------------------------------------------------------------------

// The four constants that must match across all implementations (ADR-0005).
// Values are what the codebase should contain — if a grep finds something
// different that is surfaced as a discrepancy, not an error in this tool.
const INVARIANT_CHECKS = [
  {
    id: "LAZY_DEPTH",
    description: "SMT lazy-storage depth (ADR-0022, pinned const)",
    grep: "LAZY_DEPTH",
    expected: "72",
    files: ["src-tauri/src/smt/tree.rs"],
  },
  {
    id: "CANOPY_RECOMPUTE_CAP",
    description: "SMT over-cap threshold (ADR-0022, pinned const)",
    grep: "CANOPY_RECOMPUTE_CAP",
    expected: "1024",
    files: ["src-tauri/src/smt/tree.rs"],
  },
  {
    id: "NODE_PREFIX",
    description: "SMT node hash domain prefix (all implementations must match)",
    grep: "OLY:NODE:V1",
    files: [
      "crates/olympus-crypto/src/lib.rs",
      "verifiers/rust/src/lib.rs",
      "verifiers/javascript/verifier.js",
      "clients/python/src/olympus_manifest/hashing.py",
    ],
  },
  {
    id: "EMPTY_LEAF_PREFIX",
    description: "SMT empty-leaf sentinel (all implementations must match)",
    grep: "OLY:EMPTY-LEAF:V1",
    files: [
      "crates/olympus-crypto/src/lib.rs",
      "verifiers/rust/src/lib.rs",
      "verifiers/javascript/verifier.js",
      "clients/python/src/olympus_manifest/hashing.py",
    ],
  },
  {
    id: "LEAF_BODY_FIELD_COUNT",
    description: "Leaf hash field count (0x05 = 5 fields, ADR-0005)",
    grep: "LEAF_BODY_FIELD_COUNT\\|0x05",
    files: ["crates/olympus-crypto/src/lib.rs"],
  },
];

/**
 * For each invariant, grep the repo for the constant and return hits.
 * This is evidence-gathering, not assertion — the caller (or model) interprets
 * whether the hits confirm or contradict the invariant.
 */
export async function checkInvariants() {
  const results = [];

  for (const check of INVARIANT_CHECKS) {
    let hits;
    try {
      // Restrict the grep to the files this invariant lives in BEFORE any
      // truncation. Searching the whole repo and filtering afterwards meant a
      // 4 KB cap could be consumed by docs/ and migrations/ hits (which sort
      // ahead of src-tauri/), so LAZY_DEPTH and CANOPY_RECOMPUTE_CAP reported
      // "no hits in relevant files" while sitting at tree.rs:129/148.
      hits = await gitGrep(check.grep, { globs: check.files ?? [], maxBytes: 8000 });
    } catch (err) {
      hits = `ERROR: ${err.message}`;
    }

    const lines = hits
      ? hits
          .split("\n")
          .filter(Boolean)
          // Keep only lines from the files we care about (if specified)
          .filter((line) =>
            check.files ? check.files.some((f) => line.startsWith(f + ":")) : true,
          )
      : [];

    results.push({
      id: check.id,
      description: check.description,
      grep_pattern: check.grep,
      expected_value: check.expected ?? "(see hits)",
      relevant_files: check.files ?? [],
      hits: lines.length > 0 ? lines : ["(no hits in relevant files)"],
      found_in_all_files: check.files
        ? check.files.every((f) => lines.some((l) => l.startsWith(f + ":")))
        : null,
    });
  }

  return { invariants: results };
}
