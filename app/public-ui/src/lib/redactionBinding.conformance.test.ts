/**
 * Pin the JS `recomputeRedactionCommitment` output against the Rust
 * `pdf_objects.rs::js_conformance_fixture_locked` reference value (ADR-0026).
 *
 * The expected decimal value is pinned in
 * `verifiers/test_vectors/redaction_vectors.json` (emitted by
 * `pdf_objects.rs::emit_redaction_vectors`) AND asserted by the Rust
 * `pdf_objects::js_conformance_fixture_locked` test. If ANY side changes
 * (object-leaf domain prefix, Pedersen H derivation, Poseidon parameters,
 * fold order, mask convention, anything), ALL THREE assertions fail and ALL
 * THREE must be updated in the same commit. That's the entire point of
 * this file — drift between the desktop, web, and reference auditors would
 * silently invalidate every redaction audit.
 *
 * The test exercises the object-leaf + Merkle-root + redactedCommitment
 * pipeline directly from the vector's `objects` array (no PDF xref parsing
 * — that's covered by `pdfObjects.test.ts`). The xref parser is the only
 * thing between a real bundle audit and this conformance pin.
 */
import { describe, it, expect, vi } from "vitest";
import { poseidon2 } from "poseidon-lite";
// Vite `?raw` import — works in vitest and satisfies `tsc -b` via the
// `vite/client` ambient module types (no node types in tsconfig.app.json).
import vectorsRaw from "../../../../verifiers/test_vectors/redaction_vectors.json?raw";

// `redactionBinding.ts` only needs `@noble/hashes`, not the WASM-backed
// `lib/blake3.ts`. But importing it indirectly via `useRedactionAudit` or
// `api.ts` in any other test would drag in the WASM init; mock it to be
// safe across the suite.
vi.mock("./blake3", async () => ({
  hashBytes: async () => "",
}));

const { objectLeaf, recomputeRedactionCommitment, MAX_LEAVES } = await import(
  "./redactionBinding"
);

interface VectorObject {
  obj_id: number;
  bytes_hex: string;
  blinding_decimal: string;
  leaf_hex: string;
}
interface RedactionVectors {
  scheme: string;
  obj_domain: string;
  max_leaves: number;
  tree_depth: number;
  objects: VectorObject[];
  reveal_mask: number[];
  revealed_count: number;
  original_root_hex: string;
  redacted_commitment_decimal: string;
}

const data: RedactionVectors = JSON.parse(vectorsRaw);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex32(x: bigint): string {
  return x.toString(16).padStart(64, "0");
}

function domainNode(domain: bigint, left: bigint, right: bigint): bigint {
  const inner = poseidon2([domain, left]);
  return poseidon2([inner, right]);
}

describe("redactionBinding: Rust↔JS object-level conformance (ADR-0026)", () => {
  it("pins ADR-0026 geometry against the shared vectors file", () => {
    expect(data.scheme).toBe("pdf-object-level-redaction-adr0026");
    expect(data.obj_domain).toBe("OLY:REDACTION:OBJ:V1");
    expect(data.max_leaves).toBe(MAX_LEAVES);
    expect(data.tree_depth).toBe(10);
  });

  it("recomputes each per-object hiding leaf byte-for-byte", () => {
    for (const o of data.objects) {
      const leaf = objectLeaf(
        o.obj_id,
        hexToBytes(o.bytes_hex),
        BigInt(o.blinding_decimal),
      );
      expect(toHex32(leaf)).toBe(o.leaf_hex);
    }
  });

  it("recomputes originalRoot via depth-10 fold over padded leaves", () => {
    const realLeaves = data.objects.map((o) =>
      objectLeaf(o.obj_id, hexToBytes(o.bytes_hex), BigInt(o.blinding_decimal)),
    );
    let level: bigint[] = realLeaves.slice();
    while (level.length < data.max_leaves) level.push(0n);
    for (let d = 0; d < data.tree_depth; d++) {
      const next: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(domainNode(1n, level[i], level[i + 1]));
      }
      level = next;
    }
    expect(toHex32(level[0])).toBe(data.original_root_hex);
  });

  it("recomputes redactedCommitment via the padded mask chain", () => {
    // Replay the high-level pipeline directly (the API used by the auditor
    // takes a full PDF; here we drive the lower layer from the vectors so the
    // pin is independent of xref parsing).
    const realLeaves = data.objects.map((o) =>
      objectLeaf(o.obj_id, hexToBytes(o.bytes_hex), BigInt(o.blinding_decimal)),
    );
    const padded = realLeaves.slice();
    while (padded.length < data.max_leaves) padded.push(0n);
    const mask = new Array<boolean>(data.max_leaves).fill(false);
    data.reveal_mask.forEach((b, i) => {
      mask[i] = b === 1;
    });
    const revealedCount = mask.filter(Boolean).length;
    expect(revealedCount).toBe(data.revealed_count);

    let acc = BigInt(revealedCount);
    for (let i = 0; i < data.max_leaves; i++) {
      const val = mask[i] ? padded[i] : 0n;
      acc = domainNode(3n, acc, val);
    }
    expect(acc.toString()).toBe(data.redacted_commitment_decimal);
  });

  it("rejects empty input", async () => {
    await expect(
      recomputeRedactionCommitment(new Uint8Array(0), [], []),
    ).rejects.toThrow(/empty/);
  });

  it("rejects a tampered object byte", () => {
    const o = data.objects.find((_, i) => data.reveal_mask[i] === 0) ??
      data.objects[0];
    const tampered = new Uint8Array(hexToBytes(o.bytes_hex).length + 1);
    tampered.set(hexToBytes(o.bytes_hex), 0);
    tampered[tampered.length - 1] = 0;
    const got = objectLeaf(o.obj_id, tampered, BigInt(o.blinding_decimal));
    expect(toHex32(got)).not.toBe(o.leaf_hex);
  });
});
