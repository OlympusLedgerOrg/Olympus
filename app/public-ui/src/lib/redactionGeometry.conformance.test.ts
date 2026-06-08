/**
 * Pin the TS `computeRevealMask` chunk geometry against the Rust
 * `redact_chunk_aligned` reference.
 *
 * Both implementations assert against the SAME golden file
 * (`redactionGeometry.vectors.json`): this test here, and
 * `src-tauri/src/zk/redact.rs::geometry_golden_vectors` over there. The mask is
 * the load-bearing value in the redaction producer flow — if the client mask
 * drifts from the server chunk geometry by one chunk, the issued bundle fails
 * to verify on the server. Shared vectors are the actual cross-impl guarantee;
 * hand-mirrored test cases are only as trustworthy as whoever wrote them.
 *
 * If you change chunk geometry, BOTH this and the Rust test fail, and the JSON
 * must be regenerated to match both.
 */
import { describe, expect, it } from "vitest";
// Load the shared vector file as a raw string (Vite `?raw`, typed by
// vite/client) and parse it — this keeps Rust and TS reading the exact same
// bytes without needing resolveJsonModule or Node fs types in the app tsconfig.
import goldenRaw from "./redactionGeometry.vectors.json?raw";
import { computeRevealMask, MAX_LEAVES } from "../hooks/useRedactionCreate";

interface GeoVector {
  name: string;
  n: number;
  ranges: [number, number][];
  mask: number[];
}
interface GeoFile {
  max_leaves: number;
  vectors: GeoVector[];
}

const golden = JSON.parse(goldenRaw) as GeoFile;

describe("redaction geometry golden vectors", () => {
  it("declares the same MAX_LEAVES the code uses", () => {
    expect(golden.max_leaves).toBe(MAX_LEAVES);
  });

  it("has vectors to check", () => {
    expect(golden.vectors.length).toBeGreaterThan(0);
  });

  for (const v of golden.vectors) {
    it(`computeRevealMask matches: ${v.name}`, () => {
      const ranges = v.ranges.map(([start, end]) => ({ start, end }));
      expect(computeRevealMask(v.n, ranges)).toEqual(v.mask);
    });
  }
});
