/**
 * Pin the JS `recomputeRedactionCommitment` output against the Rust
 * `redaction_commitment` reference.
 *
 * The expected decimal value below is emitted by
 * `src-tauri/src/zk/chunk.rs::js_conformance_fixture_locked`. If either
 * side changes (chunking, BLAKE3 domain tag, Poseidon parameterisation,
 * mask convention, anything), BOTH tests fail and BOTH must be updated.
 * That's the entire point of this file — drift between the desktop and
 * web auditors would silently invalidate every redaction audit.
 */
import { describe, it, expect, vi } from "vitest";

// jsdom can't fetch a WASM URL the way Vite resolves it at build time, so
// swap the WASM-backed BLAKE3 for a pure-JS one in tests. BLAKE3 has a
// single specification — the two implementations produce identical hex
// digests, which is exactly what this conformance test relies on.
vi.mock("./blake3", async () => {
  const { blake3 } = await import("@noble/hashes/blake3.js");
  const { bytesToHex } = await import("@noble/hashes/utils.js");
  return {
    hashBytes: async (data: Uint8Array) => bytesToHex(blake3(data)),
  };
});

const { recomputeRedactionCommitment } = await import("./redactionBinding");

// Pinned Rust fixture spec (see chunk.rs::js_conformance_fixture_locked):
//   bytes        = b"OLYMPUS_REDACTION_FIXTURE_V1"
//   reveal_mask  = alternating, 8 revealed
const FIXTURE_BYTES = new TextEncoder().encode("OLYMPUS_REDACTION_FIXTURE_V1");
const FIXTURE_MASK = Array.from({ length: 16 }, (_, i) => (i % 2 === 0 ? 1 : 0));
const FIXTURE_EXPECTED_DEC =
  "1786829174294484691772886452158686008354416298517052234753040495478582148229";

describe("redactionBinding: Rust↔JS conformance", () => {
  it("recomputes the pinned Rust fixture value byte-for-byte", async () => {
    const got = await recomputeRedactionCommitment(FIXTURE_BYTES, FIXTURE_MASK);
    expect(got).toBe(FIXTURE_EXPECTED_DEC);
  });

  it("rejects mask of wrong length", async () => {
    await expect(
      recomputeRedactionCommitment(FIXTURE_BYTES, Array(15).fill(1)),
    ).rejects.toThrow(/reveal_mask must have 16 entries/);
  });

  it("rejects non-binary mask entries", async () => {
    const badMask = [...FIXTURE_MASK];
    badMask[3] = 2;
    await expect(
      recomputeRedactionCommitment(FIXTURE_BYTES, badMask),
    ).rejects.toThrow(/not 0 or 1/);
  });

  it("rejects empty input", async () => {
    await expect(
      recomputeRedactionCommitment(new Uint8Array(0), FIXTURE_MASK),
    ).rejects.toThrow(/empty/);
  });
});
