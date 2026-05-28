import { describe, expect, it } from "vitest";
import {
  MAX_PROOF_BUNDLE_BYTES,
  formatProofBundleSize,
  isProofVerificationRequest,
  parseProofBundleInput,
  proofRequestFromHashResponse,
  serializeProofBundle,
} from "./proofBundle";
import type { HashVerificationResponse, ProofVerificationRequest } from "./types";

const VALID: ProofVerificationRequest = {
  content_hash: "ch",
  merkle_root: "root",
  merkle_proof: { siblings: [], directions: [] },
};

describe("formatProofBundleSize", () => {
  it("renders bytes", () => {
    expect(formatProofBundleSize(512)).toBe("512 B");
  });
  it("renders KB to 1 decimal", () => {
    expect(formatProofBundleSize(2048)).toBe("2.0 KB");
  });
  it("renders MB to 1 decimal", () => {
    expect(formatProofBundleSize(2 * 1024 * 1024)).toBe("2.0 MB");
  });
  it("threshold constant matches the 50 KB cap", () => {
    expect(MAX_PROOF_BUNDLE_BYTES).toBe(50 * 1024);
  });
});

describe("isProofVerificationRequest", () => {
  it("accepts a well-formed bundle", () => {
    expect(isProofVerificationRequest(VALID)).toBe(true);
  });
  it("rejects null / primitives", () => {
    expect(isProofVerificationRequest(null)).toBe(false);
    expect(isProofVerificationRequest("hello")).toBe(false);
    expect(isProofVerificationRequest(42)).toBe(false);
  });
  it("rejects when content_hash is missing", () => {
    expect(isProofVerificationRequest({ ...VALID, content_hash: undefined })).toBe(false);
  });
  it("rejects when merkle_proof is not an object", () => {
    expect(isProofVerificationRequest({ ...VALID, merkle_proof: "nope" })).toBe(false);
  });
});

describe("parseProofBundleInput", () => {
  // Field order matters: stringify preserves insertion order, so by putting
  // merkle_proof first we get a JSON that ends with `"` instead of `}`. The
  // source's repair logic only kicks in when the trailing/leading char isn't
  // already a brace, so building the test fixture this way lets the
  // "missing closer" repair actually fire.
  const FLAT: ProofVerificationRequest = {
    merkle_proof: {},
    content_hash: "ch",
    merkle_root: "root",
  };
  const CLEAN = JSON.stringify(FLAT); // `{"merkle_proof":{},"content_hash":"ch","merkle_root":"root"}`
  const INNER = CLEAN.slice(1, -1);   // strips outer braces, body ends with `"`

  it("parses a clean bundle JSON paste", () => {
    expect(parseProofBundleInput(CLEAN)).toEqual(FLAT);
  });
  it("repairs a missing leading { (paste lost the opener)", () => {
    expect(parseProofBundleInput(`${INNER}}`)).toEqual(FLAT);
  });
  it("repairs a missing trailing } (paste lost the closer)", () => {
    expect(parseProofBundleInput(`{${INNER}`)).toEqual(FLAT);
  });
  it("repairs both braces missing", () => {
    expect(parseProofBundleInput(INNER)).toEqual(FLAT);
  });
  it("trims surrounding whitespace", () => {
    expect(parseProofBundleInput(`  \n${CLEAN}\n  `)).toEqual(FLAT);
  });
  it("throws on irrecoverable input", () => {
    expect(() => parseProofBundleInput("definitely not json")).toThrow(/invalid-proof-bundle-json/);
  });
  it("throws when JSON is valid but wrong shape", () => {
    expect(() => parseProofBundleInput(`{"x":1}`)).toThrow(/invalid-proof-bundle-json/);
  });
});

describe("proofRequestFromHashResponse", () => {
  const hashResp: HashVerificationResponse = {
    content_hash: "ch",
    proof_id: "pid",
    record_id: "rid",
    shard_id: "0",
    merkle_root: "root",
    merkle_proof_valid: true,
    ledger_entry_hash: "leh",
    timestamp: "2026-05-28T00:00:00Z",
    merkle_proof: { siblings: ["s1"], directions: [false] },
  };

  it("forwards proof_id when present", () => {
    const out = proofRequestFromHashResponse(hashResp);
    expect(out).toEqual({
      proof_id: "pid",
      content_hash: "ch",
      merkle_root: "root",
      merkle_proof: { siblings: ["s1"], directions: [false] },
    });
  });

  it("returns null when merkle_proof is null", () => {
    expect(proofRequestFromHashResponse({ ...hashResp, merkle_proof: null })).toBeNull();
  });
});

describe("serializeProofBundle", () => {
  it("formats with 2-space indentation", () => {
    const s = serializeProofBundle(VALID);
    expect(s).toContain('"content_hash": "ch"');
    expect(s.split("\n").length).toBeGreaterThan(1);
  });
});
