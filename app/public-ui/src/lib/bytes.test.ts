/**
 * Tests for lib/bytes.ts — base64 round-trips, including the >32 KiB chunk
 * boundary that the naive `String.fromCharCode(...all)` would blow up on.
 */
import { describe, expect, it } from "vitest";
import { bytesToBase64, base64ToBytes } from "./bytes";

function roundTrip(bytes: Uint8Array) {
  return base64ToBytes(bytesToBase64(bytes));
}

describe("bytes base64", () => {
  it("round-trips an empty buffer", () => {
    expect(bytesToBase64(new Uint8Array(0))).toBe("");
    expect(base64ToBytes("")).toEqual(new Uint8Array(0));
  });

  it("round-trips arbitrary small bytes", () => {
    const b = new Uint8Array([0, 1, 2, 254, 255, 127, 128]);
    expect(Array.from(roundTrip(b))).toEqual(Array.from(b));
  });

  it("matches a known base64 vector", () => {
    // "hello" → aGVsbG8=
    const hello = new TextEncoder().encode("hello");
    expect(bytesToBase64(hello)).toBe("aGVsbG8=");
    expect(new TextDecoder().decode(base64ToBytes("aGVsbG8="))).toBe("hello");
  });

  it("round-trips across the 32 KiB chunk boundary", () => {
    const n = 0x8000 * 2 + 123; // spans 3 chunks
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
    const out = roundTrip(b);
    expect(out.length).toBe(n);
    expect(Array.from(out)).toEqual(Array.from(b));
  });

  it("tolerates surrounding whitespace on decode", () => {
    expect(new TextDecoder().decode(base64ToBytes("  aGVsbG8=\n"))).toBe("hello");
  });
});
