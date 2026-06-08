/**
 * Tests for selectionToByteOffset — the text-selection → byte-offset mapping
 * that feeds redaction ranges. The multi-byte and CRLF cases are the ones that
 * would silently corrupt ranges if the mapping used character indices.
 */
import { describe, expect, it } from "vitest";
import { selectionToByteOffset } from "./selectionBytes";

describe("selectionToByteOffset", () => {
  it("is identity for ASCII", () => {
    expect(selectionToByteOffset("hello world", 0)).toBe(0);
    expect(selectionToByteOffset("hello world", 6)).toBe(6);
    expect(selectionToByteOffset("hello world", 11)).toBe(11);
  });

  it("counts bytes, not characters, past a multi-byte char", () => {
    // "a—b": '—' (U+2014 em dash) is 3 UTF-8 bytes, 1 UTF-16 unit.
    const text = "a—b";
    expect(selectionToByteOffset(text, 1)).toBe(1); // after 'a'
    expect(selectionToByteOffset(text, 2)).toBe(4); // after 'a—' = 1 + 3 bytes
    expect(selectionToByteOffset(text, 3)).toBe(5); // after 'a—b'
  });

  it("accounts for CR bytes hidden by textarea CRLF normalization", () => {
    // Original bytes: a(0) b(1) \r(2) \n(3) c(4) d(5).
    // The textarea normalizes to "ab\ncd", so selecting 'c' gives normIndex 3.
    const text = "ab\r\ncd";
    expect(selectionToByteOffset(text, 3)).toBe(4); // 'c' is at byte 4, not 3
    expect(selectionToByteOffset(text, 5)).toBe(6); // end of "cd"
  });

  it("handles a lone CR (also normalized to one char)", () => {
    // "a\rb" → textarea value "a\nb"; normIndex 2 is 'b' at byte 2.
    expect(selectionToByteOffset("a\rb", 2)).toBe(2);
  });

  it("clamps non-positive indices to 0", () => {
    expect(selectionToByteOffset("anything", -3)).toBe(0);
  });
});
