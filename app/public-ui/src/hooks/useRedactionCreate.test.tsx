/**
 * Tests for useRedactionCreate — the redaction producer hook.
 *
 * `computeRevealMask` is pinned to the Rust reference
 * (`crate::zk::redact::redact_chunk_aligned`'s mask): the cases below mirror the
 * `redact.rs` unit tests (320-byte sample ⇒ chunk_size 20; short 5-byte input ⇒
 * chunk_size 1). If the chunk geometry ever changes on either side, these break.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  redactDocument: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => "test-key"),
}));
vi.mock("../lib/redactionBinding", () => ({
  verifyRedactionBindingJs: vi.fn(),
}));

import { redactDocument } from "../lib/api";
import { verifyRedactionBindingJs } from "../lib/redactionBinding";
import {
  useRedactionCreate,
  computeRevealMask,
  computeChunkStatus,
  populatedChunks,
  MAX_LEAVES,
} from "./useRedactionCreate";

const mockedRedact = vi.mocked(redactDocument);
const mockedVerifyBinding = vi.mocked(verifyRedactionBindingJs);

function file(bytes: number, name = "doc.txt") {
  const content = new Uint8Array(bytes).fill(65); // 'A'
  return new File([content], name, { type: "text/plain" });
}

beforeEach(() => {
  mockedRedact.mockReset();
  mockedVerifyBinding.mockReset();
  mockedVerifyBinding.mockResolvedValue(true);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("computeRevealMask", () => {
  it("hides only the overlapping chunk (320B ⇒ chunk_size 20)", () => {
    // [40,55) overlaps chunk 2 ([40,60)) only.
    const mask = computeRevealMask(320, [{ start: 40, end: 55 }]);
    const expected = Array(MAX_LEAVES).fill(1);
    expected[2] = 0;
    expect(mask).toEqual(expected);
  });

  it("hides both chunks a range straddles", () => {
    // [55,65) straddles chunk 2 ([40,60)) and chunk 3 ([60,80)).
    const mask = computeRevealMask(320, [{ start: 55, end: 65 }]);
    expect(mask[2]).toBe(0);
    expect(mask[3]).toBe(0);
    expect(mask.filter((m) => m === 0)).toHaveLength(2);
  });

  it("handles multiple ranges at the extremes", () => {
    const mask = computeRevealMask(320, [
      { start: 0, end: 5 },
      { start: 300, end: 320 },
    ]);
    expect(mask[0]).toBe(0);
    expect(mask[15]).toBe(0);
    expect(mask.filter((m) => m === 0)).toHaveLength(2);
  });

  it("uses 1-byte chunks for short input (n=5)", () => {
    const mask = computeRevealMask(5, [{ start: 2, end: 3 }]);
    expect(mask[2]).toBe(0);
    expect(mask.filter((m) => m === 0)).toHaveLength(1);
    expect(populatedChunks(5)).toBe(5);
  });

  it("treats an empty file as all-revealed padding", () => {
    expect(computeRevealMask(0, [{ start: 0, end: 1 }])).toEqual(Array(MAX_LEAVES).fill(1));
    expect(populatedChunks(0)).toBe(0);
  });
});

describe("computeChunkStatus", () => {
  it("marks an untouched chunk revealed", () => {
    const st = computeChunkStatus(320, [{ start: 40, end: 55 }]);
    expect(st[0]).toBe("revealed");
    expect(st[3]).toBe("revealed");
  });

  it("marks a chunk full only when its whole span is covered (cs=20)", () => {
    // [40,60) is exactly chunk 2 → full; [40,55) leaves [55,60) → partial.
    expect(computeChunkStatus(320, [{ start: 40, end: 60 }])[2]).toBe("full");
    expect(computeChunkStatus(320, [{ start: 40, end: 55 }])[2]).toBe("partial");
  });

  it("treats a partially-overlapped boundary chunk as partial", () => {
    // [55,65): chunk 2 ([40,60)) keeps [40,55); chunk 3 ([60,80)) keeps [65,80).
    const st = computeChunkStatus(320, [{ start: 55, end: 65 }]);
    expect(st[2]).toBe("partial");
    expect(st[3]).toBe("partial");
  });

  it("treats adjacent ranges that jointly cover a chunk as full", () => {
    // [40,50)+[50,60) together cover chunk 2 with no gap → full.
    const st = computeChunkStatus(320, [
      { start: 40, end: 50 },
      { start: 50, end: 60 },
    ]);
    expect(st[2]).toBe("full");
  });
});

describe("useRedactionCreate flow", () => {
  it("starts idle and empty", () => {
    const { result } = renderHook(() => useRedactionCreate());
    expect(result.current.stage).toBe("idle");
    expect(result.current.fileName).toBeNull();
    expect(result.current.ranges).toEqual([]);
  });

  it("loads a text file and decodes the preview", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(result.current.fileName).toBe("doc.txt");
    expect(result.current.fileSize).toBe(320);
    expect(result.current.fileText).toBe("A".repeat(320));
  });

  it("validates ranges against file bounds", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(100));
    });
    act(() => result.current.addRange(50, 40)); // inverted
    expect(result.current.error).toMatch(/empty/);
    expect(result.current.ranges).toHaveLength(0);

    act(() => result.current.addRange(90, 120)); // out of bounds
    expect(result.current.error).toMatch(/out of bounds/);

    act(() => result.current.addRange(10, 20)); // valid
    expect(result.current.ranges).toEqual([{ start: 10, end: 20 }]);
    expect(result.current.error).toBeNull();
  });

  it("dedupes identical ranges and keeps them sorted", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.addRange(100, 110));
    act(() => result.current.addRange(10, 20));
    act(() => result.current.addRange(100, 110)); // dup
    expect(result.current.ranges).toEqual([
      { start: 10, end: 20 },
      { start: 100, end: 110 },
    ]);
  });

  it("refuses to submit with no ranges / no recipient", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/at least one byte range/);
    expect(mockedRedact).not.toHaveBeenCalled();

    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.error).toMatch(/Recipient ID is required/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("rejects an all-redacted submission before hitting the server", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("123"));
    act(() => result.current.addRange(0, 320)); // every chunk
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/nothing would be revealed/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("submits valid inputs and stores the result", async () => {
    mockedRedact.mockResolvedValue({
      redactedBase64: "QUJD",
      bundle: {
        circuit: "redaction_validity",
        contentHash: "ab".repeat(32),
        originalRoot: "cd".repeat(32),
        proofJson: {},
        publicSignals: ["1", "2", "3", "4", "5", "6"],
        revealMask: [0, ...Array(15).fill(1)],
        revealedChunkHashes: [],
        signatureHex: "ff",
      },
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("  42  "));
    act(() => result.current.setFill("88"));
    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(mockedRedact).toHaveBeenCalledWith(
      expect.any(String),
      [{ start: 40, end: 55 }],
      "42", // trimmed
      88, // fill parsed to number
      "test-key",
    );
    expect(result.current.result?.redactedBase64).toBe("QUJD");
    // verify-before-send ran and surfaced its result.
    expect(mockedVerifyBinding).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      [0, ...Array(15).fill(1)],
      "3", // publicSignals[2] = redactedCommitment
    );
    expect(result.current.bindingValid).toBe(true);
  });

  it("reports bindingValid=false when the artifact does not bind", async () => {
    mockedVerifyBinding.mockResolvedValue(false);
    mockedRedact.mockResolvedValue({
      redactedBase64: "QUJD",
      bundle: {
        circuit: "redaction_validity",
        contentHash: "ab".repeat(32),
        originalRoot: "cd".repeat(32),
        proofJson: {},
        publicSignals: ["1", "2", "3", "4", "5", "6"],
        revealMask: [0, ...Array(15).fill(1)],
        revealedChunkHashes: [],
        signatureHex: "ff",
      },
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.bindingValid).toBe(false);
  });

  it("allows redacting only the last partial chunk (not all-redacted)", async () => {
    // n=33 ⇒ chunk_size 3, 11 populated chunks; redacting [30,33) hides only
    // chunk 10. This must NOT trip the all-redacted guard.
    mockedRedact.mockResolvedValue({
      redactedBase64: "QUJD",
      bundle: {
        circuit: "redaction_validity",
        contentHash: "ab".repeat(32),
        originalRoot: "cd".repeat(32),
        proofJson: {},
        publicSignals: ["1", "2", "3", "4", "5", "6"],
        revealMask: [...Array(10).fill(1), 0, ...Array(5).fill(1)],
        revealedChunkHashes: [],
        signatureHex: "ff",
      },
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(33));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.addRange(30, 33));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(mockedRedact).toHaveBeenCalled();
  });

  it("rejects an out-of-range fill byte", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.setFill("300"));
    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/0–255/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("surfaces a server error", async () => {
    mockedRedact.mockRejectedValue(new Error("403: not on ledger"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/not on ledger/);
  });

  it("refuses to redact with no file loaded", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/Load an original document first/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("removes and clears ranges, resetting a done result", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.addRange(0, 5));
    act(() => result.current.addRange(40, 55));
    act(() => result.current.removeRange(0));
    expect(result.current.ranges).toEqual([{ start: 40, end: 55 }]);
    act(() => result.current.clearRanges());
    expect(result.current.ranges).toEqual([]);
  });

  it("downloads the redacted file and the bundle JSON", async () => {
    URL.createObjectURL = vi.fn(() => "blob:redaction");
    URL.revokeObjectURL = vi.fn();
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    mockedRedact.mockResolvedValue({
      redactedBase64: "QUJD",
      bundle: {
        circuit: "redaction_validity",
        contentHash: "ab".repeat(32),
        originalRoot: "cd".repeat(32),
        proofJson: {},
        publicSignals: ["1", "2", "3", "4", "5", "6"],
        revealMask: [0, ...Array(15).fill(1)],
        revealedChunkHashes: [],
        signatureHex: "ff",
      },
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.addRange(40, 55));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    act(() => result.current.downloadRedacted());
    act(() => result.current.downloadBundle());
    expect(URL.createObjectURL).toHaveBeenCalledTimes(2);
    expect(clickSpy).toHaveBeenCalledTimes(2);
  });

  it("download helpers no-op before a result exists", () => {
    const { result } = renderHook(() => useRedactionCreate());
    URL.createObjectURL = vi.fn(() => "blob:x");
    act(() => result.current.downloadRedacted());
    act(() => result.current.downloadBundle());
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it("preserves recipient + fill across a file swap", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(100));
    });
    act(() => result.current.setRecipientId("999"));
    act(() => result.current.setFill("7"));
    act(() => result.current.addRange(10, 20));
    await act(async () => {
      await result.current.onFile(file(200, "other.txt"));
    });
    expect(result.current.fileName).toBe("other.txt");
    expect(result.current.recipientId).toBe("999");
    expect(result.current.fill).toBe("7");
    expect(result.current.ranges).toEqual([]); // ranges are per-file
  });
});
