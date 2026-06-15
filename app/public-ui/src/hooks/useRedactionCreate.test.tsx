/**
 * Tests for useRedactionCreate — the object-level redaction producer hook (ADR-0026).
 *
 * The hook loads a committed PDF, BLAKE3-hashes its bytes to look up the
 * committed object manifest (`GET /redaction/manifest/{hash}`), lets the
 * operator check objects to hide, and calls `POST /redaction/redact` with the
 * selected object ids.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getRedactionManifest: vi.fn(),
  redactDocument: vi.fn(),
  isTauri: vi.fn(() => false),
  tauriInvoke: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => "test-key"),
}));
vi.mock("../lib/blake3", () => ({
  hashBytes: vi.fn(async () => "ab".repeat(32)),
}));

import { getRedactionManifest, redactDocument } from "../lib/api";
import type { RedactDocumentResponse, RedactionManifestResponse } from "../lib/api";
import { useRedactionCreate } from "./useRedactionCreate";

const mockedManifest = vi.mocked(getRedactionManifest);
const mockedRedact = vi.mocked(redactDocument);

const CONTENT_HASH = "ab".repeat(32);

function file(bytes: number, name = "doc.pdf") {
  const content = new Uint8Array(bytes).fill(65); // 'A'
  return new File([content], name, { type: "application/pdf" });
}

function manifest(ids: number[]): RedactionManifestResponse {
  return {
    contentHash: CONTENT_HASH,
    format: "pdf-object",
    originalRoot: "cd".repeat(32),
    objectCount: ids.length,
    objects: ids.map((segmentId) => ({ segmentId, byteLength: 100, label: null })),
  };
}

function bundleResponse(redactedObjIds: number[]): RedactDocumentResponse {
  return {
    redactedBase64: "QUJD",
    bundle: {
      circuit: "redaction_validity",
      contentHash: CONTENT_HASH,
      originalRoot: "cd".repeat(32),
      proofJson: {},
      publicSignals: ["1", "2", "3", "4", "5", "6"],
      redactedObjIds,
      revealedSegments: [],
      signatureHex: "ff",
    },
  };
}

beforeEach(() => {
  mockedManifest.mockReset();
  mockedRedact.mockReset();
  mockedManifest.mockResolvedValue(manifest([1, 2, 3]));
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe("useRedactionCreate flow", () => {
  it("starts idle and empty", () => {
    const { result } = renderHook(() => useRedactionCreate());
    expect(result.current.stage).toBe("idle");
    expect(result.current.fileName).toBeNull();
    expect(result.current.manifest).toBeNull();
    expect(result.current.selectedIds).toEqual([]);
  });

  it("loads a file, hashes it, and fetches the object manifest", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(result.current.fileName).toBe("doc.pdf");
    expect(result.current.fileSize).toBe(320);
    expect(result.current.contentHash).toBe(CONTENT_HASH);
    expect(result.current.manifest?.objectCount).toBe(3);
    expect(mockedManifest).toHaveBeenCalledWith(CONTENT_HASH, "test-key");
    expect(result.current.stage).toBe("idle");
  });

  it("surfaces a manifest lookup failure (not on-ledger / non-PDF)", async () => {
    mockedManifest.mockRejectedValue(new Error("404: no manifest"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/no manifest/);
    expect(result.current.manifest).toBeNull();
  });

  it("toggles object ids in and out of the redacted set, kept sorted", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.toggleId(3));
    act(() => result.current.toggleId(1));
    expect(result.current.selectedIds).toEqual([1, 3]);
    act(() => result.current.toggleId(3)); // remove
    expect(result.current.selectedIds).toEqual([1]);
    act(() => result.current.clearSelection());
    expect(result.current.selectedIds).toEqual([]);
  });

  it("refuses to submit with no selection / no recipient", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/at least one object/);
    expect(mockedRedact).not.toHaveBeenCalled();

    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.error).toMatch(/Recipient ID is required/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("rejects hiding every object before hitting the server", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.toggleId(1));
    act(() => result.current.toggleId(2));
    act(() => result.current.toggleId(3)); // all 3 of 3
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/nothing would be revealed/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("submits the selected object ids and stores the result", async () => {
    mockedRedact.mockResolvedValue(bundleResponse([2]));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("  42  "));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(mockedRedact).toHaveBeenCalledWith(
      expect.any(String), // base64
      [2],
      "42", // trimmed
      "test-key",
    );
    expect(result.current.result?.redactedBase64).toBe("QUJD");
  });

  it("surfaces a server error", async () => {
    mockedRedact.mockRejectedValue(new Error("403: not on ledger"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/not on ledger/);
  });

  it("refuses to redact with no file/manifest loaded", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/Load an original document/);
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("discards a redact response after reset() supersedes it", async () => {
    let resolveRedact!: (v: RedactDocumentResponse) => void;
    mockedRedact.mockReturnValue(
      new Promise<RedactDocumentResponse>((res) => {
        resolveRedact = res;
      }),
    );
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.toggleId(2));

    let redactPromise!: Promise<void>;
    act(() => {
      redactPromise = result.current.redact();
    });
    expect(result.current.stage).toBe("redacting");

    // User resets while the request is still in flight.
    act(() => result.current.reset());
    expect(result.current.stage).toBe("idle");

    // The stale response now resolves — it must NOT revive the old session.
    await act(async () => {
      resolveRedact(bundleResponse([2]));
      await redactPromise;
    });
    expect(result.current.stage).toBe("idle");
    expect(result.current.result).toBeNull();
  });

  it("downloads the redacted file and the bundle JSON", async () => {
    URL.createObjectURL = vi.fn(() => "blob:redaction");
    URL.revokeObjectURL = vi.fn();
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    mockedRedact.mockResolvedValue(bundleResponse([2]));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    act(() => result.current.setRecipientId("1"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    act(() => result.current.downloadRedacted());
    await act(async () => { await result.current.downloadBundle(); });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(2);
    expect(clickSpy).toHaveBeenCalledTimes(2);
  });

  it("download helpers no-op before a result exists", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    URL.createObjectURL = vi.fn(() => "blob:x");
    act(() => result.current.downloadRedacted());
    await act(async () => { await result.current.downloadBundle(); });
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it("preserves the recipient across a file swap and resets the selection", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(100));
    });
    act(() => result.current.setRecipientId("999"));
    act(() => result.current.toggleId(1));
    await act(async () => {
      await result.current.onFile(file(200, "other.pdf"));
    });
    expect(result.current.fileName).toBe("other.pdf");
    expect(result.current.recipientId).toBe("999");
    expect(result.current.selectedIds).toEqual([]); // selection is per-file
  });
});
