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
  describeRedaction: vi.fn(),
  redactDocument: vi.fn(),
  isTauri: vi.fn(() => false),
  tauriInvoke: vi.fn(),
  // Real predicates, not stubs: the hook gates its describe call on the first
  // and picks which response field to read with the second, and a mock that
  // always said "yes" would hide a wrong gate rather than catch it.
  supportsDescribe: (f: string) =>
    f === "pdf-object" || f === "pdf-xref-stream" || f === "pdf-textrun",
  describesWords: (f: string) => f === "pdf-textrun",
  // Render stays narrower than describe on purpose: pdf.js can draw a
  // `pdf-textrun` document, but describe returns it no `placements`, so the
  // drag-box would hit-test against nothing.
  supportsRender: (f: string) => f === "pdf-object" || f === "pdf-xref-stream",
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => "test-key"),
}));
vi.mock("../lib/blake3", () => ({
  hashBytes: vi.fn(async () => "ab".repeat(32)),
}));
vi.mock("@tauri-apps/api/core", () => {
  class Channel<T> {
    onmessage: ((m: T) => void) | null = null;
  }
  return { invoke: vi.fn(), Channel };
});

import { invoke } from "@tauri-apps/api/core";
import {
  getRedactionManifest,
  describeRedaction,
  redactDocument,
  isTauri,
  tauriInvoke,
} from "../lib/api";
import type { RedactDocumentResponse, RedactionManifestResponse } from "../lib/api";
import { useRedactionCreate } from "./useRedactionCreate";

const mockedManifest = vi.mocked(getRedactionManifest);
const mockedDescribe = vi.mocked(describeRedaction);
const mockedRedact = vi.mocked(redactDocument);
const mockedInvoke = vi.mocked(invoke);
const mockedIsTauri = vi.mocked(isTauri);
const mockedTauriInvoke = vi.mocked(tauriInvoke);

const CONTENT_HASH = "ab".repeat(32);

function file(bytes: number, name = "doc.pdf") {
  const content = new Uint8Array(bytes).fill(65); // 'A'
  return new File([content], name, { type: "application/pdf" });
}

function manifest(
  ids: number[],
  format: RedactionManifestResponse["format"] = "pdf-object",
): RedactionManifestResponse {
  return {
    contentHash: CONTENT_HASH,
    format,
    originalRoot: "cd".repeat(32),
    objectCount: ids.length,
    objects: ids.map((segmentId) => ({ segmentId, byteLength: 100, label: null })),
  };
}

function bundleResponse(redactedObjIds: number[]): RedactDocumentResponse {
  const redacted = new Set(redactedObjIds);
  return {
    redactedBase64: "QUJD",
    bundle: {
      original_root: "cd".repeat(32),
      format: "pdf-object",
      segment_count: 3,
      recipient_id: "42",
      segments: [1, 2, 3].map((id) =>
        redacted.has(id)
          ? {
              segment_id: id,
              redacted: true,
              artifact_offset: 0,
              artifact_length: 0,
              leaf_hex: "ab".repeat(32),
            }
          : {
              segment_id: id,
              redacted: false,
              artifact_offset: 0,
              artifact_length: 10,
              blinding_decimal: "7",
            },
      ),
      nullifier: "ef".repeat(32),
      signature_hex: "00".repeat(64),
    },
  };
}

beforeEach(() => {
  mockedManifest.mockReset();
  mockedRedact.mockReset();
  mockedDescribe.mockReset();
  mockedManifest.mockResolvedValue(manifest([1, 2, 3]));
  // Default: describe enrichment returns no objects (A2). Individual tests
  // override to assert the enrichment / failure paths.
  mockedDescribe.mockResolvedValue({
    contentHash: CONTENT_HASH,
    format: "pdf-object",
    objectCount: 0,
    objects: [],
    segmentCount: 0,
    segments: [],
  });
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

  it("reads segments, not objects, for a pdf-textrun commitment (ADR-0029 B-3)", async () => {
    // The two id spaces are unrelated — an object id is a PDF indirect-object
    // number, a segment id a position in the committed word sequence — so the
    // hook must pick the field by FORMAT. Both arrays are populated here so a
    // "whichever is non-empty" implementation would pass on the wrong one.
    mockedManifest.mockResolvedValue(manifest([0, 1, 2], "pdf-textrun"));
    mockedDescribe.mockResolvedValue({
      contentHash: CONTENT_HASH,
      format: "pdf-textrun",
      objectCount: 1,
      objects: [
        {
          objId: 99,
          byteLength: 100,
          kind: "page",
          label: "must not be used",
          page: 1,
          preview: null,
          width: null,
          height: null,
          filter: null,
          baseFont: null,
          typeName: "Page",
          placements: [],
        },
      ],
      segmentCount: 2,
      segments: [
        {
          segmentId: 0,
          kind: "word",
          redactable: true,
          objId: 4,
          page: 1,
          text: "SECRET",
          byteLength: 6,
        },
        {
          segmentId: 1,
          kind: "skeleton",
          redactable: false,
          objId: 4,
          page: 1,
          text: null,
          byteLength: 40,
        },
      ],
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(result.current.segments).toHaveLength(2);
    expect(result.current.segments?.[0].text).toBe("SECRET");
    expect(result.current.descriptions).toBeNull();
  });

  it("enriches the checklist via /redaction/describe on the browser path (ADR-0029 A2)", async () => {
    mockedDescribe.mockResolvedValue({
      contentHash: CONTENT_HASH,
      format: "pdf-object",
      objectCount: 1,
      objects: [
        {
          objId: 1,
          byteLength: 100,
          kind: "page",
          label: "Page 1 (structure)",
          page: 1,
          preview: null,
          width: null,
          height: null,
          filter: null,
          baseFont: null,
          typeName: "Page",
          placements: [],
        },
      ],
      segmentCount: 0,
      segments: [],
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(mockedDescribe).toHaveBeenCalledWith(expect.any(String), CONTENT_HASH, "test-key", {
      originalRoot: "cd".repeat(32),
    });
    expect(result.current.descriptions).toHaveLength(1);
    expect(result.current.descriptions?.[0].label).toBe("Page 1 (structure)");
    expect(result.current.descriptions?.[0].page).toBe(1);
  });

  it("treats a describe failure as non-fatal — manifest loads, descriptions null", async () => {
    mockedDescribe.mockRejectedValue(new Error("describe boom"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(result.current.stage).toBe("idle");
    expect(result.current.manifest?.objectCount).toBe(3);
    expect(result.current.descriptions).toBeNull();
  });

  // Regression guard for the gate A.5-1 made stale: the endpoint describes both
  // PDF object schemes, but this call site still asked only for `pdf-object`,
  // so a modern PDF silently got no labels despite the backend supporting it.
  it("describes a modern xref-stream PDF, not just traditional-xref", async () => {
    mockedManifest.mockResolvedValue(manifest([1, 2, 3], "pdf-xref-stream"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(mockedDescribe).toHaveBeenCalled();
    expect(result.current.descriptions).not.toBeNull();
  });

  it("skips describe for a format the endpoint cannot classify", async () => {
    mockedManifest.mockResolvedValue(manifest([1, 2, 3], "text-line"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFile(file(320));
    });
    expect(mockedDescribe).not.toHaveBeenCalled();
    expect(result.current.descriptions).toBeNull();
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
      "cd".repeat(32),
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
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
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
    await act(async () => {
      await result.current.downloadBundle();
    });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(2);
    expect(clickSpy).toHaveBeenCalledTimes(2);
  });

  it("download helpers no-op before a result exists", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    URL.createObjectURL = vi.fn(() => "blob:x");
    act(() => result.current.downloadRedacted());
    await act(async () => {
      await result.current.downloadBundle();
    });
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

// ── Tauri (desktop) path ──────────────────────────────────────────────────────
// Path-based flow: Rust reads/hashes/saves the file; no bytes cross the JS
// boundary. Gated by isTauri() && state.filePath.

describe("useRedactionCreate Tauri path", () => {
  beforeEach(() => {
    mockedIsTauri.mockReturnValue(true);
    mockedManifest.mockReset();
    mockedManifest.mockResolvedValue(manifest([1, 2, 3]));
    mockedTauriInvoke.mockReset();
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      return undefined; // save_text_to_disk etc.
    });
    mockedInvoke.mockReset();
  });
  afterEach(() => {
    // restoreAllMocks does NOT reset mockReturnValue on factory vi.fns, so the
    // browser describe-block would leak isTauri()===true without this.
    mockedIsTauri.mockReturnValue(false);
  });

  it("onFilePath hashes via Rust and loads the committed object manifest", async () => {
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    expect(result.current.fileName).toBe("doc.pdf");
    expect(result.current.filePath).toBe("/abs/doc.pdf");
    expect(result.current.contentHash).toBe(CONTENT_HASH);
    expect(result.current.manifest?.objectCount).toBe(3);
    expect(mockedTauriInvoke).toHaveBeenCalledWith("hash_file_for_manifest", {
      path: "/abs/doc.pdf",
    });
    expect(mockedManifest).toHaveBeenCalledWith(CONTENT_HASH, "test-key");
    expect(result.current.stage).toBe("idle");
  });

  // ADR-0029 A.5-3. The desktop path never has the document bytes in JS, so the
  // producer checklist used to get no labels there at all; `describe_by_path`
  // does the read + encode + call natively.
  it("onFilePath enriches the checklist via describe_by_path", async () => {
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") {
        return {
          contentHash: CONTENT_HASH,
          format: "pdf-object",
          objectCount: 1,
          objects: [
            {
              objId: 1,
              byteLength: 100,
              kind: "image",
              label: "Image 800×600 (DCTDecode)",
              page: 1,
              preview: null,
              width: 800,
              height: 600,
              filter: "DCTDecode",
              baseFont: null,
              typeName: "XObject",
              placements: [{ page: 1, x: 50, y: 600, w: 200, h: 100 }],
            },
          ],
        };
      }
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    expect(mockedTauriInvoke).toHaveBeenCalledWith("describe_by_path", {
      path: "/abs/doc.pdf",
      originalRoot: "cd".repeat(32),
      shardId: null,
      apiKey: "test-key",
    });
    expect(result.current.descriptions?.[0].label).toBe("Image 800×600 (DCTDecode)");
    // A.5-2 geometry rides along, which is what a drag-box will hit-test.
    expect(result.current.descriptions?.[0].placements).toEqual([
      { page: 1, x: 50, y: 600, w: 200, h: 100 },
    ]);
    expect(result.current.stage).toBe("idle");
  });

  it("onFilePath treats a describe_by_path failure as non-fatal", async () => {
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") throw new Error("HTTP 422: unsupported");
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    // The manifest still loaded; the UI falls back to the plain id/size listing.
    expect(result.current.stage).toBe("idle");
    expect(result.current.manifest?.objectCount).toBe(3);
    expect(result.current.descriptions).toBeNull();
  });

  // ── ADR-0029 A.5-4 desktop read-for-render ────────────────────────────────
  // pdf.js runs in the webview, so the page render is the one thing on this
  // path that genuinely needs the bytes in JS. `read_file_for_render` supplies
  // them under its own display-only cap; everything about it is best-effort.

  /** A `describe_by_path` reply with one placed object — enough to draw a box over. */
  function describedObject() {
    return {
      contentHash: CONTENT_HASH,
      format: "pdf-object",
      objectCount: 1,
      objects: [
        {
          objId: 1,
          byteLength: 100,
          kind: "image",
          label: "Image 800×600 (DCTDecode)",
          page: 1,
          preview: null,
          width: 800,
          height: 600,
          filter: "DCTDecode",
          baseFont: null,
          typeName: "XObject",
          placements: [{ page: 1, x: 50, y: 600, w: 200, h: 100 }],
        },
      ],
    };
  }

  it("onFilePath fetches the bytes for render once there are descriptions", async () => {
    const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // "%PDF"
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") return describedObject();
      // The Rust command answers over binary IPC, so JS sees an ArrayBuffer.
      if (cmd === "read_file_for_render") return pdf.buffer;
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    expect(mockedTauriInvoke).toHaveBeenCalledWith("read_file_for_render", {
      path: "/abs/doc.pdf",
    });
    // This is the whole point of A.5-4 on the desktop path: `documentBytes` is
    // what gates the drag-box UI, and it used to be null here forever.
    expect(result.current.documentBytes).not.toBeNull();
    expect(Array.from(result.current.documentBytes!)).toEqual([0x25, 0x50, 0x44, 0x46]);
  });

  it("onFilePath treats a read_file_for_render failure as non-fatal", async () => {
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") return describedObject();
      if (cmd === "read_file_for_render") throw new Error("exceeds 67108864 byte cap");
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/huge.pdf", "huge.pdf");
    });
    // Over the render cap the box selection is gone, but the document still
    // loaded and the checklist still works — that is the intended degradation.
    expect(result.current.stage).toBe("idle");
    expect(result.current.documentBytes).toBeNull();
    expect(result.current.descriptions).toHaveLength(1);
  });

  it("onFilePath skips the render read when there is nothing to draw a box over", async () => {
    // No descriptions → no placements → a rendered page the operator could not
    // hit-test against. Not worth copying a multi-MB buffer into the webview.
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") throw new Error("HTTP 422: unsupported");
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    expect(mockedTauriInvoke).not.toHaveBeenCalledWith("read_file_for_render", expect.anything());
    expect(result.current.documentBytes).toBeNull();
  });

  it("onFilePath drops a previous buffer before loading the next document", async () => {
    const first = new Uint8Array([1, 2, 3]);
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") return describedObject();
      if (cmd === "read_file_for_render") return first.buffer;
      return undefined;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/a.pdf", "a.pdf");
    });
    expect(result.current.documentBytes).not.toBeNull();

    // Second document: describe fails, so no render read happens. The bytes
    // from the FIRST document must not survive into it — they would render the
    // wrong page under the new document's object ids.
    mockedTauriInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === "hash_file_for_manifest") return CONTENT_HASH;
      if (cmd === "describe_by_path") throw new Error("HTTP 422: unsupported");
      return undefined;
    });
    await act(async () => {
      await result.current.onFilePath("/abs/b.pdf", "b.pdf");
    });
    expect(result.current.documentBytes).toBeNull();
  });

  it("onFilePath skips describe for a format the endpoint cannot classify", async () => {
    mockedManifest.mockResolvedValue(manifest([1, 2, 3], "ooxml-part"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.docx", "doc.docx");
    });
    expect(result.current.stage).toBe("idle");
    expect(result.current.descriptions).toBeNull();
    expect(mockedTauriInvoke).not.toHaveBeenCalledWith("describe_by_path", expect.anything());
  });

  it("onFilePath surfaces a hash/manifest lookup failure", async () => {
    mockedManifest.mockRejectedValue(new Error("404: no manifest"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/no manifest/);
    expect(result.current.manifest).toBeNull();
  });

  it("redact() runs the path-based flow, streams progress, and finishes done", async () => {
    mockedInvoke.mockImplementation(async (cmd: string, args: unknown) => {
      if (cmd === "redact_by_path") {
        (
          args as { onProgress: { onmessage?: (m: { percent: number; label: string }) => void } }
        ).onProgress.onmessage?.({ percent: 50, label: "sending" });
        return { bundle: bundleResponse([2]).bundle, savedPath: "/out/doc_redacted.pdf" };
      }
      return null;
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    act(() => result.current.setRecipientId("42"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.progress).toBe(100);
    expect(result.current.savedRedactedPath).toBe("/out/doc_redacted.pdf");
    expect(result.current.result?.redactedBase64).toBe("");
    expect(
      result.current.result?.bundle.segments.filter((s) => s.redacted).map((s) => s.segment_id),
    ).toEqual([2]);
    expect(mockedInvoke).toHaveBeenCalledWith(
      "redact_by_path",
      expect.objectContaining({
        path: "/abs/doc.pdf",
        redactedObjIds: [2],
        recipientId: "42",
        apiKey: "test-key",
      }),
    );
    // Browser fallback must NOT be used on the Tauri path.
    expect(mockedRedact).not.toHaveBeenCalled();
  });

  it("redact() surfaces a Rust backend error", async () => {
    mockedInvoke.mockRejectedValue(new Error("backend boom"));
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    act(() => result.current.setRecipientId("42"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/boom/);
    expect(result.current.progress).toBeNull();
  });

  it("downloadBundle() saves via the native save_text_to_disk command", async () => {
    mockedInvoke.mockResolvedValue({
      bundle: bundleResponse([2]).bundle,
      savedPath: "/out/doc_redacted.pdf",
    });
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    act(() => result.current.setRecipientId("42"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    await act(async () => {
      await result.current.downloadBundle();
    });
    expect(mockedTauriInvoke).toHaveBeenCalledWith(
      "save_text_to_disk",
      expect.objectContaining({
        filenameHint: expect.stringContaining(".redaction.json"),
      }),
    );
  });

  it("downloadRedacted() is a no-op on the Tauri path (already saved to disk)", async () => {
    mockedInvoke.mockResolvedValue({
      bundle: bundleResponse([2]).bundle,
      savedPath: "/out/doc_redacted.pdf",
    });
    URL.createObjectURL = vi.fn(() => "blob:x");
    const { result } = renderHook(() => useRedactionCreate());
    await act(async () => {
      await result.current.onFilePath("/abs/doc.pdf", "doc.pdf");
    });
    act(() => result.current.setRecipientId("42"));
    act(() => result.current.toggleId(2));
    await act(async () => {
      await result.current.redact();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    act(() => result.current.downloadRedacted());
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
