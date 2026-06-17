/**
 * Smoke + interaction tests for <RedactTab> (the object-level redaction
 * producer UI, ADR-0026).
 *
 * The tab is a thin view over `useRedactionCreate`; these tests drive it with a
 * hand-built hook stub and assert the view wires user actions to the right hook
 * callbacks and renders each state (empty / loading manifest / object checklist
 * / done / error).
 *
 * Two execution paths share this component:
 *
 *   • Browser fallback — `isTauri()` is false (the default mock). The drop zone
 *     forwards bytes via `hook.onFile`, the picker clicks a hidden <input>, and
 *     redact progress is indeterminate.
 *   • Tauri (desktop) — `isTauri()` returns true. A native `file-dropped` event
 *     listener registers on mount, the picker calls the `pick_file_path` IPC
 *     command, the browser <input>/onDrop paths become no-ops, and redact
 *     progress is a determinate percent bar fed from Rust.
 *
 * The Tauri branches are the ones a real desktop user hits but jsdom cannot
 * exercise without mocking `isTauri`, `tauriInvoke`, and the `@tauri-apps/api/
 * event` `listen` import — which is what this file covers.
 */
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `../lib/api` is mocked so we can flip `isTauri()` per test and observe the
// `tauriInvoke` calls the Tauri code paths make. The component only imports
// `isTauri` + `tauriInvoke` from this module; the type-only imports below are
// erased at compile time and do not need to appear in the factory.
vi.mock("../lib/api", () => ({
  isTauri: vi.fn(() => false),
  tauriInvoke: vi.fn(),
}));

// The native drag-drop listener is registered via a dynamic
// `import("@tauri-apps/api/event")` inside RedactTab's mount effect. Each test
// that needs it sets `mockedListen`'s implementation to capture the callback.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

import RedactTab from "./RedactTab";
import { renderWithSkin } from "../__tests__/render";
import { isTauri, tauriInvoke } from "../lib/api";
import { listen } from "@tauri-apps/api/event";
import type { useRedactionCreate } from "../hooks/useRedactionCreate";
import type { RedactionManifestResponse, RedactDocumentResponse } from "../lib/api";

type Hook = ReturnType<typeof useRedactionCreate>;

const mockedIsTauri = vi.mocked(isTauri);
const mockedTauriInvoke = vi.mocked(tauriInvoke);
const mockedListen = vi.mocked(listen);

const CONTENT_HASH = "ab".repeat(32);

function manifest(ids: number[]): RedactionManifestResponse {
  return {
    contentHash: CONTENT_HASH,
    format: "pdf-object",
    originalRoot: "cd".repeat(32),
    objectCount: ids.length,
    objects: ids.map((segmentId) => ({ segmentId, byteLength: 100, label: null })),
  };
}

function doneResult(redactedObjIds: number[]): RedactDocumentResponse {
  const redacted = new Set(redactedObjIds);
  return {
    redactedBase64: "QUJD",
    bundle: {
      original_root: "cd".repeat(32),
      format: "pdf-object",
      segment_count: 3,
      recipient_id: "1",
      segments: [1, 2, 3].map((id) =>
        redacted.has(id)
          ? { segment_id: id, redacted: true, artifact_offset: 0, artifact_length: 0, leaf_hex: "ab".repeat(32) }
          : { segment_id: id, redacted: false, artifact_offset: 0, artifact_length: 10, blinding_decimal: "12345" },
      ),
      nullifier: "ef".repeat(32),
      signature_hex: "00".repeat(64),
    },
  };
}

/** Full hand-built stub of `useRedactionCreate`'s return value: every state
 *  field RedactTab reads plus every callback it may invoke. */
function makeHook(overrides: Partial<Hook> = {}): Hook {
  return {
    // ── State ──
    stage: "idle",
    fileName: null,
    fileSize: 0,
    contentHash: null,
    manifest: null,
    descriptions: null,
    selectedIds: [],
    recipientId: "",
    result: null,
    error: null,
    progress: null,
    savedRedactedPath: null,
    filePath: null,
    // ── Callbacks ──
    onFile: vi.fn(),
    onFilePath: vi.fn(),
    toggleId: vi.fn(),
    clearSelection: vi.fn(),
    setRecipientId: vi.fn(),
    redact: vi.fn(),
    downloadRedacted: vi.fn(),
    downloadBundle: vi.fn(),
    reset: vi.fn(),
    ...overrides,
  } as Hook;
}

function setup(overrides: Partial<Hook> = {}) {
  const hook = makeHook(overrides);
  return { hook, ...renderWithSkin(<RedactTab hook={hook} />) };
}

/** The picker button is the first <button> inside the drop region. */
function pickerButton(region: HTMLElement): HTMLButtonElement {
  const btn = region.querySelector("button");
  if (!btn) throw new Error("picker button not found inside drop region");
  return btn as HTMLButtonElement;
}

function getDropRegion(): HTMLElement {
  return screen.getByRole("region", { name: /Drop the original document/i });
}

beforeEach(() => {
  mockedIsTauri.mockReset();
  mockedIsTauri.mockReturnValue(false); // browser by default
  mockedTauriInvoke.mockReset();
  mockedListen.mockReset();
  mockedListen.mockImplementation(async () => () => {});
});

afterEach(() => {
  vi.clearAllMocks();
});

// ── Browser-path rendering + wiring ──────────────────────────────────────────

describe("<RedactTab> (browser path)", () => {
  it("renders the original-PDF drop zone when empty", () => {
    setup();
    expect(getDropRegion()).toBeInTheDocument();
    expect(screen.getByText(/ORIGINAL_PDF/)).toBeInTheDocument();
  });

  it("shows a loading affordance while the manifest is fetched", () => {
    setup({ stage: "loading_manifest", fileName: "doc.pdf", fileSize: 320 });
    expect(screen.getByText(/Loading object manifest/i)).toBeInTheDocument();
  });

  it("renders the object checklist with size info and wires toggle", () => {
    const hook = makeHook({
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
    });
    renderWithSkin(<RedactTab hook={hook} />);
    expect(screen.getByText("#1")).toBeInTheDocument();
    expect(screen.getByText("#3")).toBeInTheDocument();
    expect(screen.getByText(/0\/3 hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Hide object 2"));
    expect(hook.toggleId).toHaveBeenCalledWith(2);
  });

  it("reflects the selected (hidden) count and wires clear all", () => {
    const hook = makeHook({
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
    });
    renderWithSkin(<RedactTab hook={hook} />);
    expect(screen.getByText(/1\/3 hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("clear all"));
    expect(hook.clearSelection).toHaveBeenCalled();
  });

  it("renders the ADR-0029 A2 page-grouped, labelled checklist when descriptions are present", () => {
    const { hook } = setup({
      manifest: manifest([1, 2, 3]),
      descriptions: [
        { objId: 1, byteLength: 100, kind: "page", label: "Page 1 (structure)", page: 1, preview: null, width: null, height: null, filter: null, baseFont: null, typeName: "Page" },
        { objId: 2, byteLength: 100, kind: "content_stream", label: "Page 1 — text", page: 1, preview: "Hello SECRET name", width: null, height: null, filter: null, baseFont: null, typeName: null },
        { objId: 3, byteLength: 100, kind: "font", label: "Font: Helvetica", page: null, preview: null, width: null, height: null, filter: null, baseFont: "Helvetica", typeName: null },
      ],
    });
    // Page-group + document-level headers.
    expect(screen.getByText("PAGE 1")).toBeInTheDocument();
    expect(screen.getByText("DOCUMENT-LEVEL")).toBeInTheDocument();
    // Human labels replace the bare id/size listing.
    expect(screen.getByText("Page 1 — text")).toBeInTheDocument();
    expect(screen.getByText("Font: Helvetica")).toBeInTheDocument();
    // Content-stream preview surfaced.
    expect(screen.getByText(/Hello SECRET name/)).toBeInTheDocument();
    // Checkboxes still wired by segment id.
    fireEvent.click(screen.getByLabelText("Hide object 2"));
    expect(hook.toggleId).toHaveBeenCalledWith(2);
  });

  it("disables REDACT until a manifest is loaded and an object is selected", () => {
    const { rerender } = setup({
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [],
    });
    expect(screen.getByText("REDACT_DOCUMENT")).toBeDisabled();
    rerender(
      <RedactTab
        hook={makeHook({
          fileName: "doc.pdf",
          fileSize: 320,
          contentHash: CONTENT_HASH,
          manifest: manifest([1, 2, 3]),
          selectedIds: [2],
          recipientId: "1",
        })}
      />,
    );
    expect(screen.getByText("REDACT_DOCUMENT")).not.toBeDisabled();
  });

  it("wires the recipient input", () => {
    const hook = makeHook({
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.change(screen.getByLabelText("Recipient ID"), { target: { value: "42" } });
    expect(hook.setRecipientId).toHaveBeenCalledWith("42");
  });

  it("renders download buttons and revealed segments on success (browser)", () => {
    const hook = makeHook({
      stage: "done",
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
      result: doneResult([2]),
    });
    renderWithSkin(<RedactTab hook={hook} />);
    expect(screen.getByText(/REVEALED_SEGMENTS/)).toBeInTheDocument();
    // Browser path shows the in-memory download button…
    fireEvent.click(screen.getByText("DOWNLOAD_REDACTED_FILE"));
    expect(hook.downloadRedacted).toHaveBeenCalled();
    // …and labels the bundle button DOWNLOAD (not SAVE).
    fireEvent.click(screen.getByText("DOWNLOAD_BUNDLE.json"));
    expect(hook.downloadBundle).toHaveBeenCalled();
  });

  it("surfaces an error message", () => {
    setup({ fileName: "doc.pdf", fileSize: 10, error: "boom" });
    expect(screen.getByText("boom")).toBeInTheDocument();
  });

  it("loads a file via the hidden file input", () => {
    const hook = makeHook();
    const { container } = renderWithSkin(<RedactTab hook={hook} />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    expect(input).not.toBeNull();
    const f = new File(["data"], "in.pdf", { type: "application/pdf" });
    fireEvent.change(input, { target: { files: [f] } });
    expect(hook.onFile).toHaveBeenCalledWith(f);
  });

  it("fires redact from the action button", () => {
    const hook = makeHook({
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("REDACT_DOCUMENT"));
    expect(hook.redact).toHaveBeenCalled();
  });

  it("shows the busy label and disables actions while redacting", () => {
    setup({
      stage: "redacting",
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
    });
    expect(screen.getByText("REDACTING...")).toBeDisabled();
    expect(screen.getByText("RESET")).toBeDisabled();
  });

  it("fires reset from the action button when a file is loaded", () => {
    const hook = makeHook({
      stage: "done",
      fileName: "doc.pdf",
      fileSize: 10,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
      result: doneResult([2]),
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("RESET"));
    expect(hook.reset).toHaveBeenCalled();
  });

  // Branch 3: picker click in the browser routes to the hidden <input>, NOT to
  // any Tauri IPC. jsdom won't open a file chooser from a synthetic
  // input.click(), so we just assert no Tauri path was taken and onFilePath was
  // never called.
  it("picker click in the browser does not invoke Tauri IPC or onFilePath", () => {
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(pickerButton(getDropRegion()));
    expect(mockedTauriInvoke).not.toHaveBeenCalled();
    expect(hook.onFilePath).not.toHaveBeenCalled();
  });

  // Branch 5: onDrop in the browser forwards the dropped File to hook.onFile.
  it("drop on the region forwards the file to hook.onFile (browser)", () => {
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);
    const region = getDropRegion();
    const f = new File(["data"], "drop.pdf", { type: "application/pdf" });
    fireEvent.dragOver(region);
    fireEvent.dragLeave(region);
    fireEvent.drop(region, { dataTransfer: { files: [f] } });
    expect(hook.onFile).toHaveBeenCalledWith(f);
  });

  // Branch 6b: indeterminate "Redacting…" text shows when progress is null.
  it("renders the indeterminate Redacting text when progress is null", () => {
    setup({
      stage: "redacting",
      progress: null,
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
    });
    // The indeterminate paragraph reads "Redacting…" (ellipsis). The button
    // label is the upper-case "REDACTING..."; match the paragraph specifically.
    expect(screen.getByText(/^Redacting…$/)).toBeInTheDocument();
  });
});

// ── Tauri (desktop) path ──────────────────────────────────────────────────────
// These cover the branches a real desktop user hits: native drag-drop event,
// path-based picker IPC, browser-handler no-ops, and the determinate progress
// bar. Each test opts into Tauri mode via mockedIsTauri.mockReturnValue(true).

describe("<RedactTab> (Tauri path)", () => {
  beforeEach(() => {
    mockedIsTauri.mockReturnValue(true);
  });

  // Branch 1: the native `file-dropped` listener registers on mount, and its
  // callback forwards the dropped path/name to hook.onFilePath.
  it("registers the file-dropped listener on mount and forwards path+name", async () => {
    let captured:
      | ((event: { payload: { path: string; name: string } }) => void)
      | undefined;
    mockedListen.mockImplementation(async (_event, cb) => {
      captured = cb as typeof captured;
      return () => {};
    });

    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);

    await waitFor(() =>
      expect(mockedListen).toHaveBeenCalledWith("file-dropped", expect.any(Function)),
    );
    expect(captured).toBeTypeOf("function");

    // Simulate the OS dropping a file onto the window.
    captured!({ payload: { path: "/p.pdf", name: "p.pdf" } });
    expect(hook.onFilePath).toHaveBeenCalledWith("/p.pdf", "p.pdf");
  });

  // Branch 2: clicking the picker in Tauri calls `pick_file_path` and forwards
  // the returned {path,name} to hook.onFilePath.
  it("picker click calls pick_file_path then forwards to onFilePath", async () => {
    mockedTauriInvoke.mockResolvedValue({ name: "x.pdf", path: "/x.pdf" });
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);

    fireEvent.click(pickerButton(getDropRegion()));

    await waitFor(() =>
      expect(mockedTauriInvoke).toHaveBeenCalledWith("pick_file_path", {}),
    );
    await waitFor(() =>
      expect(hook.onFilePath).toHaveBeenCalledWith("/x.pdf", "x.pdf"),
    );
    // Browser <input> path must not be involved.
    expect(hook.onFile).not.toHaveBeenCalled();
  });

  // Branch 2b: a cancelled picker (null result) forwards nothing.
  it("picker click with a cancelled (null) result does not call onFilePath", async () => {
    mockedTauriInvoke.mockResolvedValue(null);
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);

    fireEvent.click(pickerButton(getDropRegion()));

    await waitFor(() =>
      expect(mockedTauriInvoke).toHaveBeenCalledWith("pick_file_path", {}),
    );
    expect(hook.onFilePath).not.toHaveBeenCalled();
  });

  // Branch 4: onDrop is a no-op in Tauri — the native file-dropped event owns
  // drag-drop, so the React onDrop handler must NOT call hook.onFile.
  it("drop on the region is a no-op (native event handles it)", () => {
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);
    const region = getDropRegion();
    const f = new File(["data"], "drop.pdf", { type: "application/pdf" });
    fireEvent.drop(region, { dataTransfer: { files: [f] } });
    expect(hook.onFile).not.toHaveBeenCalled();
  });

  // Branch 6a: determinate progress bar renders an inner element scaled to the
  // current percent.
  it("renders a determinate progress bar at the current percent", () => {
    const { container } = setup({
      stage: "redacting",
      progress: 42,
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
      filePath: "/abs/doc.pdf",
    });
    // The percent is shown in the header…
    expect(screen.getByText("42%")).toBeInTheDocument();
    // …and the fill bar's inline width is "42%".
    const fill = container.querySelector('[style*="42%"]');
    expect(fill).not.toBeNull();
  });

  // The done panel hides the in-memory download button (file is already on
  // disk) and labels the bundle button SAVE rather than DOWNLOAD.
  it("hides DOWNLOAD_REDACTED_FILE and labels the bundle button SAVE on success", () => {
    const hook = makeHook({
      stage: "done",
      fileName: "doc.pdf",
      fileSize: 320,
      contentHash: CONTENT_HASH,
      manifest: manifest([1, 2, 3]),
      selectedIds: [2],
      recipientId: "1",
      result: doneResult([2]),
      savedRedactedPath: "/out/doc_redacted.pdf",
    });
    renderWithSkin(<RedactTab hook={hook} />);
    expect(screen.queryByText("DOWNLOAD_REDACTED_FILE")).toBeNull();
    expect(screen.getByText("SAVE_BUNDLE.json")).toBeInTheDocument();
    // The saved path's basename is surfaced.
    expect(screen.getByText("doc_redacted.pdf")).toBeInTheDocument();
    fireEvent.click(screen.getByText("SAVE_BUNDLE.json"));
    expect(hook.downloadBundle).toHaveBeenCalled();
  });

  // The hidden browser <input> is not rendered in Tauri mode.
  it("does not render the hidden browser file input in Tauri mode", () => {
    const { container } = setup();
    expect(container.querySelector('input[type="file"]')).toBeNull();
  });
});
