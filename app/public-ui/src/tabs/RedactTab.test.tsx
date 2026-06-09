/**
 * Smoke + interaction tests for <RedactTab> (the object-level redaction
 * producer UI, ADR-0026).
 *
 * The tab is a thin view over `useRedactionCreate`; these tests drive it with a
 * hand-built hook stub and assert the view wires user actions to the right hook
 * callbacks and renders each state (empty / loading manifest / object checklist
 * / done / error).
 */
import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import RedactTab from "./RedactTab";
import { renderWithSkin } from "../__tests__/render";
import type { useRedactionCreate } from "../hooks/useRedactionCreate";
import type { RedactionManifestResponse, RedactDocumentResponse } from "../lib/api";

type Hook = ReturnType<typeof useRedactionCreate>;

const CONTENT_HASH = "ab".repeat(32);

function manifest(ids: number[]): RedactionManifestResponse {
  return {
    contentHash: CONTENT_HASH,
    originalRoot: "cd".repeat(32),
    objectCount: ids.length,
    objects: ids.map((segmentId) => ({ segmentId, byteLength: 100 })),
  };
}

function doneResult(redactedObjIds: number[]): RedactDocumentResponse {
  return {
    redactedBase64: "QUJD",
    bundle: {
      circuit: "redaction_validity",
      contentHash: CONTENT_HASH,
      originalRoot: "cd".repeat(32),
      proofJson: {},
      publicSignals: ["1", "2", "3", "4", "5", "6"],
      redactedObjIds,
      revealedSegments: [{ segmentId: 1, blindingDecimal: "12345" }],
      signatureHex: "ff",
    },
  };
}

function makeHook(overrides: Partial<Hook> = {}): Hook {
  return {
    stage: "idle",
    fileName: null,
    fileSize: 0,
    contentHash: null,
    manifest: null,
    selectedIds: [],
    recipientId: "",
    result: null,
    error: null,
    onFile: vi.fn(),
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

describe("<RedactTab>", () => {
  it("renders the original-PDF drop zone when empty", () => {
    setup();
    expect(screen.getByRole("region", { name: /Drop the original document/i })).toBeInTheDocument();
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

  it("renders download buttons and revealed segments on success", () => {
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
    fireEvent.click(screen.getByText("DOWNLOAD_REDACTED_FILE"));
    expect(hook.downloadRedacted).toHaveBeenCalled();
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
    const f = new File(["data"], "in.pdf", { type: "application/pdf" });
    fireEvent.change(input, { target: { files: [f] } });
    expect(hook.onFile).toHaveBeenCalledWith(f);
  });

  it("loads a file via drag and drop", () => {
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);
    const region = screen.getByRole("region", { name: /Drop the original document/i });
    const f = new File(["data"], "drop.pdf", { type: "application/pdf" });
    fireEvent.dragOver(region);
    fireEvent.dragLeave(region);
    fireEvent.drop(region, { dataTransfer: { files: [f] } });
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
});
