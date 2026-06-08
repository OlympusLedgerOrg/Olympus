/**
 * Smoke + interaction tests for <RedactTab> (the redaction producer UI).
 *
 * The tab is a thin view over `useRedactionCreate`; these tests drive it with a
 * hand-built hook stub and assert the view wires user actions to the right hook
 * callbacks and renders each state (empty / ranges / done / binary file).
 */
import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import RedactTab from "./RedactTab";
import { renderWithSkin } from "../__tests__/render";
import type { useRedactionCreate } from "../hooks/useRedactionCreate";

type Hook = ReturnType<typeof useRedactionCreate>;

function makeHook(overrides: Partial<Hook> = {}): Hook {
  return {
    stage: "idle",
    fileName: null,
    fileSize: 0,
    fileText: null,
    ranges: [],
    recipientId: "",
    fill: "",
    result: null,
    bindingValid: null,
    error: null,
    previewMask: Array(16).fill(1),
    previewStatus: Array(16).fill("revealed"),
    onFile: vi.fn(),
    addRange: vi.fn(),
    removeRange: vi.fn(),
    clearRanges: vi.fn(),
    setRecipientId: vi.fn(),
    setFill: vi.fn(),
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
  it("renders the original-doc drop zone when empty", () => {
    setup();
    expect(screen.getByRole("region", { name: /Drop the original document/i })).toBeInTheDocument();
    expect(screen.getByText(/ORIGINAL_DOC/)).toBeInTheDocument();
  });

  it("shows the text preview and wires Add selection", () => {
    const hook = makeHook({
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "hello world",
    });
    renderWithSkin(<RedactTab hook={hook} />);
    const preview = screen.getByLabelText("Document preview") as HTMLTextAreaElement;
    expect(preview).toBeInTheDocument();
    // Select "world" (chars 6..11) → byte offsets 6..11 (ASCII).
    preview.setSelectionRange(6, 11);
    fireEvent.click(screen.getByText("ADD_SELECTION"));
    expect(hook.addRange).toHaveBeenCalledWith(6, 11);
  });

  it("warns and hides preview for a non-text file", () => {
    setup({ fileName: "image.bin", fileSize: 10, fileText: null });
    expect(screen.queryByLabelText("Document preview")).not.toBeInTheDocument();
    expect(screen.getByText(/not valid UTF-8 text/i)).toBeInTheDocument();
  });

  it("adds a manual range and clears the inputs", () => {
    const hook = makeHook({ fileName: "doc.txt", fileSize: 320, fileText: "x".repeat(320) });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.change(screen.getByLabelText("Range start byte"), { target: { value: "40" } });
    fireEvent.change(screen.getByLabelText("Range end byte"), { target: { value: "55" } });
    fireEvent.click(screen.getByText("ADD_RANGE"));
    expect(hook.addRange).toHaveBeenCalledWith(40, 55);
  });

  it("lists ranges with remove buttons and a chunk preview", () => {
    const previewMask = Array(16).fill(1);
    previewMask[2] = 0;
    const hook = makeHook({
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 40, end: 55 }],
      previewMask,
    });
    renderWithSkin(<RedactTab hook={hook} />);
    expect(screen.getByText("[40, 55)")).toBeInTheDocument();
    expect(screen.getByText(/1\/16 hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Remove range 40 to 55/i }));
    expect(hook.removeRange).toHaveBeenCalledWith(0);
  });

  it("disables REDACT until a file and at least one range exist", () => {
    const { rerender } = setup({ fileName: "doc.txt", fileSize: 320, fileText: "x", ranges: [] });
    expect(screen.getByText("REDACT_DOCUMENT")).toBeDisabled();
    rerender(
      <RedactTab
        hook={makeHook({
          fileName: "doc.txt",
          fileSize: 320,
          fileText: "x",
          ranges: [{ start: 0, end: 5 }],
          recipientId: "1",
        })}
      />,
    );
    expect(screen.getByText("REDACT_DOCUMENT")).not.toBeDisabled();
  });

  it("renders download buttons on success", () => {
    const hook = makeHook({
      stage: "done",
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 40, end: 55 }],
      recipientId: "1",
      result: {
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
      },
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("DOWNLOAD_REDACTED_FILE"));
    expect(hook.downloadRedacted).toHaveBeenCalled();
    fireEvent.click(screen.getByText("DOWNLOAD_BUNDLE.json"));
    expect(hook.downloadBundle).toHaveBeenCalled();
  });

  it("surfaces an error message", () => {
    setup({ fileName: "doc.txt", fileSize: 10, fileText: "x", error: "boom" });
    expect(screen.getByText("boom")).toBeInTheDocument();
  });

  it("wires the recipient and fill inputs", () => {
    const hook = makeHook({ fileName: "doc.txt", fileSize: 320, fileText: "x".repeat(320) });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.change(screen.getByLabelText("Recipient ID"), { target: { value: "42" } });
    expect(hook.setRecipientId).toHaveBeenCalledWith("42");
    fireEvent.change(screen.getByLabelText("Fill byte"), { target: { value: "88" } });
    expect(hook.setFill).toHaveBeenCalledWith("88");
  });

  it("loads a file via the hidden file input", () => {
    const hook = makeHook();
    const { container } = renderWithSkin(<RedactTab hook={hook} />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const f = new File(["data"], "in.txt", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [f] } });
    expect(hook.onFile).toHaveBeenCalledWith(f);
  });

  it("loads a file via drag and drop", () => {
    const hook = makeHook();
    renderWithSkin(<RedactTab hook={hook} />);
    const region = screen.getByRole("region", { name: /Drop the original document/i });
    const f = new File(["data"], "drop.txt", { type: "text/plain" });
    fireEvent.dragOver(region);
    fireEvent.dragLeave(region);
    fireEvent.drop(region, { dataTransfer: { files: [f] } });
    expect(hook.onFile).toHaveBeenCalledWith(f);
  });

  it("does not add a range when the selection is collapsed", () => {
    const hook = makeHook({ fileName: "doc.txt", fileSize: 320, fileText: "hello world" });
    renderWithSkin(<RedactTab hook={hook} />);
    const preview = screen.getByLabelText("Document preview") as HTMLTextAreaElement;
    preview.setSelectionRange(5, 5); // collapsed — no selection
    fireEvent.click(screen.getByText("ADD_SELECTION"));
    expect(hook.addRange).not.toHaveBeenCalled();
  });

  it("fires redact from the action button", () => {
    const hook = makeHook({
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 0, end: 5 }],
      recipientId: "1",
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("REDACT_DOCUMENT"));
    expect(hook.redact).toHaveBeenCalled();
  });

  it("clears all ranges via the clear button", () => {
    const previewMask = Array(16).fill(1);
    previewMask[2] = 0;
    const hook = makeHook({
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 40, end: 55 }],
      previewMask,
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("clear all"));
    expect(hook.clearRanges).toHaveBeenCalled();
  });

  it("shows the busy label and disables actions while redacting", () => {
    setup({
      stage: "redacting",
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 0, end: 5 }],
      recipientId: "1",
    });
    expect(screen.getByText("REDACTING...")).toBeDisabled();
    expect(screen.getByText("RESET")).toBeDisabled();
  });

  it("fires reset from the action button when not idle", () => {
    const hook = makeHook({
      stage: "done",
      fileName: "doc.txt",
      fileSize: 10,
      fileText: "x".repeat(10),
      ranges: [{ start: 0, end: 5 }],
      recipientId: "1",
      result: {
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
      },
    });
    renderWithSkin(<RedactTab hook={hook} />);
    fireEvent.click(screen.getByText("RESET"));
    expect(hook.reset).toHaveBeenCalled();
  });

  it("hard-blocks REDACT for a non-text (binary) file even with ranges", () => {
    setup({
      fileName: "image.bin",
      fileSize: 100,
      fileText: null,
      ranges: [{ start: 0, end: 5 }],
      recipientId: "1",
    });
    expect(screen.getByText(/BLOCKED/)).toBeInTheDocument();
    expect(screen.getByText("REDACT_DOCUMENT")).toBeDisabled();
  });

  it("notes partially-blanked chunks in the preview strip", () => {
    const previewStatus = Array(16).fill("revealed");
    previewStatus[2] = "partial";
    setup({
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 41, end: 45 }],
      previewStatus,
    });
    expect(screen.getByText(/striped = partially-blanked chunk/i)).toBeInTheDocument();
  });

  it("shows the verify-before-send indicator on success", () => {
    setup({
      stage: "done",
      fileName: "doc.txt",
      fileSize: 320,
      fileText: "x".repeat(320),
      ranges: [{ start: 40, end: 55 }],
      recipientId: "1",
      bindingValid: true,
      result: {
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
      },
    });
    expect(screen.getByText(/VERIFIED — artifact binds/i)).toBeInTheDocument();
  });
});
