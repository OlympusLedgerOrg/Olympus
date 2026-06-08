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
    error: null,
    previewMask: Array(16).fill(1),
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
});
