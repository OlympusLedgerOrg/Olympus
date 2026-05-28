import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import AuditProofTab from "./AuditProofTab";
import { renderWithSkin } from "../__tests__/render";

type AuditProofTabProps = ComponentProps<typeof AuditProofTab>;

const baseProps: AuditProofTabProps = {
  stage: "idle",
  bundleName: null,
  parsed: null,
  result: null,
  anchor: null,
  error: null,
  onBundleFile: vi.fn(),
  onBundleText: vi.fn(),
  onAudit: vi.fn(),
  onReset: vi.fn(),
};

function setup(overrides: Partial<AuditProofTabProps> = {}) {
  const props: AuditProofTabProps = { ...baseProps, ...overrides };
  return { props, ...renderWithSkin(<AuditProofTab {...props} />) };
}

describe("<AuditProofTab>", () => {
  it("renders the drop zone with the empty-state prompt", () => {
    setup();
    expect(screen.getByRole("region", { name: /Drop ZK proof bundle/i })).toBeInTheDocument();
    expect(screen.getByText(/DROP_PROOF_BUNDLE\.json HERE/i)).toBeInTheDocument();
  });

  it("shows the bundleName once a file is loaded", () => {
    setup({ stage: "ready", bundleName: "proof-existence.json" });
    expect(screen.getByText("proof-existence.json")).toBeInTheDocument();
  });

  it("shows CIRCUIT_<name> and public-signal count once parsed", () => {
    setup({
      stage: "ready",
      bundleName: "p.json",
      parsed: {
        circuit: "document_existence",
        proofJson: "{}",
        publicSignals: ["r", "l", "i", "t"],
      },
    });
    expect(screen.getByText(/CIRCUIT_/)).toBeInTheDocument();
    expect(screen.getByText(/DOCUMENT_EXISTENCE/)).toBeInTheDocument();
    expect(screen.getByText(/4 PUBLIC_SIGNALS/)).toBeInTheDocument();
  });

  it("calls onBundleText when the textarea changes", () => {
    const { props } = setup();
    // userEvent.type treats `{` as a keyboard descriptor opener — use
    // fireEvent.change for the textarea-paste path instead.
    fireEvent.change(screen.getByPlaceholderText(/document_existence/), {
      target: { value: '{"circuit":"document_existence"}' },
    });
    expect(props.onBundleText).toHaveBeenCalledWith('{"circuit":"document_existence"}');
  });

  it("calls onBundleFile when a file is dropped on the region", () => {
    const { props } = setup();
    const region = screen.getByRole("region", { name: /Drop ZK proof bundle/i });
    const file = new File(["{}"], "p.json", { type: "application/json" });
    fireEvent.dragOver(region);
    fireEvent.drop(region, { dataTransfer: { files: [file] } });
    expect(props.onBundleFile).toHaveBeenCalledWith(file);
  });

  it("clicking the bundle button opens the hidden file input (no crash)", async () => {
    setup();
    // Just verify the button is rendered + clickable; jsdom can't simulate
    // the OS file picker, but the click handler must not throw.
    const btn = screen.getByRole("button", { name: /PROOF BUNDLE/i });
    await userEvent.click(btn);
    expect(btn).toBeInTheDocument();
  });

  it("renders the error banner when error is set", () => {
    setup({ error: "Malformed proof bundle" });
    expect(screen.getByText(/Malformed proof bundle/)).toBeInTheDocument();
  });

  it("renders PROOF_MATH_VALID when result.valid is true", () => {
    setup({
      stage: "done",
      parsed: {
        circuit: "document_existence",
        proofJson: "{}",
        publicSignals: ["a", "b", "c", "d"],
      },
      result: { valid: true, circuit: "document_existence" },
      anchor: null,
    });
    expect(screen.getByText(/PROOF_MATH_VALID/)).toBeInTheDocument();
    // No content_hash → anchor is null → ANCHOR_UNCHECKED branch
    expect(screen.getByText(/ANCHOR_UNCHECKED/)).toBeInTheDocument();
  });

  it("renders PROOF_MATH_INVALID when result.valid is false", () => {
    setup({
      stage: "done",
      parsed: {
        circuit: "non_existence",
        proofJson: "{}",
        publicSignals: ["r", "k"],
      },
      result: { valid: false, circuit: "non_existence" },
      anchor: null,
    });
    expect(screen.getByText(/PROOF_MATH_INVALID/)).toBeInTheDocument();
  });

  it("renders ANCHORED_TO_TRUSTED_SNAPSHOT when anchor.valid is true", () => {
    setup({
      stage: "done",
      parsed: {
        circuit: "document_existence",
        proofJson: "{}",
        publicSignals: ["a", "b", "c", "d"],
        contentHash: "ch",
      },
      result: { valid: true, circuit: "document_existence" },
      anchor: {
        valid: true,
        proofMathValid: true,
        detail: "ok",
        signalsBindToSnapshot: true,
        snapshotTrusted: true,
      },
    });
    expect(screen.getByText(/ANCHORED_TO_TRUSTED_SNAPSHOT/)).toBeInTheDocument();
  });

  it("renders ANCHOR_FAILED with the failure reason chips when anchor.valid is false", () => {
    setup({
      stage: "done",
      parsed: {
        circuit: "document_existence",
        proofJson: "{}",
        publicSignals: ["a", "b", "c", "d"],
        contentHash: "ch",
      },
      result: { valid: true, circuit: "document_existence" },
      anchor: {
        valid: false,
        proofMathValid: true,
        detail: "signals don't bind to any stored snapshot",
        signalsBindToSnapshot: false,
        snapshotTrusted: true,
      },
    });
    expect(screen.getByText(/ANCHOR_FAILED/)).toBeInTheDocument();
    expect(screen.getByText(/signals don't bind/)).toBeInTheDocument();
  });
});
