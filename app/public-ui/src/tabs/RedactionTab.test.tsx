import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import RedactionTab from "./RedactionTab";
import { renderWithSkin } from "../__tests__/render";

type RedactionTabProps = ComponentProps<typeof RedactionTab>;

const baseProps: RedactionTabProps = {
  stage: "idle",
  fileName: null,
  fileHash: null,
  fileProgress: 0,
  bundleName: null,
  parsed: null,
  result: null,
  bindingValid: null,
  error: null,
  onFile: vi.fn(),
  onBundleFile: vi.fn(),
  onAudit: vi.fn(),
  onReset: vi.fn(),
};

function setup(overrides: Partial<RedactionTabProps> = {}) {
  const props: RedactionTabProps = { ...baseProps, ...overrides };
  return { props, ...renderWithSkin(<RedactionTab {...props} />) };
}

describe("<RedactionTab>", () => {
  it("renders the dual-slot drop region with the empty prompt", () => {
    setup();
    expect(
      screen.getByRole("region", { name: /Drop redacted file and redaction proof bundle/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/DROP_REDACTED_FILE/)).toBeInTheDocument();
  });

  it("shows fileName + truncated fileHash once a file is loaded", () => {
    setup({
      stage: "ready",
      fileName: "doc-a.pdf",
      fileHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
    expect(screen.getByText("doc-a.pdf")).toBeInTheDocument();
    // short() helper formats long hashes as `xxxxxxxxx…xxxxxx`
    expect(screen.getByText(/012345678…abcdef/)).toBeInTheDocument();
  });

  it("shows 'hashing… N%' progress while the file is being hashed", () => {
    setup({ stage: "hashing", fileName: "doc.pdf", fileProgress: 42 });
    // Two "hashing" matches: the in-slot "hashing… 42%" indicator AND the
    // primary button label "HASHING_FILE...". Both are correct UI; assert
    // on the more specific one.
    expect(screen.getByText(/hashing… 42%/)).toBeInTheDocument();
  });

  it("shows the bundle name once the redaction proof JSON is loaded", () => {
    setup({ stage: "ready", bundleName: "redaction-proof.json" });
    expect(screen.getByText("redaction-proof.json")).toBeInTheDocument();
  });

  it("disables AUDIT_REDACTION until both slots are loaded", () => {
    setup();
    const btn = screen.getByRole("button", { name: /AUDIT_REDACTION/i });
    expect(btn).toBeDisabled();
  });

  it("enables AUDIT_REDACTION when stage is 'ready'", () => {
    setup({ stage: "ready", fileName: "f.pdf", bundleName: "b.json" });
    expect(screen.getByRole("button", { name: /AUDIT_REDACTION/i })).toBeEnabled();
  });

  it("shows VERIFYING_REDACTION label while verifying", () => {
    setup({ stage: "verifying", fileName: "f.pdf", bundleName: "b.json" });
    expect(screen.getByRole("button", { name: /VERIFYING_REDACTION/i })).toBeInTheDocument();
  });

  it("shows HASHING_FILE label while file hashing is in flight", () => {
    setup({ stage: "hashing", fileName: "f.pdf", fileProgress: 10 });
    expect(screen.getByRole("button", { name: /HASHING_FILE/i })).toBeInTheDocument();
  });

  it("renders the error banner when error is set", () => {
    setup({ error: "Bundle does not parse" });
    expect(screen.getByText("Bundle does not parse")).toBeInTheDocument();
  });

  it("fires onAudit when AUDIT_REDACTION is clicked", async () => {
    const { props } = setup({ stage: "ready", fileName: "f.pdf", bundleName: "b.json" });
    await userEvent.click(screen.getByRole("button", { name: /AUDIT_REDACTION/i }));
    expect(props.onAudit).toHaveBeenCalled();
  });

  it("fires onReset when RESET is clicked", async () => {
    const { props } = setup({ stage: "done", fileName: "f.pdf", bundleName: "b.json" });
    await userEvent.click(screen.getByRole("button", { name: /^RESET$/ }));
    expect(props.onReset).toHaveBeenCalled();
  });

  it("PROOF_MATH_VALID branch renders when result.valid is true", () => {
    setup({
      stage: "done",
      fileName: "f.pdf",
      bundleName: "b.json",
      result: { valid: true, circuit: "redaction_validity" },
      bindingValid: true,
    });
    expect(screen.getByText(/PROOF_MATH_VALID/)).toBeInTheDocument();
  });

  it("PROOF_MATH_INVALID branch renders when result.valid is false", () => {
    setup({
      stage: "done",
      fileName: "f.pdf",
      bundleName: "b.json",
      result: { valid: false, circuit: "redaction_validity" },
      bindingValid: null,
    });
    expect(screen.getByText(/PROOF_MATH_INVALID/)).toBeInTheDocument();
  });

  it("calls onFile when a file is dropped on the region", () => {
    const { props } = setup();
    const region = screen.getByRole("region", { name: /Drop redacted file/i });
    const file = new File(["%PDF-1.4"], "doc.pdf", { type: "application/pdf" });
    fireEvent.dragOver(region);
    fireEvent.drop(region, { dataTransfer: { files: [file] } });
    expect(props.onFile).toHaveBeenCalledWith(file);
  });
});
