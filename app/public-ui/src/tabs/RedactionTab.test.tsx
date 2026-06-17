import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import RedactionTab from "./RedactionTab";
import { renderWithSkin } from "../__tests__/render";
import type { V3Bundle } from "../lib/redactionBinding";

type RedactionTabProps = ComponentProps<typeof RedactionTab>;

function bundle(overrides: Partial<V3Bundle> = {}): V3Bundle {
  return {
    original_root: "ab".repeat(32),
    format: "text-line",
    segment_count: 2,
    recipient_id: "12345",
    segments: [
      { segment_id: 0, redacted: false, artifact_offset: 0, artifact_length: 4, blinding_decimal: "7" },
      { segment_id: 1, redacted: true, artifact_offset: 4, artifact_length: 0, leaf_hex: "cd".repeat(32) },
    ],
    nullifier: "ef".repeat(32),
    signature_hex: "00".repeat(64),
    ...overrides,
  };
}

const baseProps: RedactionTabProps = {
  stage: "idle",
  fileName: null,
  fileHash: null,
  fileProgress: 0,
  bundleName: null,
  parsed: null,
  issuerPubkeyHex: "",
  issuerKeyAutofilled: false,
  verified: null,
  verifyReason: null,
  error: null,
  onFile: vi.fn(),
  onBundleFile: vi.fn(),
  onIssuerPubkey: vi.fn(),
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
      screen.getByRole("region", { name: /Drop redacted file and redaction bundle/i }),
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
    expect(screen.getByText(/012345678…abcdef/)).toBeInTheDocument();
  });

  it("shows 'hashing… N%' progress while the file is being hashed", () => {
    setup({ stage: "hashing", fileName: "doc.pdf", fileProgress: 42 });
    expect(screen.getByText(/hashing… 42%/)).toBeInTheDocument();
  });

  it("shows the bundle name once the redaction bundle JSON is loaded", () => {
    setup({ stage: "ready", bundleName: "redaction-bundle.json" });
    expect(screen.getByText("redaction-bundle.json")).toBeInTheDocument();
  });

  it("wires the issuer pubkey input", () => {
    const { props } = setup();
    fireEvent.change(screen.getByLabelText("Issuer Ed25519 public key"), {
      target: { value: "aa".repeat(32) },
    });
    expect(props.onIssuerPubkey).toHaveBeenCalledWith("aa".repeat(32));
  });

  it("disables AUDIT_REDACTION until file + bundle + issuer key are all present", () => {
    // ready stage but no issuer key → still disabled.
    setup({ stage: "ready", fileName: "f.pdf", fileHash: "ff".repeat(32), bundleName: "b.json", parsed: bundle() });
    expect(screen.getByRole("button", { name: /AUDIT_REDACTION/i })).toBeDisabled();
  });

  it("enables AUDIT_REDACTION when everything is loaded", () => {
    setup({
      stage: "ready",
      fileName: "f.pdf",
      fileHash: "ff".repeat(32),
      bundleName: "b.json",
      parsed: bundle(),
      issuerPubkeyHex: "aa".repeat(32),
    });
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
    const { props } = setup({
      stage: "ready",
      fileName: "f.pdf",
      fileHash: "ff".repeat(32),
      bundleName: "b.json",
      parsed: bundle(),
      issuerPubkeyHex: "aa".repeat(32),
    });
    await userEvent.click(screen.getByRole("button", { name: /AUDIT_REDACTION/i }));
    expect(props.onAudit).toHaveBeenCalled();
  });

  it("fires onReset when RESET is clicked", async () => {
    const { props } = setup({ stage: "done", fileName: "f.pdf", bundleName: "b.json", verified: true, parsed: bundle() });
    await userEvent.click(screen.getByRole("button", { name: /^RESET$/ }));
    expect(props.onReset).toHaveBeenCalled();
  });

  it("BUNDLE_VERIFIED branch renders when verified is true", () => {
    setup({
      stage: "done",
      fileName: "f.pdf",
      bundleName: "b.json",
      parsed: bundle(),
      verified: true,
    });
    expect(screen.getByText(/BUNDLE_VERIFIED/)).toBeInTheDocument();
    expect(screen.getByText("text-line")).toBeInTheDocument();
  });

  it("BUNDLE_REJECTED branch renders the reason when verified is false", () => {
    setup({
      stage: "done",
      fileName: "f.pdf",
      bundleName: "b.json",
      parsed: bundle(),
      verified: false,
      verifyReason: "fold != original_root",
    });
    expect(screen.getByText(/BUNDLE_REJECTED/)).toBeInTheDocument();
    expect(screen.getByText("fold != original_root")).toBeInTheDocument();
  });

  it("calls onFile when a non-JSON file is dropped on the region", () => {
    const { props } = setup();
    const region = screen.getByRole("region", { name: /Drop redacted file/i });
    const file = new File(["%PDF-1.4"], "doc.pdf", { type: "application/pdf" });
    fireEvent.dragOver(region);
    fireEvent.drop(region, { dataTransfer: { files: [file] } });
    expect(props.onFile).toHaveBeenCalledWith(file);
  });

  it("calls onBundleFile when a .json file is dropped on the region", () => {
    const { props } = setup();
    const region = screen.getByRole("region", { name: /Drop redacted file/i });
    const file = new File(["{}"], "bundle.json", { type: "application/json" });
    fireEvent.drop(region, { dataTransfer: { files: [file] } });
    expect(props.onBundleFile).toHaveBeenCalledWith(file);
  });
});
