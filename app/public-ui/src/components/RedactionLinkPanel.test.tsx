import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import RedactionLinkPanel from "./RedactionLinkPanel";
import type { RedactionLinkResult } from "../hooks/useRedactionLink";

type Props = ComponentProps<typeof RedactionLinkPanel>;

const baseProps: Props = {
  redactedFileName: "redacted.pdf",
  stage: "idle",
  originalFile: null,
  originalHash: "",
  commitId: "",
  setCommitId: vi.fn(),
  result: null,
  error: null,
  onStart: vi.fn(),
  onOriginalFile: vi.fn(),
  onLink: vi.fn(),
  onReset: vi.fn(),
};

function setup(overrides: Partial<Props> = {}) {
  const props: Props = { ...baseProps, ...overrides };
  return { props, ...render(<RedactionLinkPanel {...props} />) };
}

const SAMPLE_RESULT: RedactionLinkResult = {
  original_commit_id: "commit-abc",
  original_blake3: "ob",
  original_root: "root-poseidon-xyz",
  redacted_commitment: "rc-fff",
  reveal_mask_commitment: "rmc-eee",
  reveal_mask: [1, 1, 0, 0, 1],
  revealed_count: 3,
  redacted_count: 2,
  verified: true,
  note: "Linked successfully.",
};

beforeEach(() => {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<RedactionLinkPanel>", () => {
  it("idle stage renders the 'PROVE AS REDACTION' entry button + filename", () => {
    setup({ redactedFileName: "secret-redacted.pdf" });
    expect(screen.getByText(/OR.*VERIFY AS REDACTION/)).toBeInTheDocument();
    expect(screen.getByText("secret-redacted.pdf")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /PROVE AS REDACTION/i })).toBeInTheDocument();
  });

  it("idle PROVE AS REDACTION button fires onStart", async () => {
    const { props } = setup();
    await userEvent.click(screen.getByRole("button", { name: /PROVE AS REDACTION/i }));
    expect(props.onStart).toHaveBeenCalled();
  });

  it("awaiting_original stage shows the LINK TO ORIGINAL button (disabled)", () => {
    setup({ stage: "awaiting_original" });
    const btn = screen.getByRole("button", { name: /LINK TO ORIGINAL/i });
    expect(btn).toBeDisabled();
  });

  it("ready stage enables LINK TO ORIGINAL when a commit id + original file are present", () => {
    setup({
      stage: "ready",
      originalFile: new File(["x"], "orig.pdf"),
      originalHash: "ab".repeat(32),
      commitId: "commit-xyz",
    });
    const btn = screen.getByRole("button", { name: /LINK TO ORIGINAL/i });
    expect(btn).toBeEnabled();
  });

  it("linking stage swaps the button label to COMPUTING…", () => {
    setup({
      stage: "linking",
      originalFile: new File(["x"], "orig.pdf"),
      originalHash: "ab".repeat(32),
      commitId: "commit-xyz",
    });
    expect(
      screen.getByRole("button", { name: /COMPUTING REDACTION PROOF/i }),
    ).toBeInTheDocument();
  });

  it("setCommitId fires when the commit-id field changes", () => {
    const { props } = setup({ stage: "ready", originalFile: new File(["x"], "orig.pdf") });
    const input = screen.getAllByRole("textbox").find((el) => (el as HTMLInputElement).type !== "file");
    expect(input).toBeDefined();
    fireEvent.change(input!, { target: { value: "commit-typed" } });
    expect(props.setCommitId).toHaveBeenCalledWith("commit-typed");
  });

  it("hidden file-input change fires onOriginalFile", () => {
    const { props } = setup({ stage: "awaiting_original" });
    const file = new File(["o"], "original.pdf", { type: "application/pdf" });
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeTruthy();
    fireEvent.change(fileInput, { target: { files: [file] } });
    expect(props.onOriginalFile).toHaveBeenCalledWith(file);
  });

  it("error string is rendered when the stage carries an error", () => {
    setup({ stage: "error", error: "commit not found on ledger" });
    expect(screen.getByText("commit not found on ledger")).toBeInTheDocument();
  });

  it("done stage renders REDACTION_VERIFIED + reveal counts + bundle fields", () => {
    setup({ stage: "done", result: SAMPLE_RESULT });
    expect(screen.getByText(/REDACTION_VERIFIED/)).toBeInTheDocument();
    // counts
    expect(screen.getByText("3")).toBeInTheDocument(); // revealed
    expect(screen.getByText("2")).toBeInTheDocument(); // redacted
    // 3 / (3+2) = 60%
    expect(screen.getByText(/60% disclosed/)).toBeInTheDocument();
    // bundle fields
    expect(screen.getByText("commit-abc")).toBeInTheDocument();
    expect(screen.getByText("root-poseidon-xyz")).toBeInTheDocument();
    expect(screen.getByText("rc-fff")).toBeInTheDocument();
    expect(screen.getByText("rmc-eee")).toBeInTheDocument();
    expect(screen.getByText("Linked successfully.")).toBeInTheDocument();
  });

  it("done COPY BUNDLE writes the full result JSON to clipboard", async () => {
    setup({ stage: "done", result: SAMPLE_RESULT });
    await userEvent.click(screen.getByRole("button", { name: /COPY BUNDLE/i }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    const written = vi.mocked(navigator.clipboard.writeText).mock.calls[0][0];
    // Crypto bundle — assert deep equality, not just a single field, so any
    // missing/extra/renamed key fails the test loudly. The 10 fields here
    // are what downstream verifiers compute against.
    expect(JSON.parse(written)).toEqual(SAMPLE_RESULT);
  });

  it("done RESET button fires onReset", async () => {
    const { props } = setup({ stage: "done", result: SAMPLE_RESULT });
    await userEvent.click(screen.getByRole("button", { name: /^RESET$/i }));
    expect(props.onReset).toHaveBeenCalled();
  });
});
