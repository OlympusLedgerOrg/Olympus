import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    issueZkBundle: vi.fn(),
    issueRedaction: vi.fn(),
    getRedactionManifest: vi.fn(),
  };
});
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => ""),
}));

import { ApiError, issueZkBundle, issueRedaction, getRedactionManifest } from "../lib/api";
import ProofResultPanel from "./ProofResultPanel";
import type { VerdictState } from "../lib/types";

const mockedIssueZkBundle = vi.mocked(issueZkBundle);
const mockedIssueRedaction = vi.mocked(issueRedaction);
const mockedGetManifest = vi.mocked(getRedactionManifest);

const VALID_HASH = "ff".repeat(32);

// VerdictState.raw is typed `unknown`, so spreading `makeVerdict().raw` in
// per-test overrides errors out under strict TS. Expose the base raw object
// as a strongly-typed constant tests can extend without casts.
const BASE_RAW: Record<string, unknown> = {
  content_hash: VALID_HASH,
  proof_id: "pid-1",
  record_id: "rec-1",
  shard_id: "shard-7",
  merkle_root: "root-bb",
  merkle_proof_valid: true,
  ledger_entry_hash: "leh-cc",
  timestamp: "2026-05-28T00:00:00Z",
};

function makeVerdict(overrides: Partial<VerdictState> = {}): VerdictState {
  return {
    verdict: "verified",
    displayHash: VALID_HASH,
    details: [],
    raw: BASE_RAW,
    ...overrides,
  };
}

beforeEach(() => {
  mockedIssueZkBundle.mockReset();
  mockedIssueRedaction.mockReset();
  mockedGetManifest.mockReset();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<ProofResultPanel>", () => {
  it("renders the verified verdict title + AWAITING / VALID badges", () => {
    render(<ProofResultPanel verdict={makeVerdict()} />);
    // The "BOOT_ART // GODMODE_BUILD" kicker tags the panel.
    expect(screen.getByText(/BOOT_ART/)).toBeInTheDocument();
    // valid=true → MERKLE_PROOF badge = "VALID"
    expect(screen.getByText("VALID")).toBeInTheDocument();
  });

  it("renders the unknown verdict path with the PROOF_PENDING title", () => {
    render(<ProofResultPanel verdict={makeVerdict({ verdict: "unknown" })} />);
    expect(screen.getByText(/PROOF_PENDING/)).toBeInTheDocument();
  });

  it("renders the failed verdict path with the PROOF_FAILED badge", () => {
    render(<ProofResultPanel verdict={makeVerdict({ verdict: "failed" })} />);
    expect(screen.getByText("PROOF_FAILED")).toBeInTheDocument();
  });

  it("renders the core proof fields from verdict.raw", () => {
    render(<ProofResultPanel verdict={makeVerdict()} />);
    expect(screen.getByText("pid-1")).toBeInTheDocument();
    expect(screen.getByText("rec-1")).toBeInTheDocument();
    expect(screen.getByText("shard-7")).toBeInTheDocument();
    expect(screen.getByText("root-bb")).toBeInTheDocument();
    expect(screen.getByText("leh-cc")).toBeInTheDocument();
    expect(screen.getByText(VALID_HASH)).toBeInTheDocument();
  });

  it("shows the ORIGINAL_HASH row + REDACTED_DOCUMENT badge when is_redacted is true", () => {
    render(
      <ProofResultPanel
        verdict={makeVerdict({
          raw: {
            ...BASE_RAW,
            is_redacted: true,
            original_hash: "aa".repeat(32),
          },
        })}
      />,
    );
    expect(screen.getByText(/REDACTED_DOCUMENT/)).toBeInTheDocument();
    expect(screen.getByText("ORIGINAL_HASH")).toBeInTheDocument();
  });

  it("renders an INVALID merkle-proof badge when merkle_proof_valid=false", () => {
    render(
      <ProofResultPanel
        verdict={makeVerdict({
          raw: { ...BASE_RAW, merkle_proof_valid: false },
        })}
      />,
    );
    expect(screen.getByText("INVALID")).toBeInTheDocument();
  });

  it("renders an UNKNOWN merkle-proof badge when verdict is 'unknown' and merkle_proof_valid is missing", () => {
    // normalizeResult derives merkle_proof_valid from the verdict when raw
    // doesn't carry it: verified→true, failed→false, unknown→undefined.
    // So the UNKNOWN badge needs verdict='unknown' to actually fire.
    render(
      <ProofResultPanel
        verdict={makeVerdict({
          verdict: "unknown",
          raw: { ...BASE_RAW, merkle_proof_valid: undefined },
        })}
      />,
    );
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });

  it("COPY_PROOF_JSON writes the bundle JSON to clipboard", async () => {
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /COPY_PROOF_JSON/i }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    const written = vi.mocked(navigator.clipboard.writeText).mock.calls[0][0];
    expect(JSON.parse(written).proof_id).toBe("pid-1");
  });

  it("DOWNLOAD_BUNDLE creates and revokes a blob URL", async () => {
    const createObjectURL = vi.fn(() => "blob:fake");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });

    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /DOWNLOAD_BUNDLE/i }));
    expect(createObjectURL).toHaveBeenCalled();
    // revoke is queued via setTimeout(0) — wait for the next tick.
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith("blob:fake"));
  });

  it("GENERATE_ZK_PROOF is disabled when content_hash is absent", () => {
    render(
      <ProofResultPanel
        verdict={{
          verdict: "unknown",
          details: [],
          raw: {},
        }}
      />,
    );
    expect(screen.getByRole("button", { name: /GENERATE_ZK_PROOF/i })).toBeDisabled();
  });

  it("GENERATE_ZK_PROOF calls issueZkBundle and triggers a download on success", async () => {
    mockedIssueZkBundle.mockResolvedValue({
      circuit: "document_existence",
      proofJson: '{"pi_a":["1"]}',
      publicSignals: ["1", "2", "3", "4"],
      contentHash: VALID_HASH,
      originalRoot: "or",
      snapshotRoot: "sr",
      snapshotIndex: 7,
      snapshotSize: 16,
      snapshotSig: "sig",
    });
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: vi.fn(() => "blob:zk") });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });

    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_ZK_PROOF/i }));
    await waitFor(() => expect(mockedIssueZkBundle).toHaveBeenCalledWith(VALID_HASH, undefined));
  });

  it("GENERATE_ZK_PROOF surfaces the ApiError detail on failure", async () => {
    const err = new ApiError(503, "no snapshot anchored yet");
    mockedIssueZkBundle.mockRejectedValue(err);

    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_ZK_PROOF/i }));
    expect(await screen.findByText(/no snapshot anchored yet/)).toBeInTheDocument();
  });

  it("GENERATE_ZK_PROOF surfaces plain-Error message on non-ApiError failure", async () => {
    mockedIssueZkBundle.mockRejectedValue(new Error("network timeout"));
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_ZK_PROOF/i }));
    expect(await screen.findByText(/network timeout/)).toBeInTheDocument();
  });

  it("GENERATE_REDACTION_PROOF fetches the manifest, hides the last object, and downloads", async () => {
    mockedGetManifest.mockResolvedValue({
      contentHash: VALID_HASH,
      format: "pdf-object",
      originalRoot: "or",
      objectCount: 3,
      objects: [
        { segmentId: 1, byteLength: 10, label: null },
        { segmentId: 4, byteLength: 20, label: null },
        { segmentId: 9, byteLength: 30, label: null },
      ],
    });
    mockedIssueRedaction.mockResolvedValue({
      circuit: "redaction_validity",
      contentHash: VALID_HASH,
      originalRoot: "or",
      proofJson: { pi_a: ["9", "8", "1"] },
      publicSignals: ["1", "2", "3", "4"],
      redactedObjIds: [9],
      revealedSegments: [
        { segmentId: 1, blindingDecimal: "11" },
        { segmentId: 4, blindingDecimal: "22" },
      ],
      signatureHex: "ff",
    });
    const createObjectURL = vi.fn(() => "blob:rd");
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });

    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    await waitFor(() =>
      // Last object (segmentId 9) is hidden; recipient "1" is the MVP default.
      expect(mockedIssueRedaction).toHaveBeenCalledWith(VALID_HASH, [9], "1", undefined),
    );
    expect(createObjectURL).toHaveBeenCalled();
  });

  it("GENERATE_REDACTION_PROOF errors when the document has fewer than 2 objects", async () => {
    mockedGetManifest.mockResolvedValue({
      contentHash: VALID_HASH,
      format: "pdf-object",
      originalRoot: "or",
      objectCount: 1,
      objects: [{ segmentId: 1, byteLength: 10, label: null }],
    });
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    expect(await screen.findByText(/at least 2/)).toBeInTheDocument();
    expect(mockedIssueRedaction).not.toHaveBeenCalled();
  });

  it("GENERATE_REDACTION_PROOF errors when objects[] is shorter than 2 despite objectCount", async () => {
    // objectCount clears the >=2 gate but the array carries a single object —
    // the guard must reject before indexing objects[length-1].
    mockedGetManifest.mockResolvedValue({
      contentHash: VALID_HASH,
      format: "pdf-object",
      originalRoot: "or",
      objectCount: 2,
      objects: [{ segmentId: 1, byteLength: 10, label: null }],
    });
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    expect(await screen.findByText(/inconsistent/i)).toBeInTheDocument();
    expect(mockedIssueRedaction).not.toHaveBeenCalled();
  });

  it("GENERATE_REDACTION_PROOF errors when objectCount and objects.length disagree", async () => {
    // Array is long enough (>=2) but its length != objectCount — still rejected.
    mockedGetManifest.mockResolvedValue({
      contentHash: VALID_HASH,
      format: "pdf-object",
      originalRoot: "or",
      objectCount: 3,
      objects: [
        { segmentId: 1, byteLength: 10, label: null },
        { segmentId: 4, byteLength: 20, label: null },
      ],
    });
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    expect(await screen.findByText(/inconsistent/i)).toBeInTheDocument();
    expect(mockedIssueRedaction).not.toHaveBeenCalled();
  });

  it("GENERATE_REDACTION_PROOF surfaces the ApiError detail on failure", async () => {
    mockedGetManifest.mockRejectedValue(new ApiError(403, "lacks redact scope"));
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    expect(await screen.findByText(/lacks redact scope/)).toBeInTheDocument();
  });

  it("GENERATE_REDACTION_PROOF surfaces plain-Error message on non-ApiError failure", async () => {
    mockedGetManifest.mockRejectedValue(new Error("offline"));
    render(<ProofResultPanel verdict={makeVerdict()} />);
    await userEvent.click(screen.getByRole("button", { name: /GENERATE_REDACTION_PROOF/i }));
    expect(await screen.findByText(/offline/)).toBeInTheDocument();
  });
});
