import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SkinProvider } from "../skins/SkinProvider";

vi.mock("../lib/api", () => ({
  getPublicStats: vi.fn(),
}));
vi.mock("../lib/audio", () => ({
  playGlitchSound: vi.fn(),
}));

// Mock every hook the page composes so the integration surface is the
// page's own glue (tabs, query state, command deck, reset button) rather
// than the hook implementations (each of which has its own dedicated
// test suite in phase 1b).
const hashHook = {
  hashInput: "",
  hashError: null,
  hashStatus: { label: "READY", tone: "ok" as const },
  hashMutation: { isPending: false },
  apiKey: "",
  setApiKey: vi.fn(),
  setHashInput: vi.fn(),
  setHashError: vi.fn(),
  submitHash: vi.fn(),
  pasteHash: vi.fn().mockResolvedValue(undefined),
  reset: vi.fn(),
};
const proofHook = {
  proofError: null,
  proofMutation: { isPending: false },
  setProofError: vi.fn(),
  reset: vi.fn(),
};
const fileHook = {
  apiKey: "",
  setApiKey: vi.fn(),
  commitStage: "idle" as const,
  commitError: null,
  droppedFile: null,
  originalHash: "",
  setOriginalHash: vi.fn(),
  fileProgress: 0,
  commitFile: vi.fn(),
  resetCommit: vi.fn(),
  reset: vi.fn(),
  onFile: vi.fn(),
  onHash: vi.fn(),
  onProgress: vi.fn(),
};
const auditHook = {
  stage: "idle" as const,
  bundleName: null,
  parsed: null,
  result: null,
  anchor: null,
  error: null,
  onBundleFile: vi.fn(),
  onBundleText: vi.fn(),
  audit: vi.fn().mockResolvedValue(undefined),
  reset: vi.fn(),
};
const redactionHook = {
  stage: "idle" as const,
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
  audit: vi.fn().mockResolvedValue(undefined),
  reset: vi.fn(),
};

vi.mock("../hooks/useHashVerification", () => ({
  useHashVerification: () => hashHook,
}));
vi.mock("../hooks/useProofVerification", () => ({
  useProofVerification: () => proofHook,
}));
vi.mock("../hooks/useFileCommit", () => ({
  useFileCommit: () => fileHook,
}));
vi.mock("../hooks/useAuditProof", () => ({
  useAuditProof: () => auditHook,
}));
vi.mock("../hooks/useRedactionAudit", () => ({
  useRedactionAudit: () => redactionHook,
}));
vi.mock("../hooks/useWasmStatus", () => ({
  useWasmStatus: () => ({ wasmStatus: "ready", wasmError: null }),
}));

// Mock heavy / animated children so the test isolates the page itself.
vi.mock("../components/TiltContainer", () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock("../components/FileHasher", () => ({
  default: () => <div data-testid="file-hasher-mock" />,
}));
vi.mock("../components/RecentVerifications", () => ({
  default: () => <div data-testid="recent-verifications-mock" />,
}));
vi.mock("../components/CommandDeck", () => ({
  default: ({ activeTab, onSelect }: { activeTab: string; onSelect: (t: string) => void }) => (
    <div data-testid="command-deck-mock" data-active={activeTab} onClick={() => onSelect("audit")} />
  ),
}));

import { getPublicStats } from "../lib/api";
import { playGlitchSound } from "../lib/audio";
import HomePage from "./HomePage";

const mockedGetPublicStats = vi.mocked(getPublicStats);
const mockedPlayGlitchSound = vi.mocked(playGlitchSound);

function newClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
}

function renderHome() {
  return render(
    <QueryClientProvider client={newClient()}>
      <SkinProvider>
        <HomePage />
      </SkinProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mockedGetPublicStats.mockReset();
  mockedPlayGlitchSound.mockReset();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("<HomePage>", () => {
  it("renders the VERIFY_TRUTH hero, stat cards, and default HASH_LOOKUP tab", async () => {
    mockedGetPublicStats.mockResolvedValue({
      nodes: 3, shards: 4, proofs: 10, sbts_issued: 2, uptime: "1h", uptime_seconds: 3600,
    });
    renderHome();
    expect(screen.getByText(/VERIFY_TRUTH/)).toBeInTheDocument();
    // tab list — three role=tab buttons
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    // Default tab pre-selected is HASH_LOOKUP — HashTab's "BLAKE3 content hash" label renders
    expect(screen.getByLabelText(/BLAKE3 content hash/i)).toBeInTheDocument();
    await waitFor(() => expect(mockedGetPublicStats).toHaveBeenCalled());
  });

  it("API_OFFLINE pill shows when the stats query errors", async () => {
    mockedGetPublicStats.mockRejectedValue(new Error("server down"));
    renderHome();
    await waitFor(() => expect(screen.getByText(/API_OFFLINE/)).toBeInTheDocument());
  });

  it("clicking the AUDIT_PROOF tab swaps the panel content + plays a blip", async () => {
    mockedGetPublicStats.mockResolvedValue({
      nodes: 0, shards: 0, proofs: 0, sbts_issued: 0, uptime: "0s", uptime_seconds: 0,
    });
    renderHome();
    await userEvent.click(screen.getByRole("tab", { name: /AUDIT_PROOF/i }));
    // AuditProofTab's drop region renders
    expect(screen.getByRole("region", { name: /Drop ZK proof bundle/i })).toBeInTheDocument();
    expect(mockedPlayGlitchSound).toHaveBeenCalledWith("blip");
    expect(auditHook.reset).toHaveBeenCalled();
  });

  it("clicking the REDACTION tab swaps to the redaction panel", async () => {
    mockedGetPublicStats.mockResolvedValue({
      nodes: 0, shards: 0, proofs: 0, sbts_issued: 0, uptime: "0s", uptime_seconds: 0,
    });
    renderHome();
    await userEvent.click(screen.getByRole("tab", { name: /REDACTION/i }));
    // The audit drop region disappears, replaced by RedactionTab's content
    expect(screen.queryByRole("region", { name: /Drop ZK proof bundle/i })).not.toBeInTheDocument();
  });

  it("RESET_CONSOLE clears all hooks", async () => {
    mockedGetPublicStats.mockResolvedValue({
      nodes: 0, shards: 0, proofs: 0, sbts_issued: 0, uptime: "0s", uptime_seconds: 0,
    });
    renderHome();
    await userEvent.click(screen.getByRole("button", { name: /RESET_CONSOLE/i }));
    expect(hashHook.reset).toHaveBeenCalled();
    expect(proofHook.reset).toHaveBeenCalled();
    expect(fileHook.reset).toHaveBeenCalled();
    expect(auditHook.reset).toHaveBeenCalled();
    expect(redactionHook.reset).toHaveBeenCalled();
  });

  it("shows the READY_FOR_INPUT panel when no verdictResult is set", async () => {
    mockedGetPublicStats.mockResolvedValue({
      nodes: 0, shards: 0, proofs: 0, sbts_issued: 0, uptime: "0s", uptime_seconds: 0,
    });
    renderHome();
    expect(screen.getByText(/READY_FOR_INPUT/)).toBeInTheDocument();
  });
});
