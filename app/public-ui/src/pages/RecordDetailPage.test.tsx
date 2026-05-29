import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getRecordProof: vi.fn(),
}));
vi.mock("../lib/audio", () => ({
  playGlitchSound: vi.fn(),
}));

import { getRecordProof } from "../lib/api";
import RecordDetailPage from "./RecordDetailPage";

const mockedGetRecordProof = vi.mocked(getRecordProof);

function newQueryClient() {
  // Disable retries + caching across tests so each test starts clean.
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
}

function renderAt(path: string) {
  const client = newQueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/record/:proof_id" element={<RecordDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const FULL_RECORD = {
  proof_id: "pid-1",
  record_id: "rec-1",
  shard_id: "shard-7",
  content_hash: "ch-aaa",
  merkle_root: "root-bbb",
  merkle_proof: { siblings: ["s1"], directions: [false] },
  ledger_entry_hash: "leh-ccc",
  timestamp: "2026-05-28T00:00:00Z",
};

beforeEach(() => {
  mockedGetRecordProof.mockReset();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<RecordDetailPage>", () => {
  it("shows the LOADING_RECORD splash while the query is in flight", () => {
    // queryFn never resolves → query stays in loading state
    mockedGetRecordProof.mockReturnValue(new Promise(() => {}));
    renderAt("/record/pid-1");
    expect(screen.getByText(/LOADING_RECORD/i)).toBeInTheDocument();
  });

  it("shows RECORD_NOT_FOUND with the error message on query failure", async () => {
    mockedGetRecordProof.mockRejectedValue(new Error("404: no such record"));
    renderAt("/record/pid-1");
    expect(await screen.findByText(/RECORD_NOT_FOUND/i)).toBeInTheDocument();
    expect(screen.getByText(/404: no such record/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /BACK_TO_VERIFY/i })).toHaveAttribute("href", "/");
  });

  it("renders the record detail view on success", async () => {
    mockedGetRecordProof.mockResolvedValue(FULL_RECORD);
    renderAt("/record/pid-1");
    expect(await screen.findByText(/RECORD_DETAIL/i)).toBeInTheDocument();
    expect(screen.getByText("pid-1")).toBeInTheDocument();
    expect(screen.getByText("rec-1")).toBeInTheDocument();
    expect(screen.getByText("shard-7")).toBeInTheDocument();
    expect(screen.getByText("root-bbb")).toBeInTheDocument();
    // Calls the API with the URL-param proof_id
    expect(mockedGetRecordProof).toHaveBeenCalledWith("pid-1");
  });

  it("omits Batch ID / Poseidon Root rows when absent", async () => {
    mockedGetRecordProof.mockResolvedValue(FULL_RECORD);
    renderAt("/record/pid-1");
    await screen.findByText(/RECORD_DETAIL/i);
    // VerdictCard renders keys as `KEY.toUpperCase().replace(/ /g, "_")` —
    // so the rendered labels are "BATCH_ID" / "POSEIDON_ROOT".
    expect(screen.queryByText(/BATCH_ID/)).not.toBeInTheDocument();
    expect(screen.queryByText(/POSEIDON_ROOT/)).not.toBeInTheDocument();
  });

  it("renders optional Batch ID + Poseidon Root rows when present", async () => {
    mockedGetRecordProof.mockResolvedValue({
      ...FULL_RECORD,
      batch_id: "batch-xyz",
      poseidon_root: "pose-root-zzz",
    });
    renderAt("/record/pid-1");
    expect(await screen.findByText(/BATCH_ID/)).toBeInTheDocument();
    expect(screen.getByText("batch-xyz")).toBeInTheDocument();
    expect(screen.getByText(/POSEIDON_ROOT/)).toBeInTheDocument();
    expect(screen.getByText("pose-root-zzz")).toBeInTheDocument();
  });

  it("renders the MERKLE_PROOF_DETAILS expander with the JSON body", async () => {
    mockedGetRecordProof.mockResolvedValue(FULL_RECORD);
    renderAt("/record/pid-1");
    await screen.findByText(/MERKLE_PROOF_DETAILS/);
    // The pre block is always in the DOM (the <details> just hides it
    // visually until opened); assert the JSON content is rendered.
    const pre = document.querySelector("pre");
    expect(pre?.textContent).toContain('"siblings"');
    expect(pre?.textContent).toContain('"s1"');
  });

  it("DOWNLOAD_PROOF_BUNDLE creates and revokes a blob URL", async () => {
    mockedGetRecordProof.mockResolvedValue(FULL_RECORD);
    const createObjectURL = vi.fn(() => "blob:fake");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });

    renderAt("/record/pid-1");
    const btn = await screen.findByRole("button", { name: /DOWNLOAD_PROOF_BUNDLE/i });
    btn.click();
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:fake");
  });
});
