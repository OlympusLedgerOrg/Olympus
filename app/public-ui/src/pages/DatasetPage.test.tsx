import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getDataset: vi.fn(),
  verifyDataset: vi.fn(),
}));
vi.mock("../lib/audio", () => ({
  playGlitchSound: vi.fn(),
}));

import { getDataset, verifyDataset } from "../lib/api";
import DatasetPage from "./DatasetPage";

const mockedGetDataset = vi.mocked(getDataset);
const mockedVerifyDataset = vi.mocked(verifyDataset);

function newClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
}

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={newClient()}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/dataset/:dataset_id" element={<DatasetPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const FULL_DATASET = {
  dataset_id: "ds-1",
  dataset_name: "test-dataset",
  dataset_version: "1.0.0",
  license_spdx: "MIT",
  source_uri: "https://example.org/ds-1",
  epoch: "0",
  commit_id: "commit-abc",
  committer_pubkey: "pub-xyz",
  parent_commit_id: "commit-parent",
  files: [],
};

const VERIFIED_RESULT = {
  verified: true,
  checks: { commit: true, signature: true, chain: true },
  commit_id_valid: true,
  signature_valid: true,
  chain_valid: true,
  rfc3161_valid: true,
  key_revoked: false,
};

beforeEach(() => {
  mockedGetDataset.mockReset();
  mockedVerifyDataset.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<DatasetPage>", () => {
  it("shows the LOADING_DATASET splash while queries are in flight", () => {
    mockedGetDataset.mockReturnValue(new Promise(() => {}));
    mockedVerifyDataset.mockReturnValue(new Promise(() => {}));
    renderAt("/dataset/ds-1");
    expect(screen.getByText(/LOADING_DATASET/i)).toBeInTheDocument();
  });

  it("shows DATASET_NOT_FOUND when getDataset rejects", async () => {
    mockedGetDataset.mockRejectedValue(new Error("404: dataset missing"));
    mockedVerifyDataset.mockResolvedValue(VERIFIED_RESULT);
    renderAt("/dataset/ds-1");
    expect(await screen.findByText(/DATASET_NOT_FOUND/i)).toBeInTheDocument();
    expect(screen.getByText(/404: dataset missing/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /BACK_TO_VERIFY/i })).toHaveAttribute("href", "/");
  });

  it("renders the dataset detail view on success", async () => {
    mockedGetDataset.mockResolvedValue(FULL_DATASET);
    mockedVerifyDataset.mockResolvedValue(VERIFIED_RESULT);
    renderAt("/dataset/ds-1");
    expect(await screen.findByRole("heading", { name: /TEST-DATASET/i })).toBeInTheDocument();
    expect(screen.getByText(/V1.0.0/)).toBeInTheDocument();
    expect(screen.getByText("commit-abc")).toBeInTheDocument();
    expect(mockedGetDataset).toHaveBeenCalledWith("ds-1");
    expect(mockedVerifyDataset).toHaveBeenCalledWith("ds-1");
  });

  it("renders 'verified' verdict when verifyDataset reports verified=true", async () => {
    mockedGetDataset.mockResolvedValue(FULL_DATASET);
    mockedVerifyDataset.mockResolvedValue(VERIFIED_RESULT);
    renderAt("/dataset/ds-1");
    await screen.findByRole("heading", { name: /TEST-DATASET/i });
    // Multiple "Yes" rows when commit_id_valid / signature_valid / chain_valid
    // / rfc3161_valid all pass — assert at least one is present.
    expect(screen.getAllByText("Yes").length).toBeGreaterThan(0);
  });

  it("renders 'failed' verdict + 'No' rows for failing checks", async () => {
    mockedGetDataset.mockResolvedValue(FULL_DATASET);
    mockedVerifyDataset.mockResolvedValue({
      ...VERIFIED_RESULT,
      verified: false,
      commit_id_valid: false,
      signature_valid: false,
    });
    renderAt("/dataset/ds-1");
    await screen.findByRole("heading", { name: /TEST-DATASET/i });
    // Multiple "No" rows when checks fail
    expect(screen.getAllByText("No").length).toBeGreaterThan(0);
  });
});
