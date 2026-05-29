import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  verifyProofBundle: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  addRecentVerification: vi.fn(),
}));

import { verifyProofBundle } from "../lib/api";
import { addRecentVerification } from "../lib/storage";
import { useProofVerification } from "./useProofVerification";

const mockedVerifyProofBundle = vi.mocked(verifyProofBundle);
const mockedAddRecentVerification = vi.mocked(addRecentVerification);

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

const VALID_BUNDLE_JSON = JSON.stringify({
  content_hash: "ch",
  merkle_root: "root",
  merkle_proof: { siblings: [] },
});

beforeEach(() => {
  mockedVerifyProofBundle.mockReset();
  mockedAddRecentVerification.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useProofVerification", () => {
  it("starts with empty input and no error", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    expect(result.current.proofInput).toBe("");
    expect(result.current.proofError).toBeNull();
  });

  it("sets a parse error for invalid JSON without firing the mutation", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    act(() => result.current.setProofInput("not-json"));
    act(() => result.current.submitProof());
    expect(result.current.proofError).toMatch(/Invalid JSON/);
    expect(mockedVerifyProofBundle).not.toHaveBeenCalled();
  });

  it("rejects bundles missing required fields", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    act(() => result.current.setProofInput(JSON.stringify({ content_hash: "ch" })));
    act(() => result.current.submitProof());
    expect(result.current.proofError).toMatch(/must include content_hash, merkle_root/);
    expect(mockedVerifyProofBundle).not.toHaveBeenCalled();
  });

  it("submits a valid bundle, sets the verdict, and adds a recent-verification entry", async () => {
    const setVerdict = vi.fn();
    mockedVerifyProofBundle.mockResolvedValue({
      content_hash: "ch",
      status: "verified",
      detail: "ok",
      known_to_server: true,
      snapshot_root: "sr",
      snapshot_index: 0,
      snapshot_size: 1,
      merkle_proof_valid: true,
      merkle_root: "root",
    });

    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    act(() => result.current.setProofInput(VALID_BUNDLE_JSON));
    act(() => result.current.submitProof());

    await waitFor(() => expect(mockedVerifyProofBundle).toHaveBeenCalledTimes(1));
    expect(mockedVerifyProofBundle.mock.calls[0][0]).toMatchObject({ content_hash: "ch" });

    await waitFor(() => expect(setVerdict).toHaveBeenCalled());
    const verdictArg = setVerdict.mock.calls.at(-1)![0];
    expect(verdictArg.verdict).toBe("verified");
    expect(verdictArg.displayHash).toBe("ch");

    expect(mockedAddRecentVerification).toHaveBeenCalledWith(
      expect.objectContaining({ hash: "ch", type: "proof", verdict: "verified" }),
    );
  });

  it("sets proofError when the mutation rejects", async () => {
    const setVerdict = vi.fn();
    mockedVerifyProofBundle.mockRejectedValue(new Error("backend down"));

    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    act(() => result.current.setProofInput(VALID_BUNDLE_JSON));
    act(() => result.current.submitProof());

    await waitFor(() => expect(result.current.proofError).toBe("backend down"));
  });

  it("reset clears the input and error", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useProofVerification(setVerdict), { wrapper });
    act(() => {
      result.current.setProofInput("blah");
      result.current.setProofError("oops");
    });
    act(() => result.current.reset());
    expect(result.current.proofInput).toBe("");
    expect(result.current.proofError).toBeNull();
  });
});
