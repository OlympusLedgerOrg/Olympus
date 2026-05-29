import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  verifyHash: vi.fn(),
  verifyProofBundle: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  addRecentVerification: vi.fn(),
  getStoredApiKey: vi.fn(() => ""),
  setStoredApiKey: vi.fn(),
}));

import { verifyHash, verifyProofBundle } from "../lib/api";
import { addRecentVerification, setStoredApiKey } from "../lib/storage";
import { useHashVerification } from "./useHashVerification";

const mockedVerifyHash = vi.mocked(verifyHash);
const mockedVerifyProofBundle = vi.mocked(verifyProofBundle);
const mockedAddRecent = vi.mocked(addRecentVerification);
const mockedSetStoredApiKey = vi.mocked(setStoredApiKey);

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

const VALID_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const HASH_RESP = {
  proof_id: "pid",
  record_id: "rid",
  shard_id: "shard-0",
  content_hash: VALID_HASH,
  merkle_root: "root",
  merkle_proof: { siblings: ["s1"] },
  merkle_proof_valid: true,
  ledger_entry_hash: "leh",
  timestamp: "2026-05-28T00:00:00Z",
};

const PROOF_RESP_VERIFIED = {
  content_hash: VALID_HASH,
  status: "verified" as const,
  detail: "ok",
  known_to_server: true,
  snapshot_root: "sr",
  snapshot_index: 0,
  snapshot_size: 1,
  merkle_proof_valid: true,
  merkle_root: "root",
};

beforeEach(() => {
  mockedVerifyHash.mockReset();
  mockedVerifyProofBundle.mockReset();
  mockedAddRecent.mockReset();
  mockedSetStoredApiKey.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useHashVerification", () => {
  it("hashStatus moves through WAITING → length → BAD_HEX → READY", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    expect(result.current.hashStatus).toMatchObject({ label: "WAITING", tone: "neutral" });

    act(() => result.current.setHashInput("abc"));
    expect(result.current.hashStatus).toMatchObject({ label: "3/64", tone: "warn" });

    act(() => result.current.setHashInput("z".repeat(64)));
    expect(result.current.hashStatus).toMatchObject({ label: "BAD_HEX", tone: "err" });

    act(() => result.current.setHashInput(VALID_HASH));
    expect(result.current.hashStatus).toMatchObject({ label: "READY", tone: "ok" });
  });

  it("setApiKey writes through to storage", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.setApiKey("oly_abc"));
    expect(result.current.apiKey).toBe("oly_abc");
    expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_abc");
  });

  it("submitHash rejects an invalid hash format with the canonical error", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.submitHash("not-a-hash"));
    expect(result.current.hashError).toMatch(/valid 64-character hexadecimal/);
    expect(mockedVerifyHash).not.toHaveBeenCalled();
  });

  it("submitHash runs both calls, sets the upgraded snapshot verdict, and logs a recent entry", async () => {
    const setVerdict = vi.fn();
    mockedVerifyHash.mockResolvedValue(HASH_RESP);
    mockedVerifyProofBundle.mockResolvedValue(PROOF_RESP_VERIFIED);

    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.submitHash(VALID_HASH));

    await waitFor(() => expect(mockedVerifyHash).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockedVerifyProofBundle).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(setVerdict).toHaveBeenCalledWith(
        expect.objectContaining({ verdict: "verified", displayHash: VALID_HASH }),
      ),
    );
    expect(mockedAddRecent).toHaveBeenCalledWith(
      expect.objectContaining({ hash: VALID_HASH, type: "hash", verdict: "verified" }),
    );
  });

  it("404 from verifyHash maps to verdict='unknown' + recent-entry 'unknown'", async () => {
    const setVerdict = vi.fn();
    mockedVerifyHash.mockRejectedValue(new Error("HTTP 404: not found"));

    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.submitHash(VALID_HASH));

    await waitFor(() =>
      expect(setVerdict).toHaveBeenCalledWith(
        expect.objectContaining({ verdict: "unknown" }),
      ),
    );
    expect(mockedAddRecent).toHaveBeenCalledWith(
      expect.objectContaining({ verdict: "unknown" }),
    );
  });

  it("non-404 error from verifyHash sets hashError", async () => {
    const setVerdict = vi.fn();
    mockedVerifyHash.mockRejectedValue(new Error("server down"));

    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.submitHash(VALID_HASH));

    await waitFor(() => expect(result.current.hashError).toBe("server down"));
  });

  it("snapshot endpoint failure falls back to GET-only verdict + recent entry", async () => {
    const setVerdict = vi.fn();
    mockedVerifyHash.mockResolvedValue(HASH_RESP);
    mockedVerifyProofBundle.mockRejectedValue(new Error("snapshot endpoint down"));

    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => result.current.submitHash(VALID_HASH));

    // Verdict from the GET path still posts; a recent-entry is logged using
    // the GET-only verdict.
    await waitFor(() => expect(mockedAddRecent).toHaveBeenCalled());
    expect(mockedAddRecent.mock.calls.at(-1)![0]).toMatchObject({ hash: VALID_HASH });
  });

  it("pasteHash reads from navigator.clipboard and trims the value into the hash input", async () => {
    const readText = vi.fn().mockResolvedValue(`  ${VALID_HASH}  `);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText },
    });
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });

    await act(async () => {
      await result.current.pasteHash();
    });
    expect(result.current.hashInput).toBe(VALID_HASH);
  });

  it("pasteHash surfaces a hashError when the browser blocks clipboard reads", async () => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText: vi.fn().mockRejectedValue(new Error("blocked")) },
    });
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });

    await act(async () => {
      await result.current.pasteHash();
    });
    expect(result.current.hashError).toMatch(/Clipboard read was blocked/);
  });

  it("reset clears the input and the error", () => {
    const setVerdict = vi.fn();
    const { result } = renderHook(() => useHashVerification(setVerdict), { wrapper });
    act(() => {
      result.current.setHashInput("anything");
      result.current.setHashError("oops");
    });
    act(() => result.current.reset());
    expect(result.current.hashInput).toBe("");
    expect(result.current.hashError).toBeNull();
  });
});
