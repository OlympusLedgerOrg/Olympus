import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/blake3", () => ({
  hashBytes: vi.fn(),
}));
vi.mock("../lib/api", () => ({
  getApiBase: vi.fn().mockResolvedValue("http://127.0.0.1:3737"),
}));

import { hashBytes } from "../lib/blake3";
import { useRedactionLink } from "./useRedactionLink";

const mockedHashBytes = vi.mocked(hashBytes);

function makeFile(name = "doc.pdf", content = "abcdefgh") {
  return new File([content], name, { type: "application/pdf" });
}

beforeEach(() => {
  mockedHashBytes.mockReset();
  // Default: produce deterministic per-call hashes.
  let n = 0;
  mockedHashBytes.mockImplementation(async () => `hash-${++n}`);
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useRedactionLink", () => {
  it("starts in idle stage with empty inputs", () => {
    const { result } = renderHook(() => useRedactionLink(null));
    expect(result.current.stage).toBe("idle");
    expect(result.current.originalFile).toBeNull();
    expect(result.current.originalHash).toBe("");
    expect(result.current.commitId).toBe("");
    expect(result.current.result).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("onStart transitions to awaiting_original and clears state", () => {
    const { result } = renderHook(() => useRedactionLink(null));
    act(() => {
      result.current.setCommitId("stale");
    });
    act(() => result.current.onStart());
    expect(result.current.stage).toBe("awaiting_original");
    expect(result.current.commitId).toBe("");
  });

  it("onOriginalFile hashes the file and transitions to 'ready'", async () => {
    const { result } = renderHook(() => useRedactionLink(null));
    await act(async () => {
      await result.current.onOriginalFile(makeFile());
    });
    expect(result.current.stage).toBe("ready");
    expect(result.current.originalHash).toMatch(/^hash-\d+$/);
    expect(result.current.originalFile).not.toBeNull();
  });

  it("onOriginalFile surfaces a hash error and lands in 'error' stage", async () => {
    mockedHashBytes.mockReset();
    mockedHashBytes.mockRejectedValueOnce(new Error("blake3 wasm blocked"));
    const { result } = renderHook(() => useRedactionLink(null));
    await act(async () => {
      await result.current.onOriginalFile(makeFile());
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/blake3 wasm blocked/);
  });

  it("onLink short-circuits when prerequisites are missing", async () => {
    const { result } = renderHook(() => useRedactionLink(null));
    await act(async () => {
      await result.current.onLink();
    });
    // No fetch attempt, no stage advance.
    expect(result.current.stage).toBe("idle");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("onLink (happy path) posts chunked hashes + commit id and lands in 'done'", async () => {
    const linkResp = {
      original_commit_id: "commit-1",
      original_blake3: "ob",
      original_root: "or",
      redacted_commitment: "rc",
      reveal_mask_commitment: "rmc",
      reveal_mask: [1, 0, 1],
      revealed_count: 2,
      redacted_count: 1,
      verified: true,
      note: "ok",
    };
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify(linkResp), { status: 200 }),
    );
    const redacted = makeFile("redacted.pdf", "x".repeat(128));
    const { result } = renderHook(() => useRedactionLink(redacted));
    await act(async () => {
      await result.current.onOriginalFile(makeFile("orig.pdf", "y".repeat(128)));
    });
    act(() => result.current.setCommitId("commit-1"));
    await act(async () => {
      await result.current.onLink();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.result).toEqual(linkResp);

    // POST body assertions
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/redaction\/link$/);
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body.original_commit_id).toBe("commit-1");
    expect(Array.isArray(body.original_chunks)).toBe(true);
    expect(Array.isArray(body.redacted_chunks)).toBe(true);
    expect(body.original_chunks.length).toBe(64);
    expect(body.redacted_chunks.length).toBe(64);
  });

  it("onLink surfaces server error detail when the response is not ok", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: "commit not found" }), { status: 404 }),
    );
    const { result } = renderHook(() => useRedactionLink(makeFile()));
    await act(async () => {
      await result.current.onOriginalFile(makeFile());
    });
    act(() => result.current.setCommitId("c"));
    await act(async () => {
      await result.current.onLink();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toBe("commit not found");
  });

  it("onLink falls back to 'Server error N' when the error body has no detail", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("", { status: 500 }));
    const { result } = renderHook(() => useRedactionLink(makeFile()));
    await act(async () => {
      await result.current.onOriginalFile(makeFile());
    });
    act(() => result.current.setCommitId("c"));
    await act(async () => {
      await result.current.onLink();
    });
    expect(result.current.error).toMatch(/Server error 500/);
  });

  it("onLink rejects an HTML body (asset server not ready)", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("<!DOCTYPE html>", { status: 200 }),
    );
    const { result } = renderHook(() => useRedactionLink(makeFile()));
    await act(async () => {
      await result.current.onOriginalFile(makeFile());
    });
    act(() => result.current.setCommitId("c"));
    await act(async () => {
      await result.current.onLink();
    });
    expect(result.current.error).toMatch(/Server not ready/);
  });

  it("onReset returns to idle and clears all state", () => {
    const { result } = renderHook(() => useRedactionLink(null));
    act(() => result.current.setCommitId("c"));
    act(() => result.current.onReset());
    expect(result.current.stage).toBe("idle");
    expect(result.current.commitId).toBe("");
    expect(result.current.originalFile).toBeNull();
  });
});
