import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getApiBase: vi.fn().mockResolvedValue("http://127.0.0.1:3737"),
}));
vi.mock("../lib/storage", () => ({
  apiKeyProblem: vi.fn(),
  getStoredApiKey: vi.fn(() => ""),
  normalizeApiKey: vi.fn((k: string) => k.trim()),
  setStoredApiKey: vi.fn(),
}));

import { apiKeyProblem, setStoredApiKey } from "../lib/storage";
import { useFileCommit } from "./useFileCommit";

const mockedApiKeyProblem = vi.mocked(apiKeyProblem);
const mockedSetStoredApiKey = vi.mocked(setStoredApiKey);

const VALID_KEY = "a".repeat(64);
const VALID_HASH = "ff".repeat(32);

interface TauriInternals {
  __TAURI_INTERNALS__?: unknown;
}

function makeFile(name = "doc.pdf", content = "data") {
  const f = new File([content], name, { type: "application/pdf" });
  return f;
}

beforeEach(() => {
  mockedApiKeyProblem.mockReturnValue(null);
  mockedSetStoredApiKey.mockReset();
  delete (window as unknown as TauriInternals).__TAURI_INTERNALS__;
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  delete (window as unknown as TauriInternals).__TAURI_INTERNALS__;
  vi.restoreAllMocks();
  // vi.stubGlobal isn't undone by restoreAllMocks — explicit unstub keeps
  // the global fetch mock from leaking into the next suite.
  vi.unstubAllGlobals();
});

describe("useFileCommit", () => {
  it("starts with empty state and idle commitStage", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    expect(result.current.droppedFile).toBeNull();
    expect(result.current.fileHash).toBeNull();
    expect(result.current.commitStage).toBe("idle");
    expect(result.current.commitError).toBeNull();
  });

  it("onFile stores the file and resets the verdict + commit-error state", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    const file = makeFile();
    act(() => result.current.onFile(file));
    expect(result.current.droppedFile).toBe(file);
    expect(setVerdict).toHaveBeenCalledWith(null);
  });

  it("onHash records the hash and bumps fileProgress to 100", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => result.current.onHash(VALID_HASH));
    expect(result.current.fileHash).toBe(VALID_HASH);
    expect(result.current.fileProgress).toBe(100);
  });

  it("setApiKey passes through to storage", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => result.current.setApiKey("oly_abc"));
    expect(result.current.apiKey).toBe("oly_abc");
    expect(mockedSetStoredApiKey).toHaveBeenCalledWith("oly_abc");
  });

  it("commitFile short-circuits when prerequisites are missing", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    await act(async () => {
      await result.current.commitFile();
    });
    // Nothing was set up — no commit attempt, stage stays idle.
    expect(result.current.commitStage).toBe("idle");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("commitFile bails when apiKeyProblem returns a message and lands in 'error' stage", async () => {
    mockedApiKeyProblem.mockReturnValue("invalid key shape");
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey("bad");
    });
    await act(async () => {
      await result.current.commitFile();
    });
    expect(result.current.commitStage).toBe("error");
    expect(result.current.commitError).toMatch(/invalid key shape/);
  });

  it("commitFile (browser path) POSTs FormData to /ingest/files and finishes in 'done'", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ content_hash: VALID_HASH }), { status: 200 }),
    );
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile("doc.pdf"));
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    await waitFor(() => expect(result.current.commitStage).toBe("done"));
    expect(submitHash).toHaveBeenCalledWith(VALID_HASH, "file");
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/ingest\/files$/);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeInstanceOf(FormData);
    const fd = init?.body as FormData;
    expect(fd.get("shard_id")).toBe("files");
    expect(fd.get("version")).toBe("1");
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe(VALID_KEY);
  });

  it("forwards original_hash in the FormData when a valid 64-hex original is set", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ content_hash: VALID_HASH }), { status: 200 }),
    );
    const originalHash = "b".repeat(64);
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
      result.current.setOriginalHash(originalHash);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    const fd = vi.mocked(fetch).mock.calls[0][1]?.body as FormData;
    expect(fd.get("original_hash")).toBe(originalHash);
  });

  it("omits original_hash when the value isn't a 64-char hex string", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ content_hash: VALID_HASH }), { status: 200 }),
    );
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
      result.current.setOriginalHash("not-a-hash");
    });
    await act(async () => {
      await result.current.commitFile();
    });
    const fd = vi.mocked(fetch).mock.calls[0][1]?.body as FormData;
    expect(fd.get("original_hash")).toBeNull();
  });

  it("401 from server is mapped to the canonical auth-error message (does NOT leak detail)", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: "key prefix xy- expired 3d ago" }), { status: 401 }),
    );
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    expect(result.current.commitStage).toBe("error");
    expect(result.current.commitError).toMatch(/Authentication failed/);
    // Audit M-UI-1: 401 detail MUST NOT leak through to UI state
    expect(result.current.commitError).not.toMatch(/key prefix/);
  });

  it("non-401 errors surface the server-supplied detail", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: "Shard quota exceeded" }), { status: 429 }),
    );
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    expect(result.current.commitError).toMatch(/Shard quota exceeded/);
  });

  it("server-vs-local hash mismatch trips the error stage", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ content_hash: "aa".repeat(32) }), { status: 200 }),
    );
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH); // ff..ff
      result.current.setApiKey(VALID_KEY);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    expect(result.current.commitStage).toBe("error");
    expect(result.current.commitError).toMatch(/disagrees with local/);
    expect(submitHash).not.toHaveBeenCalled();
  });

  it("missing content_hash in server response trips the error stage", async () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setApiKey(VALID_KEY);
    });
    await act(async () => {
      await result.current.commitFile();
    });
    expect(result.current.commitStage).toBe("error");
    expect(result.current.commitError).toMatch(/missing content_hash/);
  });

  it("resetCommit drops the commit state without touching file/hash", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
    });
    act(() => result.current.resetCommit());
    expect(result.current.commitStage).toBe("idle");
    expect(result.current.fileHash).toBe(VALID_HASH);
    expect(result.current.droppedFile).not.toBeNull();
  });

  it("reset clears file + hash + originalHash + commit state", () => {
    const setVerdict = vi.fn();
    const submitHash = vi.fn();
    const { result } = renderHook(() => useFileCommit(setVerdict, submitHash));
    act(() => {
      result.current.onFile(makeFile());
      result.current.onHash(VALID_HASH);
      result.current.setOriginalHash("anything");
    });
    act(() => result.current.reset());
    expect(result.current.droppedFile).toBeNull();
    expect(result.current.fileHash).toBeNull();
    expect(result.current.originalHash).toBe("");
    expect(result.current.commitStage).toBe("idle");
  });
});
