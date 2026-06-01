/**
 * Tests for lib/blake3.ts. Mocks the underlying blake3-wasm package so
 * the control flow in this file (ensureInit caching + CSP error mapping,
 * all-zero ABI guards, hasher.free() cleanup) runs without loading the
 * actual WASM binary — jsdom can't instantiate it, and even if it could,
 * the surface under test is the JS wrapper, not the BLAKE3 algorithm.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// All three things blake3.ts imports from blake3-wasm must be mocked at
// module level (the source binds them at import time with `import init,
// { hash, create_hasher } from "..."`). Each test can rebind the mock
// behaviour via mockImplementation / mockResolvedValue per case.
const mockInit = vi.fn();
const mockHash = vi.fn();
const mockCreateHasher = vi.fn();

vi.mock("blake3-wasm/dist/wasm/web/blake3_js", () => ({
  default: mockInit,
  hash: mockHash,
  create_hasher: mockCreateHasher,
}));
vi.mock("blake3-wasm/dist/wasm/web/blake3_js_bg.wasm?url", () => ({
  default: "blob:fake-wasm-url",
}));

beforeEach(async () => {
  mockInit.mockReset();
  mockHash.mockReset();
  mockCreateHasher.mockReset();
  // ensureInit caches the resolved init promise in module state. Each test
  // needs a fresh module instance so a previously-rejected promise (CSP
  // path) doesn't survive into the next test's success path.
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ensureInit / checkWasmAvailable", () => {
  it("resolves once on success and caches the init promise", async () => {
    mockInit.mockResolvedValue(undefined);
    const { checkWasmAvailable } = await import("./blake3");
    await checkWasmAvailable();
    await checkWasmAvailable();
    // Init called exactly once across both calls — the second checkWasmAvailable
    // reuses the cached promise.
    expect(mockInit).toHaveBeenCalledTimes(1);
    // Passes the WASM URL through to the underlying init.
    expect(mockInit).toHaveBeenCalledWith("blob:fake-wasm-url");
  });

  it("maps a CSP rejection to the user-friendly message", async () => {
    mockInit.mockRejectedValue(new Error("compile error: disallowed by embedder"));
    const { checkWasmAvailable } = await import("./blake3");
    await expect(checkWasmAvailable()).rejects.toThrow(/Content Security Policy/);
  });

  it("recognises 'wasm-unsafe-eval' rejections as CSP", async () => {
    mockInit.mockRejectedValue(new Error("CompileError: wasm-unsafe-eval blocked"));
    const { checkWasmAvailable } = await import("./blake3");
    await expect(checkWasmAvailable()).rejects.toThrow(/Content Security Policy/);
  });

  it("falls back to the generic 'failed to initialize' message for unknown rejections", async () => {
    mockInit.mockRejectedValue(new Error("network timeout fetching wasm"));
    const { checkWasmAvailable } = await import("./blake3");
    await expect(checkWasmAvailable()).rejects.toThrow(
      /BLAKE3 WASM failed to initialize: network timeout/,
    );
  });

  it("clears the cached promise after a rejection so a retry can succeed", async () => {
    mockInit
      .mockRejectedValueOnce(new Error("transient init failure"))
      .mockResolvedValueOnce(undefined);
    const { checkWasmAvailable } = await import("./blake3");
    await expect(checkWasmAvailable()).rejects.toThrow();
    // Second call should retry (cached failure promise was cleared).
    await checkWasmAvailable();
    expect(mockInit).toHaveBeenCalledTimes(2);
  });

  it("stringifies non-Error rejections in the generic branch", async () => {
    mockInit.mockRejectedValue("plain string error");
    const { checkWasmAvailable } = await import("./blake3");
    await expect(checkWasmAvailable()).rejects.toThrow(
      /BLAKE3 WASM failed to initialize: plain string error/,
    );
  });
});

describe("hashBytes", () => {
  it("returns the lowercase hex digest of the 32-byte output buffer", async () => {
    mockInit.mockResolvedValue(undefined);
    // Simulate a real BLAKE3: write a predictable digest into the out buffer.
    mockHash.mockImplementation((_data: Uint8Array, out: Uint8Array) => {
      for (let i = 0; i < 32; i++) out[i] = i;
    });
    const { hashBytes } = await import("./blake3");
    const hex = await hashBytes(new Uint8Array([1, 2, 3]));
    // 0x00 0x01 … 0x1f → "000102…1e1f"
    expect(hex).toBe(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    expect(mockHash).toHaveBeenCalledTimes(1);
  });

  it("trips the all-zero ABI guard when the WASM leaves the out buffer untouched", async () => {
    mockInit.mockResolvedValue(undefined);
    // The mock does nothing — `out` stays all-zero. Source must throw.
    mockHash.mockImplementation(() => {
      /* simulate ABI mismatch: out is never written */
    });
    const { hashBytes } = await import("./blake3");
    await expect(hashBytes(new Uint8Array([1]))).rejects.toThrow(
      /all-zero digest.*ABI mismatch/,
    );
  });
});

describe("hashFile", () => {
  function makeHasher() {
    return {
      update: vi.fn(),
      digest: vi.fn((out: Uint8Array) => {
        for (let i = 0; i < 32; i++) out[i] = 0xab;
      }),
      free: vi.fn(),
    };
  }

  it("handles a zero-byte file via the single-shot hash path (not the streaming hasher)", async () => {
    mockInit.mockResolvedValue(undefined);
    mockHash.mockImplementation((_data: Uint8Array, out: Uint8Array) => {
      out[0] = 0xff; // non-zero to satisfy the ABI guard
    });
    const onProgress = vi.fn();
    const { hashFile } = await import("./blake3");
    const empty = new File([], "empty.bin");
    const hex = await hashFile(empty, onProgress);
    expect(mockCreateHasher).not.toHaveBeenCalled();
    expect(mockHash).toHaveBeenCalled();
    expect(onProgress).toHaveBeenCalledWith(100);
    expect(hex).toMatch(/^ff/);
  });

  it("trips the all-zero ABI guard on the empty-file path", async () => {
    mockInit.mockResolvedValue(undefined);
    mockHash.mockImplementation(() => {
      /* leave out all-zero */
    });
    const { hashFile } = await import("./blake3");
    await expect(hashFile(new File([], "empty.bin"))).rejects.toThrow(
      /all-zero digest/,
    );
  });

  it("streams a non-empty file in chunks, reports progress, and calls hasher.free() on success", async () => {
    mockInit.mockResolvedValue(undefined);
    const hasher = makeHasher();
    mockCreateHasher.mockReturnValue(hasher);

    const onProgress = vi.fn();
    const { hashFile } = await import("./blake3");
    // 8 MB file → exactly two 4 MB chunks → two `update` calls + two
    // progress callbacks (50%, then 100%).
    const big = new File([new Uint8Array(8 * 1024 * 1024)], "big.bin");
    const hex = await hashFile(big, onProgress);

    expect(hasher.update).toHaveBeenCalledTimes(2);
    expect(hasher.digest).toHaveBeenCalledTimes(1);
    expect(hasher.free).toHaveBeenCalledTimes(1);
    expect(onProgress).toHaveBeenCalledWith(50);
    expect(onProgress).toHaveBeenCalledWith(100);
    // digest fills out with 0xab; 32 bytes = "ab" × 32
    expect(hex).toBe("ab".repeat(32));
  });

  it("calls hasher.free() even when digest() trips the all-zero ABI guard (try/finally)", async () => {
    mockInit.mockResolvedValue(undefined);
    const hasher = makeHasher();
    hasher.digest = vi.fn(() => {
      /* leave out all-zero → guard throws */
    });
    mockCreateHasher.mockReturnValue(hasher);

    const { hashFile } = await import("./blake3");
    const big = new File([new Uint8Array(4 * 1024 * 1024)], "big.bin");
    await expect(hashFile(big)).rejects.toThrow(/all-zero digest/);
    // Cleanup MUST run even on the throw path — WASM memory leak otherwise.
    expect(hasher.free).toHaveBeenCalledTimes(1);
  });

  it("calls hasher.free() when an exception during update propagates", async () => {
    mockInit.mockResolvedValue(undefined);
    const hasher = makeHasher();
    hasher.update = vi.fn(() => {
      throw new Error("update failed");
    });
    mockCreateHasher.mockReturnValue(hasher);

    const { hashFile } = await import("./blake3");
    const big = new File([new Uint8Array(4 * 1024 * 1024)], "big.bin");
    await expect(hashFile(big)).rejects.toThrow(/update failed/);
    expect(hasher.free).toHaveBeenCalledTimes(1);
  });
});
