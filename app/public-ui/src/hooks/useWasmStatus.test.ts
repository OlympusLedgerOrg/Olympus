import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/blake3", () => ({
  checkWasmAvailable: vi.fn(),
}));

import { checkWasmAvailable } from "../lib/blake3";
import { useWasmStatus } from "./useWasmStatus";

afterEach(() => {
  vi.resetAllMocks();
});

describe("useWasmStatus", () => {
  it("starts in 'loading' and transitions to 'ready' on success", async () => {
    vi.mocked(checkWasmAvailable).mockResolvedValue(undefined);
    const { result } = renderHook(() => useWasmStatus());
    expect(result.current.wasmStatus).toBe("loading");
    await waitFor(() => expect(result.current.wasmStatus).toBe("ready"));
    expect(result.current.wasmError).toBeNull();
  });

  it("captures Error message on failure", async () => {
    vi.mocked(checkWasmAvailable).mockRejectedValue(new Error("CSP blocked wasm"));
    const { result } = renderHook(() => useWasmStatus());
    await waitFor(() => expect(result.current.wasmStatus).toBe("error"));
    expect(result.current.wasmError).toBe("CSP blocked wasm");
  });

  it("stringifies non-Error rejections", async () => {
    vi.mocked(checkWasmAvailable).mockRejectedValue("string-only-rejection");
    const { result } = renderHook(() => useWasmStatus());
    await waitFor(() => expect(result.current.wasmStatus).toBe("error"));
    expect(result.current.wasmError).toBe("string-only-rejection");
  });
});
