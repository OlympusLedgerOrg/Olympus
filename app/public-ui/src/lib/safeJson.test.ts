import { afterEach, describe, expect, it, vi } from "vitest";
import { safeJsonFetch } from "./safeJson";

afterEach(() => {
  vi.restoreAllMocks();
});

function mockFetchOnce(body: string, init: ResponseInit = {}) {
  const response = new Response(body, { status: 200, ...init });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
}

describe("safeJsonFetch", () => {
  it("parses a JSON object body", async () => {
    mockFetchOnce(`{"x":1}`);
    const result = await safeJsonFetch<{ x: number }>("/whatever");
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ x: 1 });
  });

  it("parses a JSON array body", async () => {
    mockFetchOnce(`[1,2,3]`);
    const result = await safeJsonFetch<number[]>("/x");
    expect(result.data).toEqual([1, 2, 3]);
  });

  it("returns data=null when the body is HTML (Tauri asset 404)", async () => {
    mockFetchOnce(`<!DOCTYPE html><html></html>`, { status: 404 });
    const result = await safeJsonFetch("/auth/register");
    expect(result.ok).toBe(false);
    expect(result.status).toBe(404);
    expect(result.data).toBeNull();
    expect(result.text).toContain("<!DOCTYPE html>");
  });

  it("returns data=null when JSON is malformed but starts with { ", async () => {
    mockFetchOnce(`{not really json`);
    const result = await safeJsonFetch("/x");
    expect(result.data).toBeNull();
  });

  it("returns status=0 on network-level failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")));
    const result = await safeJsonFetch("/x");
    expect(result.ok).toBe(false);
    expect(result.status).toBe(0);
    expect(result.data).toBeNull();
    expect(result.text).toMatch(/fetch failed/);
  });

  it("ignores leading whitespace when sniffing JSON", async () => {
    mockFetchOnce(`   \n{"a":2}`);
    const result = await safeJsonFetch<{ a: number }>("/x");
    expect(result.data).toEqual({ a: 2 });
  });
});
