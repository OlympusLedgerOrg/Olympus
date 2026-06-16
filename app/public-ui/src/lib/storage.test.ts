import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  addRecentVerification,
  apiKeyProblem,
  clearRecentVerifications,
  clearStoredAdminKey,
  clearStoredApiKey,
  getRecentVerifications,
  getStoredAdminKey,
  getStoredApiKey,
  hasStoredAdminKey,
  normalizeApiKey,
  setStoredAdminKey,
  setStoredApiKey,
} from "./storage";
import type { RecentVerificationEntry } from "./types";

// The keychain helpers dynamically `await import("@tauri-apps/api/core")`
// inside a fire-and-forget `void ...` chain, so the `invoke` call lands a tick
// after the synchronous helper returns. A macrotask boundary (setTimeout 0)
// reliably drains the dynamic-import + promise chain so assertions see the
// call — microtask flushing alone is not enough for the async `import()`.
const flushMicrotasks = async (): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, 0));
};

const VALID_KEY = "a".repeat(64);
const ENTRY = (
  hash: string,
  verdict: RecentVerificationEntry["verdict"] = "verified",
): RecentVerificationEntry => ({
  hash,
  type: "hash",
  verdict,
  timestamp: Date.now(),
});

// ─── Surface (1): pure / in-memory helpers (no Tauri needed) ─────────────────
// These use the static import; module state (inMemoryApiKey / inMemoryAdminKey)
// is reset between tests via the clear* helpers in beforeEach.
beforeEach(() => {
  localStorage.clear();
  clearStoredApiKey();
  clearStoredAdminKey();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("normalizeApiKey", () => {
  it("strips the oly_ prefix and surrounding whitespace", () => {
    expect(normalizeApiKey(`  oly_${VALID_KEY}  `)).toBe(VALID_KEY);
  });
  it("accepts a bare 64-hex key unchanged", () => {
    expect(normalizeApiKey(VALID_KEY)).toBe(VALID_KEY);
  });
  it("strips embedded whitespace operators paste from terminals", () => {
    expect(normalizeApiKey(`oly_${VALID_KEY.slice(0, 32)} ${VALID_KEY.slice(32)}`)).toBe(VALID_KEY);
  });
  it("case-insensitively strips OLY_ prefix", () => {
    expect(normalizeApiKey(`OLY_${VALID_KEY}`)).toBe(VALID_KEY);
  });
});

describe("apiKeyProblem", () => {
  it("returns null for a valid 64-hex key", () => {
    expect(apiKeyProblem(VALID_KEY)).toBeNull();
  });
  it("returns null for a valid prefixed key", () => {
    expect(apiKeyProblem(`oly_${VALID_KEY}`)).toBeNull();
  });
  it("complains about an empty paste", () => {
    expect(apiKeyProblem("")).toMatch(/paste a real api key/i);
  });
  it("treats whitespace-only input as empty", () => {
    expect(apiKeyProblem("   ")).toMatch(/paste a real api key/i);
  });
  it("complains about a too-short key", () => {
    expect(apiKeyProblem("oly_abc123")).toMatch(/64-character hex/);
  });
  it("complains about non-hex characters", () => {
    expect(apiKeyProblem("z".repeat(64))).toMatch(/64-character hex/);
  });
});

describe("API key in-memory storage", () => {
  it("round-trips a valid key (normalized)", () => {
    setStoredApiKey(`oly_${VALID_KEY}`);
    expect(getStoredApiKey()).toBe(VALID_KEY);
  });
  it("refuses to store an invalid key (silently drops)", () => {
    setStoredApiKey("not-a-key");
    expect(getStoredApiKey()).toBe("");
  });
  it("returns empty when nothing has been stored", () => {
    expect(getStoredApiKey()).toBe("");
  });
  it("clear removes the key", () => {
    setStoredApiKey(VALID_KEY);
    clearStoredApiKey();
    expect(getStoredApiKey()).toBe("");
  });
  it("repairs a stored key with stray whitespace on read", () => {
    // setStoredApiKey normalizes on the way in, so to exercise the
    // getStoredApiKey repair branch (normalized !== raw) we feed a value with
    // internal whitespace. normalizeApiKey collapses it; the result is valid
    // and the stored slot is rewritten to the normalized form.
    setStoredApiKey(`${VALID_KEY.slice(0, 32)} ${VALID_KEY.slice(32)}`);
    expect(getStoredApiKey()).toBe(VALID_KEY);
    // Idempotent on a second read (now stored already-normalized → no rewrite).
    expect(getStoredApiKey()).toBe(VALID_KEY);
  });
  it("evicts a key that is set then invalidated", () => {
    setStoredApiKey(VALID_KEY);
    expect(getStoredApiKey()).toBe(VALID_KEY);
    setStoredApiKey(""); // invalid → clears the slot
    expect(getStoredApiKey()).toBe("");
  });
  it("never writes to localStorage", () => {
    setStoredApiKey(VALID_KEY);
    expect(localStorage.getItem("olympus_api_key")).toBeNull();
    expect(Object.keys(localStorage)).toHaveLength(0);
  });
});

describe("admin key in-memory storage", () => {
  it("round-trips a trimmed value and reflects presence", () => {
    expect(hasStoredAdminKey()).toBe(false);
    setStoredAdminKey("  admin-secret  ");
    expect(getStoredAdminKey()).toBe("admin-secret");
    expect(hasStoredAdminKey()).toBe(true);
  });
  it("treats empty/whitespace as unset", () => {
    setStoredAdminKey("   ");
    expect(getStoredAdminKey()).toBe("");
    expect(hasStoredAdminKey()).toBe(false);
  });
  it("clear empties the slot", () => {
    setStoredAdminKey("x");
    clearStoredAdminKey();
    expect(getStoredAdminKey()).toBe("");
    expect(hasStoredAdminKey()).toBe(false);
  });
  it("never writes to localStorage", () => {
    setStoredAdminKey("x");
    expect(Object.keys(localStorage)).toHaveLength(0);
  });
});

describe("recent verifications (localStorage)", () => {
  it("returns [] when storage is empty", () => {
    expect(getRecentVerifications()).toEqual([]);
  });

  it("prepends new entries newest-first", () => {
    addRecentVerification(ENTRY("a"));
    addRecentVerification(ENTRY("b"));
    const list = getRecentVerifications();
    expect(list.map((e) => e.hash)).toEqual(["b", "a"]);
  });

  it("deduplicates by hash, keeping the new entry", () => {
    addRecentVerification(ENTRY("a", "verified"));
    addRecentVerification(ENTRY("a", "failed"));
    const list = getRecentVerifications();
    expect(list).toHaveLength(1);
    expect(list[0].verdict).toBe("failed");
  });

  it("caps the list at 20 entries", () => {
    for (let i = 0; i < 25; i++) addRecentVerification(ENTRY(`h${i}`));
    expect(getRecentVerifications()).toHaveLength(20);
  });

  it("clear empties storage and fires a storage event", () => {
    addRecentVerification(ENTRY("a"));
    const listener = vi.fn();
    window.addEventListener("storage", listener);
    clearRecentVerifications();
    expect(getRecentVerifications()).toEqual([]);
    expect(listener).toHaveBeenCalled();
  });

  it("survives malformed JSON in storage", () => {
    localStorage.setItem("olympus_recent_verifications", "{not json");
    expect(getRecentVerifications()).toEqual([]);
  });
});

// ─── Surface (2): OS-keychain helpers (Tauri-gated by module-load const) ─────
//
// `_isTauriEnv` is computed once at module-load time from
// `window.__TAURI_INTERNALS__`, so each scenario must set/clear the global
// BEFORE importing a fresh module instance (vi.resetModules + dynamic import).
describe("keychain helpers (Tauri-gated)", () => {
  afterEach(() => {
    delete (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window
      .__TAURI_INTERNALS__;
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it("keychain helpers no-op when not in Tauri", async () => {
    vi.resetModules();
    delete (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window
      .__TAURI_INTERNALS__;
    const invoke = vi.fn();
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    await s.initApiKeyFromKeychain();
    s.persistApiKeyToKeychain();
    s.clearStoredApiKeyAndKeychain();
    await flushMicrotasks();
    expect(invoke).not.toHaveBeenCalled();
    vi.doUnmock("@tauri-apps/api/core");
  });

  it("keychain helpers round-trip in Tauri", async () => {
    vi.resetModules();
    (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window.__TAURI_INTERNALS__ = {};
    const VALID = "ab".repeat(32);
    const invoke = vi.fn(async (cmd: string) => (cmd === "keychain_get" ? VALID : undefined));
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    await s.initApiKeyFromKeychain();
    expect(invoke).toHaveBeenCalledWith("keychain_get", { key: "api_key" });
    expect(s.getStoredApiKey()).toBe(VALID); // loaded into memory
    // persist/clear are fire-and-forget: they `void keychainInvoke(...)` which
    // dynamically `await import`s the core module, so the invoke lands a few
    // microtasks later. Flush the queue before asserting.
    s.persistApiKeyToKeychain();
    await flushMicrotasks();
    expect(invoke).toHaveBeenCalledWith("keychain_set", { key: "api_key", value: VALID });
    s.clearStoredApiKeyAndKeychain();
    await flushMicrotasks();
    expect(invoke).toHaveBeenCalledWith("keychain_delete", { key: "api_key" });
    expect(s.getStoredApiKey()).toBe("");
    delete (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window
      .__TAURI_INTERNALS__;
    vi.doUnmock("@tauri-apps/api/core");
  });

  it("initApiKeyFromKeychain ignores an INVALID stored key", async () => {
    vi.resetModules();
    (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window.__TAURI_INTERNALS__ = {};
    const invoke = vi.fn(async (cmd: string) => (cmd === "keychain_get" ? "not-hex" : undefined));
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    await s.initApiKeyFromKeychain();
    expect(invoke).toHaveBeenCalledWith("keychain_get", { key: "api_key" });
    expect(s.getStoredApiKey()).toBe("");
    vi.doUnmock("@tauri-apps/api/core");
  });

  it("initApiKeyFromKeychain handles a null/empty stored key", async () => {
    vi.resetModules();
    (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window.__TAURI_INTERNALS__ = {};
    const invoke = vi.fn(async () => null);
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    await s.initApiKeyFromKeychain();
    expect(invoke).toHaveBeenCalledWith("keychain_get", { key: "api_key" });
    expect(s.getStoredApiKey()).toBe("");
    vi.doUnmock("@tauri-apps/api/core");
  });

  it("initApiKeyFromKeychain swallows a thrown invoke", async () => {
    vi.resetModules();
    (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window.__TAURI_INTERNALS__ = {};
    const invoke = vi.fn(async () => {
      throw new Error("keychain unavailable");
    });
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    await expect(s.initApiKeyFromKeychain()).resolves.toBeUndefined();
    expect(s.getStoredApiKey()).toBe("");
    vi.doUnmock("@tauri-apps/api/core");
  });

  it("persistApiKeyToKeychain is a no-op when no in-memory key is set", async () => {
    vi.resetModules();
    (globalThis as { window: { __TAURI_INTERNALS__?: unknown } }).window.__TAURI_INTERNALS__ = {};
    const invoke = vi.fn(async () => undefined);
    vi.doMock("@tauri-apps/api/core", () => ({ invoke }));
    const s = await import("./storage");
    // No key has been set → keychain_set must not be invoked.
    s.persistApiKeyToKeychain();
    await flushMicrotasks();
    expect(invoke).not.toHaveBeenCalledWith("keychain_set", expect.anything());
    vi.doUnmock("@tauri-apps/api/core");
  });
});
