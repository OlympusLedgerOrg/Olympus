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

const VALID_KEY = "a".repeat(64);
const ENTRY = (hash: string, status: "verified" | "failed" = "verified"): RecentVerificationEntry => ({
  hash,
  status,
  timestamp: Date.now(),
});

beforeEach(() => {
  localStorage.clear();
  clearStoredApiKey();
  clearStoredAdminKey();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("normalizeApiKey", () => {
  it("strips the oly_ prefix and whitespace", () => {
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
  it("complains about a too-short key", () => {
    expect(apiKeyProblem("oly_abc123")).toMatch(/64-character hex/);
  });
  it("complains about non-hex characters", () => {
    expect(apiKeyProblem("z".repeat(64))).toMatch(/64-character hex/);
  });
});

describe("API key in-memory storage", () => {
  it("round-trips a valid key", () => {
    setStoredApiKey(`oly_${VALID_KEY}`);
    expect(getStoredApiKey()).toBe(VALID_KEY);
  });
  it("refuses to store an invalid key (silently drops)", () => {
    setStoredApiKey("not-a-key");
    expect(getStoredApiKey()).toBe("");
  });
  it("clear removes the key", () => {
    setStoredApiKey(VALID_KEY);
    clearStoredApiKey();
    expect(getStoredApiKey()).toBe("");
  });
  it("never writes to localStorage", () => {
    setStoredApiKey(VALID_KEY);
    expect(localStorage.getItem("olympus_api_key")).toBeNull();
    expect(Object.keys(localStorage)).toHaveLength(0);
  });
});

describe("admin key in-memory storage", () => {
  it("round-trips a trimmed value", () => {
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
    expect(list[0].status).toBe("failed");
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
