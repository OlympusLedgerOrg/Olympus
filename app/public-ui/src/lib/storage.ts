/**
 * Persistent storage for recent hash verifications.
 *
 * Uses `localStorage` to keep a bounded list of the last 20 verifications so
 * users can review recent lookups without re-submitting.  Falls back silently
 * in environments where `localStorage` is unavailable (private browsing, SSR).
 */

import type { RecentVerificationEntry } from "./types";

const STORAGE_KEY = "olympus_recent_verifications";
const MAX_ENTRIES = 20;

function readRaw(): RecentVerificationEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as RecentVerificationEntry[];
  } catch {
    return [];
  }
}

/**
 * Retrieve the list of recent verifications, newest first.
 */
export function getRecentVerifications(): RecentVerificationEntry[] {
  return readRaw();
}

/**
 * Prepend a new verification entry and trim the list to `MAX_ENTRIES`.
 * Emits a `storage` event so that other tabs can react.
 */
export function addRecentVerification(entry: RecentVerificationEntry): void {
  try {
    const existing = readRaw();
    // Deduplicate: remove any prior entry for the same hash
    const deduped = existing.filter((e) => e.hash !== entry.hash);
    const updated = [entry, ...deduped].slice(0, MAX_ENTRIES);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    // Notify same-tab listeners (storage event only fires for other tabs)
    window.dispatchEvent(new Event("storage"));
  } catch {
    // localStorage may be unavailable (quota exceeded, private mode, SSR)
  }
}

/**
 * Remove all stored recent verification entries.
 */
export function clearRecentVerifications(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event("storage"));
  } catch {
    // ignore
  }
}

// ─── API key storage ──────────────────────────────────────────────────────────

const API_KEY_STORAGE_KEY = "olympus_api_key";
const API_KEY_RE = /^[0-9a-f]{64}$/i;

export function normalizeApiKey(key: string): string {
  return key.trim().replace(/\s+/g, "");
}

export function apiKeyProblem(key: string): string | null {
  const normalized = normalizeApiKey(key);
  if (!normalized) return "Paste a real API key first.";
  if (!API_KEY_RE.test(normalized)) {
    return "API key must be the 64-character hex key shown at signup. Clear this field and paste the real key, not password bullets.";
  }
  return null;
}

export function clearStoredApiKey(): void {
  try {
    localStorage.removeItem(API_KEY_STORAGE_KEY);
  } catch {
    // ignore
  }
}

export function getStoredApiKey(): string {
  try {
    const raw = localStorage.getItem(API_KEY_STORAGE_KEY) ?? "";
    if (!raw) return "";
    // Validate the *normalized* form (same shape as save/commit use) so that
    // a stored key with stray whitespace is either repaired or evicted —
    // returning the raw value would otherwise pass validation here but be
    // sent unsanitized in `X-API-Key` headers.
    const normalized = normalizeApiKey(raw);
    if (apiKeyProblem(normalized)) {
      localStorage.removeItem(API_KEY_STORAGE_KEY);
      return "";
    }
    if (normalized !== raw) {
      localStorage.setItem(API_KEY_STORAGE_KEY, normalized);
    }
    return normalized;
  } catch {
    return "";
  }
}

export function setStoredApiKey(key: string, _meta?: Record<string, unknown>): void {
  try {
    const normalized = normalizeApiKey(key);
    if (apiKeyProblem(normalized)) {
      localStorage.removeItem(API_KEY_STORAGE_KEY);
      return;
    }
    localStorage.setItem(API_KEY_STORAGE_KEY, normalized);
  } catch {
    // localStorage may be unavailable
  }
}
