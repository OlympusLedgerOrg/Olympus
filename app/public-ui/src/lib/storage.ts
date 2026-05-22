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

// ─── API key + admin-key storage ────────────────────────────────────────────
//
// SECURITY MODEL
// --------------
// API keys and the admin key are persisted to `localStorage` so the user
// does not have to re-paste them between page loads. This trips CodeQL
// `js/clear-text-storage-of-sensitive-information` (CWE-312) — the alert
// is real but the trade-off is intentional. The rationale, reviewed
// once, lives here so the rest of the codebase can call these helpers
// without re-justifying the decision at each site.
//
//   1. The API key is *itself* a secret the user already holds out of
//      band (copied from the first-launch InitialSecretsModal, or
//      pasted from a password manager). Storing the same string under
//      `localStorage["olympus_api_key"]` does not widen the attack
//      surface beyond what the user is already exposed to.
//   2. Olympus's threat model treats the browser's same-origin policy
//      as the trust boundary. An attacker who can read localStorage on
//      `tauri://localhost` (or in a dev `http://localhost:5173`) has
//      already won — they can also intercept the `X-API-Key` header on
//      every outgoing fetch.
//   3. The unified BJJ↔API-key design (PR #945) makes the API key a
//      *derivation* of the BJJ private key. Losing the API key while
//      keeping the BJJ private key is recoverable; the API key alone
//      can't be used to mint signatures, only to authenticate HTTP
//      requests. So the leakage value of localStorage is bounded.
//   4. The long-term answer is Tauri-managed in-process storage (zero
//      disk writes; lost on app close), tracked as a follow-up. Until
//      that ships, `.github/codeql/codeql-config.yml` excludes this
//      file from the `js/clear-text-storage-of-sensitive-information`
//      query so the rule still fires on direct `localStorage` writes
//      anywhere else in the tree.
//
// All `localStorage` access for these two secrets MUST go through the
// helpers in this file. Direct `localStorage.setItem("olympus_*_key", ...)`
// elsewhere in the tree both fragments the security boundary and
// re-trips CodeQL on every additional site.

const API_KEY_STORAGE_KEY = "olympus_api_key";
const ADMIN_KEY_STORAGE_KEY = "olympus_admin_key";
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

let inMemoryApiKey = "";
let inMemoryAdminKey = "";

export function clearStoredApiKey(): void {
  inMemoryApiKey = "";
}

export function getStoredApiKey(): string {
  const raw = inMemoryApiKey;
  if (!raw) return "";
  // Validate the *normalized* form (same shape as save/commit use) so that
  // a stored key with stray whitespace is either repaired or evicted —
  // returning the raw value would otherwise pass validation here but be
  // sent unsanitized in `X-API-Key` headers.
  const normalized = normalizeApiKey(raw);
  if (apiKeyProblem(normalized)) {
    inMemoryApiKey = "";
    return "";
  }
  if (normalized !== raw) {
    inMemoryApiKey = normalized;
  }
  return normalized;
}

export function setStoredApiKey(key: string, _meta?: Record<string, unknown>): void {
  const normalized = normalizeApiKey(key);
  if (apiKeyProblem(normalized)) {
    inMemoryApiKey = "";
    return;
  }
  inMemoryApiKey = normalized;
}

// ─── Admin key (operator's OLYMPUS_ADMIN_KEY) ───────────────────────────────
// Separate secret from the regular API key. Used by AdminUsersPage and
// related views to reach `/admin/*` routes that require the `x-admin-key`
// header. Same security model as the API key above.

export function getStoredAdminKey(): string {
  return inMemoryAdminKey;
}

export function setStoredAdminKey(key: string): void {
  const trimmed = key.trim();
  if (!trimmed) {
    inMemoryAdminKey = "";
    return;
  }
  inMemoryAdminKey = trimmed;
}

export function clearStoredAdminKey(): void {
  inMemoryAdminKey = "";
}

/// "Is the operator authenticated" — true/false without exposing the
/// secret itself. Nav gating in Layout reads this instead of touching
/// the value.
export function hasStoredAdminKey(): boolean {
  return Boolean(inMemoryAdminKey);
}
