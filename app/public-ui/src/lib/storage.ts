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
// API keys and the admin key are held in **module-level JavaScript
// variables only** (`inMemoryApiKey`, `inMemoryAdminKey` below). They are
// never written to `localStorage`, `sessionStorage`, `IndexedDB`,
// cookies, or any other persistent surface. Reloading the page
// (Ctrl+R), closing the webview, or hot-reloading Vite in dev all
// discard them — the operator has to paste the key back in, or the
// first-launch `InitialSecretsModal` re-injects it from the one-shot
// `take_initial_secrets` Tauri command (audit F-4).
//
// This is intentionally stricter than the earlier design documented
// here, which described persisting the keys to `localStorage` with a
// CodeQL `js/clear-text-storage-of-sensitive-information` suppression.
// That suppression no longer applies and has been removed from
// `.github/codeql/codeql-config.yml` — direct `localStorage.setItem` of
// any secret in this tree is a genuine bug, not a documented trade-off.
//
// Why in-memory only:
//
//   1. The browser same-origin / Tauri webview model still treats
//      anyone able to execute JS on this origin as having access to
//      whatever is in JS memory. So in-memory *vs* localStorage is not
//      a strong adversary-model boundary on its own.
//   2. But: in-memory is strictly weaker as an *exfiltration surface*.
//      `localStorage` survives a page reload and is readable by any
//      future script that lands on the same origin (including a
//      malicious extension page); module-level variables die with the
//      JS realm. An attacker has to win the race within a single page
//      lifetime, not "any time in the future".
//   3. Reloads are the common case — an XSS or a malicious extension
//      that needs the user to revisit Olympus to harvest the key from
//      memory is meaningfully harder to land than one that reads
//      `localStorage["olympus_api_key"]` opportunistically.
//   4. The unified BJJ↔API-key design (PR #945) still applies: the API
//      key is derived from the BJJ private key. The BJJ key is never
//      stored in the webview at all (only ever surfaced once at
//      bootstrap via the InitialSecretsModal).
//
// All access to these two secrets MUST go through the helpers below.
// `InitialSecretsModal.tsx` only writes to `localStorage` for the
// `olympus_initial_secrets_seen` *acknowledgement timestamp*, which
// contains no secret material.

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

export function setStoredApiKey(key: string): void {
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
