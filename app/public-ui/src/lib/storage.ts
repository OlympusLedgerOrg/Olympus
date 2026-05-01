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
