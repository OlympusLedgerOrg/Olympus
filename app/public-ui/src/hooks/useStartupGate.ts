// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useRef, useState } from "react";
import { getApiBase } from "../lib/api";
import { safeJsonFetch } from "../lib/safeJson";
import {
  getStoredApiKey,
  setStoredApiKey,
  setStoredAdminKey,
  clearStoredApiKeyAndKeychain,
  clearStoredAdminKey,
  initApiKeyFromKeychain,
  persistApiKeyToKeychain,
} from "../lib/storage";

const PROFILE_KEY = "olympus_startup_profile_v1";
const SESSION_KEY = "olympus_startup_unlocked_v1";
const PBKDF2_ITERATIONS = 160_000;

export type StartupProfile = {
  operator: string;
  email: string;
  salt: string;
  verifier: string;
  createdAt: string;
};

export type GateMode = "loading" | "setup" | "login" | "unlock";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveVerifier(password: string, salt: string): Promise<string> {
  const saltBytes = base64ToBytes(salt);
  const saltBuffer = saltBytes.buffer.slice(
    saltBytes.byteOffset,
    saltBytes.byteOffset + saltBytes.byteLength,
  ) as ArrayBuffer;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBuffer, iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function readProfile(): StartupProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StartupProfile;
  } catch {
    return null;
  }
}

function clearStartupProfile() {
  try {
    localStorage.removeItem(PROFILE_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // Storage may be blocked; state will still reset in memory.
  }
}

/**
 * useStartupGate — the imperative core of `<StartupGate>`: local-storage /
 * PBKDF2-based "startup profile" persistence, the `loading|setup|login|unlock`
 * state machine, and the async setup/sign-in/unlock/reset handlers.
 *
 * Extracted from `StartupGate.tsx` as a pure code-motion refactor — same
 * state, same effects, same handler logic, same variable names. The component
 * stays purely presentational: it destructures this hook's return value and
 * renders JSX.
 */
export function useStartupGate() {
  const [mode, setMode] = useState<GateMode>("loading");
  const [profile, setProfile] = useState<StartupProfile | null>(null);

  // setup fields
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [newApiKey, setNewApiKey] = useState("");

  // unlock fields
  const [unlockPassword, setUnlockPassword] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [mayhemMode, setMayhemMode] = useState(false);
  const bootWordBuf = useRef("");

  useEffect(() => {
    if (unlocked) return;
    const handler = (e: KeyboardEvent) => {
      const ch = e.key.length === 1 ? e.key.toUpperCase() : "";
      if (ch) {
        bootWordBuf.current = (bootWordBuf.current + ch).slice(-8);
        if (bootWordBuf.current.includes("MAYHEM")) {
          setMayhemMode(true);
          bootWordBuf.current = "";
          setTimeout(() => setMayhemMode(false), 6000);
        }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [unlocked]);

  // One-shot bootstrap on mount: hydrate the in-memory API key from the OS
  // keychain (Tauri only) FIRST, then read the persisted startup profile.
  // Awaiting the keychain hydrate before flipping `unlocked` true guarantees
  // children never render with an unlocked session — and fire API calls —
  // before the key is in memory. In the browser, initApiKeyFromKeychain
  // resolves immediately, so there is no observable delay. (setState runs
  // inside the async callback, post-await, so the set-state-in-effect lint
  // rule does not fire here.)
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await initApiKeyFromKeychain();
      if (cancelled) return;
      const saved = readProfile();
      const sessionUnlocked = sessionStorage.getItem(SESSION_KEY) === "1";
      setProfile(saved);
      setUnlocked(Boolean(saved && sessionUnlocked));
      setMode(saved ? "unlock" : "setup");
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const title = useMemo(() => {
    if (mode === "setup") return "FIRST BOOT";
    if (mode === "login") return "SIGN IN";
    return "STARTUP LOCK";
  }, [mode]);

  async function createProfile(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    const trimmedEmail = email.trim();
    const name = displayName.trim() || trimmedEmail.split("@")[0] || "operator";

    // Basic validation — including a rough TLD check to catch typos like gmail.ocm
    if (!trimmedEmail || !trimmedEmail.includes("@")) {
      setError("Enter a valid email.");
      return;
    }
    const tld = trimmedEmail.split(".").at(-1) ?? "";
    if (tld.length < 2 || tld.length > 10) {
      setError("Email TLD looks wrong — double-check the address.");
      return;
    }
    if (name.length < 2) {
      setError("Enter a display name.");
      return;
    }
    if (password.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (!crypto.subtle) {
      setError("Browser does not support local password verification.");
      return;
    }

    setBusy(true);
    try {
      // ── Step 1: Persist the local PBKDF2 profile immediately ────────────────
      // This happens BEFORE any network call so the password is always saved.
      // On the next reload the unlock gate will accept it even if the API
      // is unreachable (air-gap / embedded server not yet running).
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = bytesToBase64(saltBytes);
      const verifier = await deriveVerifier(password, salt);
      const nextProfile: StartupProfile = {
        operator: name,
        email: trimmedEmail,
        salt,
        verifier,
        createdAt: new Date().toISOString(),
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(nextProfile));
      setProfile(nextProfile);

      // ── Step 2: Attempt server registration (best-effort) ───────────────────
      // Failure here does NOT prevent local unlock. We fall into air-gap mode:
      // the profile is already saved above, so the next visit shows the unlock
      // form (PBKDF2 verify only, no network needed).
      const scopeCandidates = [
        ["read", "verify", "ingest", "commit", "write", "admin"],
        ["read", "verify", "ingest", "commit", "write"],
        ["read", "verify"],
      ];
      let apiKey = "";
      let grantedScopes: string[] = [];
      const base = await getApiBase();

      for (const scopes of scopeCandidates) {
        const { ok, status, data } = await safeJsonFetch<{
          api_key?: string;
          scopes?: string[];
          user_id?: string;
          detail?: string;
        }>(`${base}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: trimmedEmail, password, name, scopes }),
        });

        if (status === 409 || data?.detail?.toLowerCase().includes("already registered")) {
          // Profile is saved; redirect to login so they can get their API key.
          setMode("login");
          setError("This email is already registered. Sign in to retrieve your API key.");
          return;
        }
        if (status === 429) {
          // Profile saved — they can unlock next visit without an API key.
          setError(
            "Rate limit hit. Your local profile was saved — reload to unlock without an API key, or wait 60 s and try again.",
          );
          setShowKey(false);
          return;
        }
        if (status === 403) continue; // Try next scope set.

        if (ok && data?.api_key) {
          apiKey = data.api_key;
          grantedScopes = data.scopes ?? scopes;
          break;
        }

        // Non-retryable server error or HTML response (asset server).
        // Break and fall through to air-gap mode.
        if (status !== 0) break;
      }

      if (apiKey) {
        setStoredApiKey(apiKey);
        persistApiKeyToKeychain();
        setNewApiKey(apiKey);
        if (grantedScopes.includes("admin")) {
          setStoredAdminKey(apiKey);
        }
        setShowKey(true);
      } else {
        // Server unreachable or registration failed — enter the console anyway.
        // The local PBKDF2 profile is already saved; the KEYS tab can issue an
        // API key once the server is reachable.
        enterConsole();
      }
    } catch {
      enterConsole();
    } finally {
      setBusy(false);
    }
  }

  function enterConsole() {
    sessionStorage.setItem(SESSION_KEY, "1");
    setUnlocked(true);
    setShowKey(false);
    setPassword("");
    setConfirm("");
    setNewApiKey("");
  }

  async function signIn(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!email.trim() || !email.includes("@")) {
      setError("Enter a valid email.");
      return;
    }
    if (!password) {
      setError("Enter your password.");
      return;
    }
    if (!crypto.subtle) {
      setError("Browser does not support local password verification.");
      return;
    }

    setBusy(true);
    try {
      const base = await getApiBase();
      const { ok, status, data } = await safeJsonFetch<{
        user_id?: string;
        email?: string;
        detail?: string;
        keys?: Array<{ id: string; scopes: string[]; revoked?: boolean; expires_at?: string }>;
      }>(`${base}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (!ok) {
        const msg = data?.detail ?? `Sign in failed (HTTP ${status.toString()}).`;
        setError(msg);
        return;
      }

      // Build local PBKDF2 profile so future visits use the fast unlock flow
      const name = (data?.email ?? email.trim()).split("@")[0] || "operator";
      const saltBytes = new Uint8Array(16);
      crypto.getRandomValues(saltBytes);
      const salt = bytesToBase64(saltBytes);
      const verifier = await deriveVerifier(password, salt);
      const nextProfile: StartupProfile = {
        operator: name,
        email: email.trim(),
        salt,
        verifier,
        createdAt: new Date().toISOString(),
      };
      localStorage.setItem(PROFILE_KEY, JSON.stringify(nextProfile));
      setProfile(nextProfile);

      // Reissue is a recovery path for lost/expired keys ONLY — if a key is
      // already loaded this session, keep it. Unconditional reissue used to
      // clobber an admin key with a fresh non-admin one on every sign-in.
      if (getStoredApiKey()) {
        enterConsole();
        return;
      }

      // Request the union of the account's active key scopes (the same set
      // the server allows for reissue), so an admin account gets `admin`
      // back instead of the hardcoded non-admin list. Fall back to the
      // registration defaults when the account has no usable keys.
      const activeScopes = [
        ...new Set(
          (data?.keys ?? [])
            .filter((k) => {
              if (k.revoked) return false;
              if (!k.expires_at) return true;
              const t = Date.parse(k.expires_at);
              return !Number.isNaN(t) && t > Date.now();
            })
            .flatMap((k) => k.scopes),
        ),
      ];
      const reissueScopes = activeScopes.length
        ? activeScopes
        : ["read", "verify", "ingest", "commit", "write"];

      // Issue a fresh API key — recovery path for lost/expired keys
      try {
        const { ok: keyOk, data: keyData } = await safeJsonFetch<{
          api_key: string;
          key_id: string;
          scopes: string[];
          expires_at: string;
        }>(`${base}/auth/reissue-key`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: email.trim(), password, scopes: reissueScopes }),
        });
        if (keyOk && keyData?.api_key) {
          setStoredApiKey(keyData.api_key);
          persistApiKeyToKeychain();
          setNewApiKey(keyData.api_key);
          setShowKey(true);
          return;
        }
      } catch {
        enterConsole();
        return;
      }
      enterConsole();
    } catch {
      enterConsole();
    } finally {
      setBusy(false);
    }
  }

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!profile) {
      setMode("setup");
      return;
    }
    setBusy(true);
    try {
      const verifier = await deriveVerifier(unlockPassword, profile.salt);
      if (verifier !== profile.verifier) {
        setError("Startup password rejected.");
        return;
      }
      sessionStorage.setItem(SESSION_KEY, "1");
      setUnlocked(true);
      setUnlockPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not unlock.");
    } finally {
      setBusy(false);
    }
  }

  function resetProfile() {
    clearStartupProfile();
    clearStoredApiKeyAndKeychain();
    clearStoredAdminKey();
    setProfile(null);
    setEmail("");
    setDisplayName("");
    setPassword("");
    setConfirm("");
    setNewApiKey("");
    setError(null);
    setUnlocked(false);
    setShowKey(false);
    setMode("setup");
  }

  return {
    mode,
    profile,
    email,
    setEmail,
    displayName,
    setDisplayName,
    password,
    setPassword,
    confirm,
    setConfirm,
    newApiKey,
    unlockPassword,
    setUnlockPassword,
    error,
    busy,
    unlocked,
    showKey,
    mayhemMode,
    title,
    createProfile,
    signIn,
    unlock,
    resetProfile,
    enterConsole,
    setMode,
    setError,
  };
}
