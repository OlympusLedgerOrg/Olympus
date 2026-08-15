// SPDX-License-Identifier: Apache-2.0

/**
 * API client core — base-URL resolution, Tauri IPC bridging, and the shared
 * `apiFetch` helper every domain module in `lib/api/` builds on.
 *
 * All functions throw an `Error` with a descriptive message on HTTP errors so
 * that TanStack Query's `onError` callbacks receive a real `Error` instance.
 */

/** Base URL for the Olympus API.
 * Resolved in order of priority:
 * 1. VITE_API_BASE environment variable (set in .env or CI)
 * 2. Tauri `get_api_port` command — embedded Axum server (production desktop)
 * 3. Current window origin (browser same-origin, works with a Vite proxy)
 * 4. http://localhost:8000 (local development fallback for SSR/test contexts)
 *
 * The Tauri path is async so API_BASE is a Promise<string> when running inside
 * Tauri.  apiFetch() awaits it on every call; the resolved value is cached so
 * the invoke() round-trip only happens once.
 */

// Tauri 2 sets window.__TAURI_INTERNALS__ on the webview; it does NOT set
// window.isTauri.  This matches what @tauri-apps/api/core's isTauri() does.
const _isTauri =
  typeof window !== "undefined" &&
  typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== "undefined";

// Origins that serve the Tauri frontend bundle — NOT the Axum API.
// Requests to these origins return HTML, so they must never be used as an API base.
const TAURI_ASSET_ORIGINS = [
  "tauri://localhost",
  "http://tauri.localhost",
  "https://tauri.localhost",
];
const TAURI_DEV_ORIGINS = ["http://127.0.0.1:5173", "http://localhost:5173"];
const TAURI_INVOKE_TIMEOUT_MS = 2000;

function isTauriAssetOrigin(origin: string) {
  return TAURI_ASSET_ORIGINS.some((o) => origin === o || origin.startsWith(o));
}

function isTauriDevOrigin(origin: string) {
  return TAURI_DEV_ORIGINS.includes(origin);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new Error(`${label} timed out after ${timeoutMs.toString()}ms`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

// Cached port — set once invoke succeeds. Never falls back to tauri://localhost.
let _cachedPort: number | null = null;

async function resolveApiBase(): Promise<string> {
  const viteBase =
    typeof import.meta !== "undefined"
      ? (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE
      : undefined;
  if (viteBase) return viteBase;

  // Use invoke() if Tauri internals are present OR if the page origin is a
  // Tauri asset server (in which case window.location.origin is useless as an
  // API base and we must get the real Axum port via IPC). In `cargo tauri dev`,
  // the origin is Vite's dev server, but the WebView should still have Tauri
  // IPC; trying invoke first avoids accidentally probing Vite's HTML fallback.
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const isDevOrigin = isTauriDevOrigin(origin);
  const mustInvoke = (_isTauri && !isDevOrigin) || isTauriAssetOrigin(origin);
  const shouldInvoke = _isTauri || isTauriAssetOrigin(origin) || isDevOrigin;

  if (shouldInvoke) {
    // Return cached port if we already have it.
    if (_cachedPort) return `http://127.0.0.1:${_cachedPort}`;

    try {
      const { invoke } = await withTimeout(
        import("@tauri-apps/api/core"),
        TAURI_INVOKE_TIMEOUT_MS,
        "loading Tauri API",
      );
      const port = await withTimeout(
        invoke<number>("get_api_port"),
        TAURI_INVOKE_TIMEOUT_MS,
        "get_api_port",
      );
      if (port > 0) {
        _cachedPort = port;
        return `http://127.0.0.1:${port}`;
      }
      throw new Error(`get_api_port returned ${String(port)}`);
    } catch (err) {
      if (mustInvoke) {
        throw new Error(`Tauri API port unavailable: ${errorMessage(err)}`);
      }
      // Plain browser Vite dev mode has no Tauri internals. A Tauri dev
      // webview can also reach this path if IPC is unavailable, in which case
      // the Vite proxy is the resilient fallback.
    }
  }

  return origin || "http://localhost:8000";
}

/** Resolves to the Axum server base URL. Retries until the server is ready.
 *  Never returns tauri://localhost. Call it fresh each time — it caches internally. */
export const getApiBase = (): Promise<string> => resolveApiBase();

/// Invoke a Tauri IPC command via the supported Tauri 2 path: detect
/// `window.__TAURI_INTERNALS__` and dynamic-import `invoke` from
/// `@tauri-apps/api/core`. The legacy `window.__TAURI__` global is only present
/// when `app.withGlobalTauri` is set in tauri.conf.json (it is NOT), so reading
/// it short-circuits to undefined in both dev and the shipped desktop. Returns
/// `null` when not running under Tauri (e.g. plain-browser Vite dev).
export async function tauriInvoke<T>(
  cmd: string,
  args?: import("@tauri-apps/api/core").InvokeArgs,
): Promise<T | null> {
  if (!_isTauri) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

/// True when running inside the Tauri webview (supported __TAURI_INTERNALS__
/// detection). Use to branch on Tauri-vs-browser when `tauriInvoke` returning
/// null would be ambiguous (e.g. a command that itself can legitimately
/// resolve to null, like a cancelled file dialog).
export const isTauri = (): boolean => _isTauri;

/// Error subclass that carries the structured fields from a Rust API
/// failure response: `status`, `detail`, and the (optional) scope context
/// the backend includes on 403s. Consumers can `instanceof ApiError` to
/// branch on permission failures without re-parsing the message.
export class ApiError extends Error {
  status: number;
  detail: string;
  requiredScope?: string | string[];
  grantedScopes?: string[];
  code?: string;
  constructor(status: number, detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const base = await resolveApiBase();
  const res = await fetch(`${base}${url}`, options);
  // Read body as text first — never call res.json() directly.
  // If the server returns an HTML page (e.g. asset server before Axum is ready),
  // res.json() throws "Unexpected token '<'". We handle it ourselves.
  const text = await res.text().catch(() => "");
  const trimmed = text.trimStart();
  const isJson = trimmed.startsWith("{") || trimmed.startsWith("[");

  if (!res.ok) {
    let detail: string;
    let required_scope: string | string[] | undefined;
    let granted_scopes: string[] | undefined;
    let code: string | undefined;
    if (isJson) {
      try {
        const json = JSON.parse(text) as {
          detail?: string;
          error?: string;
          code?: string;
          required_scope?: string | string[];
          granted_scopes?: string[];
        };
        detail = json.detail ?? json.error ?? text.trim();
        required_scope = json.required_scope;
        granted_scopes = json.granted_scopes;
        code = json.code;
      } catch {
        detail = text.trim();
      }
    } else if (trimmed.startsWith("<")) {
      detail = `Server not ready — is Olympus running? (HTTP ${res.status.toString()})`;
    } else {
      detail = text.trim() || res.statusText;
    }
    const err = new ApiError(res.status, detail);
    err.requiredScope = required_scope;
    err.grantedScopes = granted_scopes;
    err.code = code;
    throw err;
  }

  if (!isJson) {
    throw new Error(
      `Server not ready — is Olympus running? (got HTML instead of JSON from ${url})`,
    );
  }
  return JSON.parse(text) as T;
}

/** Build-time release metadata served in the `release` block of `/health`. */
export interface ReleaseInfo {
  stage: string;
  production_trust_ready: boolean;
  data_durability: string;
  notice: string;
  /** `"stable"` or `"preview"` — stamped into the binary by `src-tauri/build.rs`. */
  channel: string;
  /** e.g. `"preview-v0.10.0-rc.1"`; `null` on stable and unlabelled previews. */
  preview_tag: string | null;
}

/**
 * Read the build-time release metadata from `/health`.
 *
 * Deliberately not routed through `apiFetch`: `/health` answers `503` when the
 * database failed to start, and `apiFetch` throws on any non-2xx. The release
 * block is a build-time constant present in all three response shapes (`ok`,
 * `degraded`, `error`), and the channel banner must be visible precisely when
 * things are going wrong — so this reads the body regardless of status and only
 * fails if it cannot be parsed.
 */
export async function getReleaseInfo(): Promise<ReleaseInfo> {
  const base = await resolveApiBase();
  const res = await fetch(`${base}/health`, { cache: "no-store" });
  const text = await res.text().catch(() => "");
  if (!text.trimStart().startsWith("{")) {
    throw new Error("Server not ready — /health did not return JSON");
  }
  const body = JSON.parse(text) as { release?: Partial<ReleaseInfo> };
  const release = body.release;
  if (!release || typeof release.channel !== "string") {
    throw new Error("/health did not report a release channel");
  }
  return {
    stage: release.stage ?? "unknown",
    production_trust_ready: release.production_trust_ready ?? false,
    data_durability: release.data_durability ?? "unknown",
    notice: release.notice ?? "",
    channel: release.channel,
    preview_tag: release.preview_tag ?? null,
  };
}
