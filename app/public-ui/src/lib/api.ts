/**
 * API client for the Olympus FastAPI backend.
 *
 * All functions throw an `Error` with a descriptive message on HTTP errors so
 * that TanStack Query's `onError` callbacks receive a real `Error` instance.
 */

import type {
  HashVerificationResponse,
  ProofVerificationRequest,
  ProofVerificationResponse,
  RecordProofResponse,
  DatasetResponse,
  DatasetVerificationResponse,
} from "./types";

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
const TAURI_ASSET_ORIGINS = ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"];

function isTauriAssetOrigin(origin: string) {
  return TAURI_ASSET_ORIGINS.some(o => origin === o || origin.startsWith(o));
}

// Cached port — set once invoke succeeds. Never falls back to tauri://localhost.
let _cachedPort: number | null = null;

async function resolveApiBase(): Promise<string> {
  const viteBase = (
    typeof import.meta !== "undefined"
      ? (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE
      : undefined
  );
  if (viteBase) return viteBase;

  // Use invoke() if Tauri internals are present OR if the page origin is a
  // Tauri asset server (in which case window.location.origin is useless as an
  // API base and we must get the real Axum port via IPC).
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const shouldInvoke = _isTauri || isTauriAssetOrigin(origin);

  if (shouldInvoke) {
    // Return cached port if we already have it.
    if (_cachedPort) return `http://127.0.0.1:${_cachedPort}`;

    // Retry until the Axum server has bound and registered its port.
    // No timeout — we wait however long it takes. The server always starts.
    // The dynamic import is inside try/catch because if the chunk fails to load
    // (e.g. asset server returns HTML for a missing JS file), the browser throws
    // SyntaxError("Unexpected token '<'") which must not propagate.
    let invoke: Awaited<typeof import("@tauri-apps/api/core")>["invoke"] | null = null;
    for (let attempt = 0; ; attempt++) {
      try {
        if (!invoke) {
          invoke = (await import("@tauri-apps/api/core")).invoke;
        }
        const port = await invoke<number>("get_api_port");
        if (port > 0) {
          _cachedPort = port;
          return `http://127.0.0.1:${port}`;
        }
      } catch { /* not ready yet or chunk failed to load */ }
      await new Promise(r => setTimeout(r, Math.min(100 * (attempt + 1), 1000)));
    }
  }

  return origin || "http://localhost:8000";
}

/** Resolves to the Axum server base URL. Retries until the server is ready.
 *  Never returns tauri://localhost. Call it fresh each time — it caches internally. */
export const getApiBase = (): Promise<string> => resolveApiBase();

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
          detail?: string; error?: string; code?: string;
          required_scope?: string | string[]; granted_scopes?: string[];
        };
        detail = json.detail ?? json.error ?? text.trim();
        required_scope = json.required_scope;
        granted_scopes = json.granted_scopes;
        code = json.code;
      } catch { detail = text.trim(); }
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
      `Server not ready — is Olympus running? (got HTML instead of JSON from ${url})`
    );
  }
  return JSON.parse(text) as T;
}

// ─── Hash verification ────────────────────────────────────────────────────────

/**
 * Verify a BLAKE3 content hash against the Olympus ledger.
 * GET /ingest/records/hash/{hash}/verify
 *
 * Requires an API key with the `verify` scope (passed via X-API-Key header).
 */
export function verifyHash(
  hash: string,
  apiKey?: string,
): Promise<HashVerificationResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<HashVerificationResponse>(
    `/ingest/records/hash/${hash}/verify`,
    { headers },
  );
}

// ─── Proof bundle verification ────────────────────────────────────────────────

/**
 * Submit a full proof bundle for server-side verification.
 * POST /ingest/proofs/verify
 */
export function verifyProofBundle(
  bundle: ProofVerificationRequest,
): Promise<ProofVerificationResponse> {
  return apiFetch<ProofVerificationResponse>("/ingest/proofs/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bundle),
  });
}

// ─── Record detail ────────────────────────────────────────────────────────────

/**
 * Fetch the full proof bundle for a specific record.
 * GET /ingest/records/{proof_id}
 */
export function getRecordProof(proofId: string): Promise<RecordProofResponse> {
  return apiFetch<RecordProofResponse>(`/ingest/records/${proofId}`);
}

// ─── Dataset ──────────────────────────────────────────────────────────────────

/**
 * Fetch full dataset detail.
 * GET /datasets/{dataset_id}
 */
export function getDataset(datasetId: string): Promise<DatasetResponse> {
  return apiFetch<DatasetResponse>(`/datasets/${datasetId}`);
}

/**
 * Run independent verification for a dataset.
 * GET /datasets/{dataset_id}/verify
 */
export function verifyDataset(
  datasetId: string,
): Promise<DatasetVerificationResponse> {
  return apiFetch<DatasetVerificationResponse>(`/datasets/${datasetId}/verify`);
}

export type PublicStatsResponse = {
  nodes: number;
  copies?: number;
  shards: number;
  proofs: number;
  sbts_issued: number;
  uptime: string;
  uptime_seconds: number;
};

export function getPublicStats(): Promise<PublicStatsResponse> {
  return apiFetch<PublicStatsResponse>("/v1/public/stats", {
    cache: "no-store",
  });
}

// ─── User registration ────────────────────────────────────────────────────────

export type RegisterRequest = {
  email: string;
  password: string;
  name?: string;
  scopes?: string[];
};

export type RegisterResponse = {
  user_id: string;
  email?: string;
  api_key: string;
  key_id?: string;
  scopes?: string[];
  role?: string;
};

export function registerPublicUser(body: RegisterRequest): Promise<RegisterResponse> {
  return apiFetch<RegisterResponse>("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ─── Key reissue (recovery path — no existing key required) ──────────────────

export type ReissueKeyResponse = {
  api_key: string;
  key_id: string;
  scopes: string[];
  expires_at: string;
};

export function reissueKey(email: string, password: string): Promise<ReissueKeyResponse> {
  return apiFetch<ReissueKeyResponse>("/auth/reissue-key", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      password,
      scopes: ["read", "verify", "ingest", "commit", "write"],
    }),
  });
}

// ─── ZK proof verification ────────────────────────────────────────────────────

export type ZkCircuit = "document_existence" | "non_existence" | "redaction_validity";

export interface ZkVerifyRequest {
  circuit: ZkCircuit;
  /** Groth16 proof object serialized as a JSON string (snarkjs-shape). */
  proofJson: string;
  /** Public signals as decimal strings in the order the circuit declares. */
  publicSignals: string[];
}

export interface ZkVerifyResponse {
  valid: boolean;
  circuit: ZkCircuit;
}

/**
 * Audit a ZK proof bundle against the embedded verification key.
 * POST /zk/verify
 *
 * Requires an API key with scope `verify`, `read`, or `admin`.
 */
export function verifyZkProof(
  req: ZkVerifyRequest,
  apiKey?: string,
): Promise<ZkVerifyResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<ZkVerifyResponse>("/zk/verify", {
    method: "POST",
    headers,
    body: JSON.stringify(req),
  });
}
