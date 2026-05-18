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
  RedactionProofBundle,
  RedactionZkVerifyResponse,
} from "./types";

/** Base URL for the Olympus API.
 * Resolved in order of priority:
 * 1. VITE_API_BASE environment variable (set in .env or CI)
 * 2. Port announced by the Tauri backend via the "api-ready" event
 * 3. Current window origin (browser same-origin, works with a Vite proxy)
 * 4. http://localhost:8000 (local development fallback)
 */

let _apiBase: string =
  (typeof import.meta !== "undefined" &&
    (import.meta as { env?: { VITE_API_BASE?: string } }).env?.VITE_API_BASE) ||
  (typeof window !== "undefined" ? window.location.origin : "http://localhost:8000");

// In Tauri context the Axum server binds to a dynamic port; the backend
// emits "api-ready" with the port number once it is listening.
if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) {
  import("@tauri-apps/api/event").then(({ listen }) => {
    listen<number>("api-ready", (ev) => {
      _apiBase = `http://127.0.0.1:${ev.payload}`;
    });
  });
  // Also try to read the port synchronously for pages that load after the event.
  import("@tauri-apps/api/core").then(({ invoke }) => {
    invoke<number | null>("get_api_port").then((port) => {
      if (port) _apiBase = `http://127.0.0.1:${port}`;
    });
  });
}

const getApiBase = () => _apiBase;

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${getApiBase()}${url}`, options);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let detail = text;
    try {
      const json = JSON.parse(text) as { detail?: unknown };
      if (typeof json.detail === "string") {
        detail = json.detail;
      } else if (json.detail && typeof json.detail === "object") {
        const inner = json.detail as { detail?: string };
        if (typeof inner.detail === "string") detail = inner.detail;
      }
    } catch {
      // fall through — raw text is fine
    }
    // Always include the HTTP status code so callers can test e.g.
    // err.message.includes("404") for "not found" disambiguation.
    const body =
      (typeof detail === "string" ? detail.trim() : "") || res.statusText;
    throw new Error(`HTTP ${res.status.toString()}: ${body}`);
  }
  return res.json() as Promise<T>;
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
  copies: number;
  shards: number;
  proofs: number;
  sbts: number;
  nodes: number;
  uptime: string;
  uptime_seconds: number;
};

export function getPublicStats(): Promise<PublicStatsResponse> {
  return apiFetch<PublicStatsResponse>("/v1/public/stats");
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

// ─── ZK Redaction ─────────────────────────────────────────────────────────────

/**
 * POST /redaction/prove — generate a Groth16 proof (prover has both files).
 * Returns a bundle that can be used to verify without the original.
 */
export function proveRedaction(
  originalFile: File,
  redactedFile: File,
  originalCommitId: string,
  apiKey?: string,
): Promise<RedactionProofBundle> {
  const form = new FormData();
  form.append("original_file", originalFile);
  form.append("redacted_file", redactedFile);
  form.append("original_commit_id", originalCommitId);
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactionProofBundle>("/redaction/prove", {
    method: "POST",
    headers,
    body: form,
  });
}

/**
 * POST /redaction/verify-zk — verify a proof bundle (no original file needed).
 */
export function verifyRedactionZk(
  redactedFile: File,
  bundle: RedactionProofBundle,
  apiKey?: string,
): Promise<RedactionZkVerifyResponse> {
  const form = new FormData();
  form.append("redacted_file", redactedFile);
  form.append("proof_bundle", JSON.stringify(bundle));
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactionZkVerifyResponse>("/redaction/verify-zk", {
    method: "POST",
    headers,
    body: form,
  });
}
