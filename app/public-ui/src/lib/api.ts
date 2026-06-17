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
import type { V3Bundle } from "./redactionBinding";

export type { V3Bundle, V3Segment } from "./redactionBinding";

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

export type ZkCircuit = "document_existence" | "non_existence";

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

// ─── Lazy ZK bundle issuance ──────────────────────────────────────────────────

/**
 * Response from GET /ingest/records/hash/{hash}/zk_bundle. Server-side
 * `#[serde(rename_all = "camelCase")]`, so wire fields are camelCase.
 */
export interface ZkBundleResponse {
  circuit: ZkCircuit;
  /** Groth16 proof object (snarkjs-shape). */
  proofJson: unknown;
  /** Public signals as decimal strings in circuit order. */
  publicSignals: string[];
  contentHash: string;
  originalRoot: string;
  snapshotRoot: string;
  snapshotIndex: number;
  snapshotSize: number;
  snapshotSig: string;
}

/**
 * Lazily issue (or fetch cached) document_existence ZK proof for a record
 * identified by its BLAKE3 content hash.
 *
 * GET /ingest/records/hash/{hash}/zk_bundle
 *
 * Returns 503 if the record has no Poseidon snapshot yet (pre-0029 row or
 * a JSON-record commit). Requires `verify`, `read`, or `admin` scope.
 */
export function issueZkBundle(
  contentHash: string,
  apiKey?: string,
): Promise<ZkBundleResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<ZkBundleResponse>(
    `/ingest/records/hash/${contentHash}/zk_bundle`,
    // no-store: this GET is regenerated server-side after a fix or cache bust;
    // the WebView2 HTTP cache must never hand back a stale bundle.
    { headers, cache: "no-store" },
  );
}

// ─── Segment-level redaction (ADR-0026 / ADR-0028) ────────────────────────────
//
// The producer selects SEGMENTS to hide by id — a segment is one PDF object
// (traditional or modern), one text line-block, or one OOXML package part. The
// original is committed with one Poseidon hiding leaf per segment. The redacted
// artifact's byte shape is FORMAT-DEPENDENT: in-place NUL-fill (length preserved)
// for traditional PDF and text; a canonically re-emitted container for OOXML
// (Stored ZIP) and modern PDFs (rebuilt traditional-xref) — those differ in bytes
// and length from the upload. In every case the committed leaf binds logical
// content (not a file offset), so each revealed segment's leaf still recomputes
// from the artifact. See `src-tauri/src/api/redaction/` + `src-tauri/src/zk/segment/`.

// ─── Object manifest (drives the producer object checklist) ────────────────────

/** One committed segment in a document's redaction manifest. */
export interface ManifestObject {
  /** Segment id (== `segmentId` in `revealedSegments`). PDF: the indirect-object
   *  id; text: the 0-based line-block index. */
  segmentId: number;
  /** Length in bytes of the segment's span in the original artifact. */
  byteLength: number;
  /** Producer-facing label — a text block's `"lines 12-18"`; `null` for PDF
   *  (the `segmentId` is itself the object's label there). */
  label: string | null;
}

/** Commitment format of a redaction manifest (drives the selection UI). */
export type RedactionFormat =
  | "pdf-object"
  | "pdf-xref-stream"
  | "text-line"
  | "ooxml-part";

/**
 * Response from GET /redaction/manifest/{contentHash}.
 * Server-side `#[serde(rename_all = "camelCase")]`.
 */
export interface RedactionManifestResponse {
  contentHash: string;
  /** Commitment format tag so the UI can render the right selection affordance. */
  format: RedactionFormat;
  originalRoot: string;
  objectCount: number;
  objects: ManifestObject[];
}

/**
 * Fetch the committed segment manifest for an already-committed document so the
 * producer can pick which segments (PDF objects / text line-blocks) to hide.
 *
 * GET /redaction/manifest/{contentHash}
 *
 * 404 if the document is not on-ledger, or was committed as an unsupported /
 * opaque-binary (chunk) record that isn't object-redactable. Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function getRedactionManifest(
  contentHash: string,
  apiKey?: string,
): Promise<RedactionManifestResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactionManifestResponse>(
    `/redaction/manifest/${contentHash}`,
    { headers, cache: "no-store" },
  );
}

/** Response from GET /redaction/issuer-key (ADR-0030). */
export interface RedactionIssuerKeyResponse {
  /** Ed25519 verifying key (32-byte lowercase hex) that signs this instance's
   *  V3 redaction bundles. */
  ed25519PubkeyHex: string;
}

/**
 * Fetch this instance's Ed25519 bundle-signing public key so the audit UI can
 * pre-fill the trust anchor.
 *
 * GET /redaction/issuer-key (unauthenticated — the key is public by design).
 *
 * Convenience anchor only: it is self-reported by the producing instance, so an
 * auditor verifying a bundle from an untrusted source should still supply the
 * issuer key out-of-band rather than trust this value.
 */
export function getRedactionIssuerKey(): Promise<RedactionIssuerKeyResponse> {
  return apiFetch<RedactionIssuerKeyResponse>("/redaction/issuer-key", {
    cache: "no-store",
  });
}

// ─── ADR-0029 Phase A1/A2: object classification + previews ───────────────────

/** Stable classification tag from `POST /redaction/describe` (ADR-0029 §A). */
export type RedactionObjectKind =
  | "catalog"
  | "pages"
  | "page"
  | "content_stream"
  | "image"
  | "font"
  | "metadata"
  | "annotation"
  | "xobject_form"
  | "other";

/**
 * One classified, human-presentable committed object. Mirrors the Rust
 * `zk::pdf_describe::ObjectDescription` (`#[serde(rename_all = "camelCase")]`).
 * Presentation only — never part of the commitment (ADR-0029 §A).
 */
export interface RedactionObjectDescription {
  objId: number;
  byteLength: number;
  kind: RedactionObjectKind;
  /** Human label, e.g. "Page 1 — text", "Image 800×600 (DCTDecode)", "Font: Helvetica". */
  label: string;
  /** 1-based page number, if resolvable; else null. */
  page: number | null;
  /** Short extracted-text preview for content streams; else null. */
  preview: string | null;
  width: number | null;
  height: number | null;
  filter: string | null;
  baseFont: string | null;
  typeName: string | null;
}

/** Response from POST /redaction/describe (ADR-0029 Phase A1). */
export interface RedactionDescribeResponse {
  contentHash: string;
  format: RedactionFormat;
  objectCount: number;
  objects: RedactionObjectDescription[];
}

/**
 * Classify an already-committed PDF's objects into human labels + previews for
 * the producer UI (ADR-0029 Phase A1 endpoint; consumed by Phase A2).
 *
 * POST /redaction/describe — takes the original bytes (base64) + content_hash;
 * the server requires `BLAKE3(bytes) == content_hash` and an on-ledger manifest.
 * Only supported for the `pdf-object` commitment format. Presentation only:
 * nothing here is persisted or part of the commitment. Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function describeRedaction(
  originalBase64: string,
  contentHash: string,
  apiKey?: string,
): Promise<RedactionDescribeResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactionDescribeResponse>("/redaction/describe", {
    method: "POST",
    headers,
    body: JSON.stringify({ content_hash: contentHash, original_base64: originalBase64 }),
  });
}

// ─── Olympus-owned redaction (producer side) ──────────────────────────────────

/**
 * Response from POST /redaction/redact (ADR-0030 V3). The server
 * `#[serde(rename_all = "camelCase")]`s the wrapper (`redactedBase64`,
 * `bundle`); `bundle` is the V3 signed-Merkle bundle, whose own fields are
 * snake_case (the `V3Bundle` type has no `rename_all`).
 */
export interface RedactDocumentResponse {
  /** Base64 of the redacted artifact. Byte shape is format-dependent: same length
   *  as the original (in-place NUL-fill) for traditional PDF and text; a
   *  canonically re-emitted container (different bytes/length) for OOXML and
   *  modern (xref-stream) PDFs. Revealed segments still recompute from it. */
  redactedBase64: string;
  /** The ADR-0030 V3 signed-Merkle bundle bound to the redacted artifact. */
  bundle: V3Bundle;
}

/**
 * Produce a binding-compatible redacted artifact from an already-committed
 * ORIGINAL document plus the segment ids to hide, and the matching ADR-0030 V3
 * signed-Merkle bundle.
 *
 * POST /redaction/redact
 *
 * The server owns the byte transformation, dispatched on the committed format:
 * in-place NUL-fill for traditional PDF / text (length + offsets preserved), or a
 * canonical re-emit for OOXML (Stored ZIP) and modern PDFs (rebuilt
 * traditional-xref). Either way the artifact binds to the committed original via
 * per-segment logical-content leaves — an unrelated re-saved document would not.
 *
 * The original MUST already be on-ledger: the server BLAKE3-hashes the uploaded
 * bytes and the bundle build fails if no committed manifest matches.
 * `recipientId` is an opaque field element (decimal string). Requires `redact`,
 * `write`, `ingest`, or `admin` scope.
 */
export function redactDocument(
  originalBase64: string,
  redactedObjIds: number[],
  recipientId: string,
  apiKey?: string,
): Promise<RedactDocumentResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<RedactDocumentResponse>("/redaction/redact", {
    method: "POST",
    headers,
    body: JSON.stringify({
      original_base64: originalBase64,
      redacted_obj_ids: redactedObjIds,
      recipient_id: recipientId,
    }),
    cache: "no-store",
  });
}

// ─── Trust-anchored existence verify ──────────────────────────────────────────

/**
 * Outcome of an anchored existence verify.
 *
 * Composes three independent checks. ALL must pass for `valid`:
 *   - `proofMathValid` — Groth16 verifies against the embedded vkey.
 *   - `signalsBindToSnapshot` — the proof's public `root`, `leafIndex`,
 *     and `treeSize` match the snapshot's `snapshot_root`,
 *     `snapshot_index`, `snapshot_size`. Without this, a proof could
 *     verify mathematically but anchor to a forged root the operator
 *     never committed to.
 *   - `snapshotTrusted` — the server's `/ingest/proofs/verify` returned
 *     `status: "verified"`, which now (Gap-2 fix) cross-checks the BJJ
 *     signature against the full trusted-issuer set rather than only
 *     the current authority key.
 */
export interface AnchoredVerifyResult {
  valid: boolean;
  proofMathValid: boolean;
  signalsBindToSnapshot: boolean;
  snapshotTrusted: boolean;
  /** Concise human-readable detail aggregating any failures. */
  detail: string;
}

/**
 * Trust-anchored verify for a `document_existence` bundle.
 *
 * The proof math alone says "leaf X is at index N in a tree of root R and
 * size S" — but says nothing about whether R is the ledger root the operator
 * ever committed to. Anchoring binds R to a signed snapshot from a trusted
 * issuer; without it, a forged-root proof would pass the math-only check.
 *
 * Requires a bundle carrying `contentHash` + at least the snapshot anchoring
 * fields (`snapshotRoot`, `snapshotIndex`, `snapshotSize`). Bundles produced
 * by `GENERATE_ZK_PROOF` always include these.
 */
export async function verifyAnchoredExistence(
  bundle: {
    circuit: ZkCircuit;
    proofJson: string;
    publicSignals: string[];
    contentHash: string;
    snapshotRoot?: string;
    snapshotIndex?: number;
    snapshotSize?: number;
  },
  apiKey?: string,
): Promise<AnchoredVerifyResult> {
  if (bundle.circuit !== "document_existence") {
    throw new Error(
      `verifyAnchoredExistence only supports document_existence; got ${bundle.circuit}`,
    );
  }

  // 1. Proof math.
  const proofMath = await verifyZkProof(
    {
      circuit: bundle.circuit,
      proofJson: bundle.proofJson,
      publicSignals: bundle.publicSignals,
    },
    apiKey,
  );

  // 2. Snapshot via /ingest/proofs/verify. The endpoint pulls the canonical
  //    snapshot from the server's own DB by content_hash — the bundle doesn't
  //    need to re-supply it, and a malicious bundle can't lie about the
  //    snapshot fields the server checks against.
  const snapshotResp = await apiFetch<ProofVerificationResponse>(
    "/ingest/proofs/verify",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey?.trim() ? { "X-API-Key": apiKey.trim() } : {}),
      },
      body: JSON.stringify({
        content_hash: bundle.contentHash,
        merkle_root: bundle.publicSignals[0] ?? "",
        merkle_proof: {},
      }),
    },
  );
  const snapshotTrusted = snapshotResp.status === "verified";

  // 3. Signal-to-snapshot binding. document_existence public signal order
  //    is [root, leafIndex, treeSize]. Anchoring is the AND of:
  //      proof.root == server's snapshot_root  (and bundle.snapshotRoot if present)
  //      proof.leafIndex == snapshot_index
  //      proof.treeSize == snapshot_size
  //
  //    We compare against the server's response (authoritative) AND the
  //    bundle's own claimed snapshot fields — if those disagree, the bundle
  //    was tampered after issuance.
  const sigRoot = (bundle.publicSignals[0] ?? "").trim();
  const sigLeafIndex = (bundle.publicSignals[1] ?? "").trim();
  const sigTreeSize = (bundle.publicSignals[2] ?? "").trim();
  const srvRoot = (snapshotResp.snapshot_root ?? "").trim();
  const srvIndex = snapshotResp.snapshot_index != null
    ? String(snapshotResp.snapshot_index)
    : "";
  const srvSize = snapshotResp.snapshot_size != null
    ? String(snapshotResp.snapshot_size)
    : "";

  // The signal root is a decimal Fr; the server's snapshot_root is hex.
  // Compare via normalisation: convert hex → BigInt → decimal string.
  let signalsBindToSnapshot = false;
  if (sigRoot && srvRoot && sigLeafIndex && sigTreeSize && srvIndex && srvSize) {
    try {
      const srvRootDec = BigInt("0x" + srvRoot.replace(/^0x/, "")).toString();
      signalsBindToSnapshot =
        sigRoot === srvRootDec &&
        sigLeafIndex === srvIndex &&
        sigTreeSize === srvSize;
    } catch {
      signalsBindToSnapshot = false;
    }
  }
  // If the bundle itself claims a snapshotRoot/Index/Size, it must agree too.
  if (signalsBindToSnapshot && bundle.snapshotRoot != null) {
    try {
      const bundleRootDec = BigInt(
        "0x" + bundle.snapshotRoot.trim().replace(/^0x/, ""),
      ).toString();
      if (bundleRootDec !== sigRoot) signalsBindToSnapshot = false;
    } catch {
      signalsBindToSnapshot = false;
    }
  }
  if (
    signalsBindToSnapshot &&
    bundle.snapshotIndex != null &&
    String(bundle.snapshotIndex) !== sigLeafIndex
  ) {
    signalsBindToSnapshot = false;
  }
  if (
    signalsBindToSnapshot &&
    bundle.snapshotSize != null &&
    String(bundle.snapshotSize) !== sigTreeSize
  ) {
    signalsBindToSnapshot = false;
  }

  const valid =
    proofMath.valid && signalsBindToSnapshot && snapshotTrusted;

  const failures: string[] = [];
  if (!proofMath.valid) failures.push("proof math invalid");
  if (!signalsBindToSnapshot)
    failures.push("public signals do not bind to server snapshot");
  if (!snapshotTrusted)
    failures.push(`snapshot ${snapshotResp.status}: ${snapshotResp.detail}`);
  const detail = valid
    ? "Proof math, signal binding, and trusted-issuer snapshot all verify."
    : failures.join("; ");

  return {
    valid,
    proofMathValid: proofMath.valid,
    signalsBindToSnapshot,
    snapshotTrusted,
    detail,
  };
}
