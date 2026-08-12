// SPDX-License-Identifier: Apache-2.0

/** ZK proof verification + lazy ZK bundle issuance. */

import { apiFetch } from "./core";

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
export function verifyZkProof(req: ZkVerifyRequest, apiKey?: string): Promise<ZkVerifyResponse> {
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
export function issueZkBundle(contentHash: string, apiKey?: string): Promise<ZkBundleResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<ZkBundleResponse>(
    `/ingest/records/hash/${contentHash}/zk_bundle`,
    // no-store: this GET is regenerated server-side after a fix or cache bust;
    // the WebView2 HTTP cache must never hand back a stale bundle.
    { headers, cache: "no-store" },
  );
}
