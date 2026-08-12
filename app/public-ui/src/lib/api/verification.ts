// SPDX-License-Identifier: Apache-2.0

/** Hash verification, proof bundle verification, record detail, dataset, and
 * trust-anchored existence verify — the "verify/check something against the
 * ledger" domain. */

import type {
  HashVerificationResponse,
  ProofVerificationRequest,
  ProofVerificationResponse,
  RecordProofResponse,
  DatasetResponse,
  DatasetVerificationResponse,
} from "../types";
import { apiFetch } from "./core";
import { verifyZkProof, type ZkCircuit } from "./zk";

// ─── Hash verification ────────────────────────────────────────────────────────

/**
 * Verify a BLAKE3 content hash against the Olympus ledger.
 * GET /ingest/records/hash/{hash}/verify
 *
 * Requires an API key with the `verify` scope (passed via X-API-Key header).
 */
export function verifyHash(hash: string, apiKey?: string): Promise<HashVerificationResponse> {
  const headers: Record<string, string> = {};
  if (apiKey?.trim()) headers["X-API-Key"] = apiKey.trim();
  return apiFetch<HashVerificationResponse>(`/ingest/records/hash/${hash}/verify`, { headers });
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
export function verifyDataset(datasetId: string): Promise<DatasetVerificationResponse> {
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
  const snapshotResp = await apiFetch<ProofVerificationResponse>("/ingest/proofs/verify", {
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
  });
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
  const srvIndex = snapshotResp.snapshot_index != null ? String(snapshotResp.snapshot_index) : "";
  const srvSize = snapshotResp.snapshot_size != null ? String(snapshotResp.snapshot_size) : "";

  // The signal root is a decimal Fr; the server's snapshot_root is hex.
  // Compare via normalisation: convert hex → BigInt → decimal string.
  let signalsBindToSnapshot = false;
  if (sigRoot && srvRoot && sigLeafIndex && sigTreeSize && srvIndex && srvSize) {
    try {
      const srvRootDec = BigInt("0x" + srvRoot.replace(/^0x/, "")).toString();
      signalsBindToSnapshot =
        sigRoot === srvRootDec && sigLeafIndex === srvIndex && sigTreeSize === srvSize;
    } catch {
      signalsBindToSnapshot = false;
    }
  }
  // If the bundle itself claims a snapshotRoot/Index/Size, it must agree too.
  if (signalsBindToSnapshot && bundle.snapshotRoot != null) {
    try {
      const bundleRootDec = BigInt("0x" + bundle.snapshotRoot.trim().replace(/^0x/, "")).toString();
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

  const valid = proofMath.valid && signalsBindToSnapshot && snapshotTrusted;

  const failures: string[] = [];
  if (!proofMath.valid) failures.push("proof math invalid");
  if (!signalsBindToSnapshot) failures.push("public signals do not bind to server snapshot");
  if (!snapshotTrusted) failures.push(`snapshot ${snapshotResp.status}: ${snapshotResp.detail}`);
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
