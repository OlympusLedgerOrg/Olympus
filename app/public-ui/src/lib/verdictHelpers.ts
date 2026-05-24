import type {
  HashVerificationResponse,
  ProofVerificationResponse,
  Verdict,
  VerdictDetail,
} from "./types";

export function hashVerificationToVerdict(
  resp: HashVerificationResponse,
): { verdict: Verdict; details: VerdictDetail[] } {
  const verdict: Verdict = resp.merkle_proof_valid ? "verified" : "failed";
  return {
    verdict,
    details: [
      { key: "Content Hash", value: resp.content_hash, status: "ok", copyable: true },
      { key: "Proof ID", value: resp.proof_id, status: "neutral", copyable: true },
      { key: "Record ID", value: resp.record_id, status: "neutral", copyable: true },
      { key: "Shard ID", value: resp.shard_id, status: "neutral" },
      { key: "Merkle Root", value: resp.merkle_root, status: "neutral", copyable: true },
      {
        key: "Merkle Proof",
        value: resp.merkle_proof_valid ? "Valid" : "Invalid",
        status: resp.merkle_proof_valid ? "ok" : "err",
      },
      {
        key: "Ledger Entry Hash",
        value: resp.ledger_entry_hash,
        status: "neutral",
        copyable: true,
      },
      {
        key: "Committed",
        value: new Date(resp.timestamp).toLocaleString(),
        status: "neutral",
      },
      ...(resp.poseidon_root
        ? [
            {
              key: "Poseidon Root",
              value: resp.poseidon_root,
              status: "neutral" as const,
              copyable: true,
            },
          ]
        : []),
    ],
  };
}

export function proofVerificationToVerdict(
  resp: ProofVerificationResponse,
): { verdict: Verdict; details: VerdictDetail[] } {
  // Authoritative state is `status`. `pending` is NOT a rejection — the
  // record is in the ledger, the snapshot just isn't anchored yet.
  // `pending` (record exists, snapshot not yet anchored) and `unknown`
  // (not in ledger at all) both map to the "unknown" verdict — neither is a
  // pass and neither is a contradiction. The `detail` field below carries the
  // human distinction.
  const verdict: Verdict =
    resp.status === "verified"
      ? "verified"
      : resp.status === "invalid"
        ? "failed"
        : "unknown";
  const snapshotStatusLabel: Record<
    ProofVerificationResponse["status"],
    { value: string; status: VerdictDetail["status"] }
  > = {
    verified: { value: "Verified (path + signature)", status: "ok" },
    pending: { value: "Pending (no snapshot anchored yet)", status: "warn" },
    invalid: { value: "Invalid (snapshot failed verification)", status: "err" },
    unknown: { value: "Unknown (not in ledger)", status: "err" },
  };
  return {
    verdict,
    details: [
      { key: "Content Hash", value: resp.content_hash, status: "neutral", copyable: true },
      {
        key: "Snapshot Status",
        value: snapshotStatusLabel[resp.status].value,
        status: snapshotStatusLabel[resp.status].status,
      },
      { key: "Detail", value: resp.detail, status: "neutral" },
      ...(resp.snapshot_root
        ? [
            {
              key: "Snapshot Root",
              value: resp.snapshot_root,
              status: "neutral" as const,
              copyable: true,
            },
          ]
        : []),
      {
        key: "Known to Server",
        value: resp.known_to_server ? "Yes" : "No",
        status: resp.known_to_server ? "ok" : "warn",
      },
    ],
  };
}
