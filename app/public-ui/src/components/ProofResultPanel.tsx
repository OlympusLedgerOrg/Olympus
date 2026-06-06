import { useState } from "react";
import type { Verdict, VerdictState } from "../lib/types";
import CopyButton from "./CopyButton";
import {
  ApiError,
  issueZkBundle,
  issueRedaction,
  verifyZkProof,
  type ZkVerifyRequest,
} from "../lib/api";
import { getStoredApiKey } from "../lib/storage";

type VerificationResult = {
  content_hash?: string;
  proof_id?: string;
  record_id?: string;
  shard_id?: string;
  merkle_root?: string;
  merkle_proof_valid?: boolean;
  ledger_entry_hash?: string;
  committed_at?: string;
  timestamp?: string;
  proof_json?: unknown;
  merkle_proof?: unknown;
  poseidon_root?: string;
  merkle_path?: unknown[];
  is_redacted?: boolean;
  original_hash?: string;
  record_type?: string;
};

type ResultRow = {
  label: string;
  value?: string;
  copyable?: boolean;
};

const COPYABLE_FIELDS = new Set([
  "CONTENT_HASH_BLAKE3",
  "PROOF_ID",
  "RECORD_ID",
  "MERKLE_ROOT",
  "POSEIDON_ROOT",
  "LEDGER_ENTRY_HASH",
  "ORIGINAL_HASH",
]);

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function detailValue(verdict: VerdictState, keyPattern: RegExp): string | undefined {
  return verdict.details.find((detail) => keyPattern.test(detail.key))?.value;
}

function normalizeResult(verdict: VerdictState): VerificationResult {
  const raw = asObject(verdict.raw);
  const fallbackProofJson = raw.proof_json ?? (Object.keys(raw).length ? raw : undefined);

  return {
    content_hash:
      asString(raw.content_hash) ??
      asString(raw.contentHash) ??
      detailValue(verdict, /content\s*hash/i) ??
      verdict.displayHash,
    proof_id: asString(raw.proof_id) ?? asString(raw.proofId) ?? detailValue(verdict, /proof\s*id/i),
    record_id:
      asString(raw.record_id) ?? asString(raw.recordId) ?? detailValue(verdict, /record\s*id/i),
    shard_id: asString(raw.shard_id) ?? asString(raw.shardId) ?? detailValue(verdict, /shard/i),
    merkle_root:
      asString(raw.merkle_root) ??
      asString(raw.merkleRoot) ??
      detailValue(verdict, /merkle\s*root|root/i),
    merkle_proof_valid:
      typeof raw.merkle_proof_valid === "boolean"
        ? raw.merkle_proof_valid
        : verdict.verdict === "verified"
          ? true
          : verdict.verdict === "failed"
            ? false
            : undefined,
    ledger_entry_hash:
      asString(raw.ledger_entry_hash) ??
      asString(raw.ledgerEntryHash) ??
      detailValue(verdict, /ledger\s*entry/i),
    committed_at:
      asString(raw.committed_at) ??
      asString(raw.timestamp) ??
      asString(raw.committedAt) ??
      detailValue(verdict, /committed|timestamp/i),
    timestamp: asString(raw.timestamp),
    proof_json: fallbackProofJson ?? verdict,
    merkle_proof: raw.merkle_proof ?? undefined,
    poseidon_root: asString(raw.poseidon_root),
    merkle_path: Array.isArray(raw.merkle_path) ? raw.merkle_path : undefined,
    is_redacted: raw.is_redacted === true,
    original_hash: asString(raw.original_hash),
    record_type: asString(raw.record_type),
  };
}

function statusConfig(verdict: Verdict) {
  if (verdict === "verified") {
    return {
      mode: "granted",
      icon: "✓",
      title: ">>> ACCESS_GRANTED",
      subtitle: "Record exists on the ledger and the Merkle proof is cryptographically valid.",
      badge: "CRYPTOGRAPHICALLY_VALID",
    } as const;
  }
  if (verdict === "failed") {
    return {
      mode: "denied",
      icon: "✗",
      title: ">>> ACCESS_DENIED",
      subtitle: "Record was found, but the hash, proof, or Merkle path failed verification.",
      badge: "PROOF_FAILED",
    } as const;
  }
  return {
    mode: "pending",
    icon: "?",
    title: ">>> PROOF_PENDING",
    subtitle:
      "No committed proof is available for this hash yet, or the server could not return a verification bundle.",
    badge: "AWAITING_LEDGER_COMMIT",
  } as const;
}

function copyText(value?: string) {
  if (!value) return;
  void navigator.clipboard?.writeText(value);
}

function downloadJson(filename: string, payload: string) {
  const blob = new Blob([payload], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  // The anchor MUST be in the document for the click to register a download
  // inside the Tauri WebView2 runtime — a detached <a>.click() is silently
  // dropped there (works in dev-browser Chrome, fails in the bundled app).
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function ProofResultPanel({ verdict }: { verdict: VerdictState }) {
  const result = normalizeResult(verdict);
  const cfg = statusConfig(verdict.verdict);
  const committedAt = result.committed_at ?? result.timestamp;
  const [zkStage, setZkStage] = useState<"idle" | "loading" | "error">("idle");
  const [zkError, setZkError] = useState<string | null>(null);
  const [redactStage, setRedactStage] = useState<"idle" | "loading" | "error">("idle");
  const [redactError, setRedactError] = useState<string | null>(null);
  // Closes the generate→verify loop: the just-minted redaction bundle, kept so
  // it can be round-tripped through POST /zk/verify without re-importing the
  // downloaded file. Verification happens server-side (Rust); the UI only
  // displays the boolean.
  const [lastRedaction, setLastRedaction] = useState<ZkVerifyRequest | null>(null);
  const [redactVerify, setRedactVerify] = useState<
    "idle" | "loading" | "valid" | "invalid" | "error"
  >("idle");
  const [redactVerifyError, setRedactVerifyError] = useState<string | null>(null);

  // Auditor (useAuditProof) accepts both camelCase and snake_case keys; we
  // emit snake_case here because that's the documented external bundle shape.
  async function onGenerateZkProof() {
    if (!result.content_hash) {
      setZkStage("error");
      setZkError("Record has no content_hash to prove inclusion of.");
      return;
    }
    setZkStage("loading");
    setZkError(null);
    try {
      const apiKey = getStoredApiKey() || undefined;
      const bundle = await issueZkBundle(result.content_hash, apiKey);
      const auditable = {
        circuit: bundle.circuit,
        proof_json: bundle.proofJson,
        public_signals: bundle.publicSignals,
        content_hash: bundle.contentHash,
        original_root: bundle.originalRoot,
        snapshot_root: bundle.snapshotRoot,
        snapshot_index: bundle.snapshotIndex,
        snapshot_size: bundle.snapshotSize,
        snapshot_sig: bundle.snapshotSig,
      };
      // Derive a short fingerprint from the proof's first coordinate so each
      // regeneration writes a DISTINCT file. Otherwise every export reuses the
      // same name and the browser silently saves the new one as "...(1).json",
      // leaving the stale original under the expected name — exactly the trap
      // that made a pre-fix proof look like it had "come back".
      const piA0 = (bundle.proofJson as { pi_a?: string[] } | null)?.pi_a?.[0] ?? "";
      const fp = piA0.slice(0, 10) || String(bundle.snapshotIndex);
      downloadJson(
        `olympus-zkproof-${result.record_id ?? result.content_hash ?? "record"}-${fp}.json`,
        JSON.stringify(auditable, null, 2),
      );
      setZkStage("idle");
    } catch (e) {
      // 503 = no snapshot yet; surface the server's detail verbatim.
      const msg =
        e instanceof ApiError
          ? e.detail || e.message
          : e instanceof Error
            ? e.message
            : String(e);
      setZkStage("error");
      setZkError(msg);
    }
  }

  // Mint a redaction_validity bundle for this committed document and download
  // it as REDACTION_PROOF.json for the Redaction tab. Default reveal mask
  // reveals the first 15 of the circuit's 16 chunk slots and redacts the last
  // (the server rejects an all-revealed mask — that isn't a redaction).
  // recipient_id is an opaque field element; "1" is a valid placeholder.
  async function onGenerateRedactionProof() {
    if (!result.content_hash) {
      setRedactStage("error");
      setRedactError("Record has no content_hash to redact.");
      return;
    }
    setRedactStage("loading");
    setRedactError(null);
    try {
      const apiKey = getStoredApiKey() || undefined;
      const revealMask = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0];
      const recipientId = "1";
      const bundle = await issueRedaction(result.content_hash, revealMask, recipientId, apiKey);
      const auditable = {
        circuit: bundle.circuit,
        proof_json: bundle.proofJson,
        public_signals: bundle.publicSignals,
        content_hash: bundle.contentHash,
        original_root: bundle.originalRoot,
        reveal_mask: bundle.revealMask,
        // recipient_id is an input (not echoed by the response), but the
        // signature payload binds it — include it so the exported bundle is
        // self-describing for verification.
        recipient_id: recipientId,
        revealed_chunk_hashes: bundle.revealedChunkHashes,
        signature_hex: bundle.signatureHex,
      };
      const piA0 = (bundle.proofJson as { pi_a?: string[] } | null)?.pi_a?.[0] ?? "";
      const fp = piA0.slice(0, 10) || "redaction";
      downloadJson(
        `olympus-redaction-proof-${result.record_id ?? result.content_hash ?? "record"}-${fp}.json`,
        JSON.stringify(auditable, null, 2),
      );
      // Keep the verifiable triple so the operator can confirm the bundle
      // round-trips through /zk/verify. `proofJson` must be the JSON *string*
      // the endpoint expects.
      setLastRedaction({
        circuit: "redaction_validity",
        proofJson: JSON.stringify(bundle.proofJson),
        publicSignals: bundle.publicSignals,
      });
      setRedactVerify("idle");
      setRedactVerifyError(null);
      setRedactStage("idle");
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? e.detail || e.message
          : e instanceof Error
            ? e.message
            : String(e);
      setRedactStage("error");
      setRedactError(msg);
    }
  }

  // Verify the just-minted redaction bundle by round-tripping it through the
  // server's POST /zk/verify (Groth16 verify against the embedded vkey). The
  // proof is verified in Rust; the UI only renders the boolean result. Needs an
  // API key with `verify`, `read`, or `admin` scope.
  async function onVerifyRedactionProof() {
    if (!lastRedaction) return;
    setRedactVerify("loading");
    setRedactVerifyError(null);
    try {
      const apiKey = getStoredApiKey() || undefined;
      const res = await verifyZkProof(lastRedaction, apiKey);
      setRedactVerify(res.valid ? "valid" : "invalid");
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? e.detail || e.message
          : e instanceof Error
            ? e.message
            : String(e);
      setRedactVerify("error");
      setRedactVerifyError(msg);
    }
  }

  // Build a structured verification bundle for copy/download
  const bundle = {
    proof_id: result.proof_id,
    record_id: result.record_id,
    shard_id: result.shard_id,
    content_hash: result.content_hash,
    merkle_root: result.merkle_root,
    poseidon_root: result.poseidon_root ?? null,
    ledger_entry_hash: result.ledger_entry_hash,
    committed_at: committedAt,
    merkle_proof: result.merkle_proof ?? {},
    merkle_proof_valid: result.merkle_proof_valid ?? null,
    record_type: result.record_type ?? "file",
    is_redacted: result.is_redacted ?? false,
    original_hash: result.original_hash ?? null,
  };
  let proofJson: string;
  try {
    proofJson = JSON.stringify(bundle, null, 2);
  } catch {
    proofJson = JSON.stringify({ error: "proof_json not serializable" }, null, 2);
  }

  const proofLabel =
    result.merkle_proof_valid === true
      ? "VALID"
      : result.merkle_proof_valid === false
        ? "INVALID"
        : "UNKNOWN";

  const rows: ResultRow[] = [
    { label: "CONTENT_HASH_BLAKE3", value: result.content_hash, copyable: true },
    { label: "PROOF_ID", value: result.proof_id, copyable: true },
    { label: "RECORD_ID", value: result.record_id, copyable: true },
    { label: "RECORD_TYPE", value: result.record_type ?? "file" },
    { label: "SHARD_ID", value: result.shard_id ?? "files" },
    { label: "MERKLE_ROOT", value: result.merkle_root, copyable: true },
    { label: "POSEIDON_ROOT", value: result.poseidon_root, copyable: true },
    { label: "LEDGER_ENTRY_HASH", value: result.ledger_entry_hash, copyable: true },
    { label: "COMMITTED", value: committedAt },
    ...(result.original_hash
      ? [{ label: "ORIGINAL_HASH", value: result.original_hash, copyable: true }]
      : []),
  ];

  return (
    <section className="proof-result-panel" data-verdict={cfg.mode}>
      <div className="proof-result-scanlines" aria-hidden="true" />
      <div className="proof-result-grid">
        <div className="proof-result-main">
          <p className="proof-kicker">BOOT_ART // GODMODE_BUILD</p>
          <h2>
            <span>{cfg.icon}</span> {cfg.title}
          </h2>
          <p className="proof-subtitle">{cfg.subtitle}</p>

          <div className="proof-valid-badge">
            <span />
            {cfg.badge}
          </div>

          {result.is_redacted && (
            <div
              className="proof-valid-badge"
              style={{
                marginTop: "0.5rem",
                borderColor: "rgba(168,85,247,0.5)",
                color: "#a855f7",
                background: "rgba(168,85,247,0.06)",
              }}
            >
              <span style={{ background: "#a855f7" }} />
              REDACTED_DOCUMENT
            </div>
          )}

          <div className="proof-fields">
            {rows.map((row) => (
              <div className="proof-field" key={row.label}>
                <div className="proof-field-label">{row.label}</div>
                <div className="proof-field-value">
                  <code>{row.value ?? "-"}</code>
                  {row.copyable && row.value && COPYABLE_FIELDS.has(row.label) ? (
                    <CopyButton text={row.value} />
                  ) : null}
                </div>
              </div>
            ))}

            <div className="proof-field proof-field-inline">
              <div className="proof-field-label">MERKLE_PROOF</div>
              <span className="proof-merkle-badge">{proofLabel}</span>
            </div>
          </div>

          <div className="proof-result-actions">
            <button type="button" onClick={() => copyText(proofJson)}>
              COPY_PROOF_JSON
            </button>
            <button
              type="button"
              onClick={() =>
                downloadJson(
                  `olympus-verification-${result.record_id ?? result.content_hash ?? "record"}.json`,
                  proofJson,
                )
              }
            >
              DOWNLOAD_BUNDLE
            </button>
            <button
              type="button"
              onClick={() =>
                document
                  .querySelector(".proof-path")
                  ?.scrollIntoView({ behavior: "smooth", block: "center" })
              }
            >
              VIEW_MERKLE_PATH
            </button>
            <button
              type="button"
              disabled={!result.content_hash || zkStage === "loading"}
              onClick={onGenerateZkProof}
              title="Fetch a Groth16 document_existence proof from the server and download the auditable bundle JSON. Drop it into the Audit Proof tab to verify."
            >
              {zkStage === "loading" ? "GENERATING_ZK..." : "GENERATE_ZK_PROOF"}
            </button>
            <button
              type="button"
              disabled={!result.content_hash || redactStage === "loading"}
              onClick={onGenerateRedactionProof}
              title="Mint a Groth16 redaction_validity proof for this committed document (reveals 15 of 16 chunk slots, redacts the last) and download the bundle JSON. Drop it into the Redaction tab to verify."
            >
              {redactStage === "loading" ? "GENERATING_REDACTION..." : "GENERATE_REDACTION_PROOF"}
            </button>
            {lastRedaction && (
              <button
                type="button"
                disabled={redactVerify === "loading"}
                onClick={onVerifyRedactionProof}
                title="Round-trip the redaction bundle just minted through POST /zk/verify (verified server-side against the embedded verification key). Requires an API key with verify/read/admin scope."
              >
                {redactVerify === "loading" ? "VERIFYING..." : "VERIFY_REDACTION_PROOF"}
              </button>
            )}
          </div>
          {redactVerify === "valid" && (
            <p className="ok-text" style={{ marginTop: "0.5rem" }}>
              ✓ Redaction proof verified by the server.
            </p>
          )}
          {redactVerify === "invalid" && (
            <p className="err-text" style={{ marginTop: "0.5rem" }}>
              ✗ Redaction proof did NOT verify.
            </p>
          )}
          {redactVerify === "error" && (
            <p className="err-text" style={{ marginTop: "0.5rem" }}>
              Verification unavailable: {redactVerifyError}
            </p>
          )}
          {zkStage === "error" && zkError && (
            <p className="err-text" style={{ marginTop: "0.5rem" }}>
              ZK proof unavailable: {zkError}
            </p>
          )}
          {redactStage === "error" && redactError && (
            <p className="err-text" style={{ marginTop: "0.5rem" }}>
              Redaction proof unavailable: {redactError}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
