import type { Verdict, VerdictState } from "../lib/types";
import CopyButton from "./CopyButton";

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
  merkle_path?: unknown[];
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
  "LEDGER_ENTRY_HASH",
]);

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
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
    merkle_path: Array.isArray(raw.merkle_path) ? raw.merkle_path : undefined,
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
  a.click();
  URL.revokeObjectURL(url);
}

export default function ProofResultPanel({ verdict }: { verdict: VerdictState }) {
  const result = normalizeResult(verdict);
  const cfg = statusConfig(verdict.verdict);
  const committedAt = result.committed_at ?? result.timestamp;
  const proofJson = JSON.stringify(result.proof_json ?? result, null, 2);
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
    { label: "SHARD_ID", value: result.shard_id ?? "files" },
    { label: "MERKLE_ROOT", value: result.merkle_root, copyable: true },
    { label: "LEDGER_ENTRY_HASH", value: result.ledger_entry_hash, copyable: true },
    { label: "COMMITTED", value: committedAt },
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
                  .querySelector(".proof-path, .verdict-card")
                  ?.scrollIntoView({ behavior: "smooth", block: "center" })
              }
            >
              VIEW_MERKLE_PATH
            </button>
            <button
              type="button"
              onClick={() => copyText(result.record_id ?? result.proof_id ?? result.content_hash)}
            >
              COPY_LEDGER_REF
            </button>
            <button type="button" onClick={() => copyText(result.merkle_root)}>
              COPY_ROOT
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
