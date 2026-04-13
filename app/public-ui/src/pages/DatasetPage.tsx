import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { getDataset, verifyDataset } from "../lib/api";
import VerdictCard from "../components/VerdictCard";
import HashDisplay from "../components/HashDisplay";
import type { Verdict, VerdictDetail } from "../lib/types";

export default function DatasetPage() {
  const { dataset_id } = useParams<{ dataset_id: string }>();

  const detailQuery = useQuery({
    queryKey: ["dataset-detail", dataset_id],
    queryFn: () => getDataset(dataset_id!),
    enabled: !!dataset_id,
  });

  const verifyQuery = useQuery({
    queryKey: ["dataset-verify", dataset_id],
    queryFn: () => verifyDataset(dataset_id!),
    enabled: !!dataset_id,
  });

  if (detailQuery.isLoading || verifyQuery.isLoading) {
    return (
      <div className="text-center py-20">
        <p className="text-sm font-ui text-ink/50">Loading dataset…</p>
      </div>
    );
  }

  if (detailQuery.error || !detailQuery.data) {
    return (
      <div className="text-center py-20">
        <h1 className="font-serif text-3xl text-ink mb-2">Dataset Not Found</h1>
        <p className="text-sm font-ui text-ink/50 mb-6">
          {detailQuery.error instanceof Error
            ? detailQuery.error.message
            : "Could not load dataset."}
        </p>
        <Link
          to="/"
          className="text-xs font-ui text-gold hover:text-gold/80 no-underline"
        >
          ← Back to Verify
        </Link>
      </div>
    );
  }

  const ds = detailQuery.data;
  const vr = verifyQuery.data;

  const verdict: Verdict = vr?.verified ? "verified" : vr ? "failed" : "unknown";

  const verifyDetails: VerdictDetail[] = [];
  if (vr) {
    if (vr.commit_id_valid !== null) {
      verifyDetails.push({
        key: "Commit ID Valid",
        value: vr.commit_id_valid ? "Yes" : "No",
        status: vr.commit_id_valid ? "ok" : "err",
      });
    }
    if (vr.signature_valid !== null) {
      verifyDetails.push({
        key: "Signature Valid",
        value: vr.signature_valid ? "Yes" : "No",
        status: vr.signature_valid ? "ok" : "err",
      });
    }
    if (vr.chain_valid !== null) {
      verifyDetails.push({
        key: "Chain Valid",
        value: vr.chain_valid ? "Yes" : "No",
        status: vr.chain_valid ? "ok" : "err",
      });
    }
    if (vr.rfc3161_valid !== null) {
      verifyDetails.push({
        key: "RFC 3161 Timestamp",
        value: vr.rfc3161_valid ? "Valid" : "Invalid",
        status: vr.rfc3161_valid ? "ok" : "err",
      });
    }
    if (vr.key_revoked !== null) {
      verifyDetails.push({
        key: "Key Revoked",
        value: vr.key_revoked ? "Yes" : "No",
        status: vr.key_revoked ? "err" : "ok",
      });
    }
    // Additional checks
    for (const [k, v] of Object.entries(vr.checks)) {
      if (!["commit_id_valid", "signature_valid", "chain_valid", "rfc3161_valid"].includes(k)) {
        verifyDetails.push({
          key: k.replace(/_/g, " "),
          value: v ? "Pass" : "Fail",
          status: v ? "ok" : "err",
        });
      }
    }
  }

  const proofBundle = vr
    ? JSON.stringify(
        {
          dataset_id: ds.dataset_id,
          verified: vr.verified,
          checks: vr.checks,
          merkle_proof: vr.merkle_proof,
          zk_proof: vr.zk_proof,
        },
        null,
        2
      )
    : null;

  return (
    <div>
      <Link
        to="/"
        className="text-xs font-ui text-ink/40 hover:text-ink/60 no-underline mb-6 inline-block"
      >
        ← Back to Verify
      </Link>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
      >
        <h1 className="font-serif text-3xl md:text-4xl text-ink mb-1">
          {ds.dataset_name}
        </h1>
        <p className="text-sm font-ui text-ink/50 mb-6">
          v{ds.dataset_version} · {ds.license_spdx}
        </p>
      </motion.div>

      {/* Metadata Grid */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1, ease: "easeOut" }}
        className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6"
      >
        <div className="bg-white/50 border border-ink/10 rounded-sm p-4">
          <p className="text-xs font-ui text-ink/40 mb-1">Dataset ID</p>
          <HashDisplay hash={ds.dataset_id} />
        </div>
        <div className="bg-white/50 border border-ink/10 rounded-sm p-4">
          <p className="text-xs font-ui text-ink/40 mb-1">Commit ID</p>
          <p className="font-mono text-xs text-ink/80 break-all">{ds.commit_id}</p>
        </div>
        <div className="bg-white/50 border border-ink/10 rounded-sm p-4">
          <p className="text-xs font-ui text-ink/40 mb-1">Source URI</p>
          <a
            href={ds.source_uri}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-ui text-gold hover:text-gold/80 break-all"
          >
            {ds.source_uri}
          </a>
        </div>
        <div className="bg-white/50 border border-ink/10 rounded-sm p-4">
          <p className="text-xs font-ui text-ink/40 mb-1">Committed</p>
          <p className="text-xs font-ui text-ink/70">
            {new Date(ds.epoch).toLocaleString()}
          </p>
        </div>
      </motion.div>

      {/* Verification Result */}
      <VerdictCard verdict={verdict} details={verifyDetails} />

      {/* Files */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.2, ease: "easeOut" }}
        className="mt-8"
      >
        <h2 className="font-serif text-xl text-ink mb-3">
          Files ({ds.files.length})
        </h2>
        <div className="border border-ink/10 rounded-sm overflow-hidden">
          <div className="grid grid-cols-[1fr_auto_auto] gap-4 px-4 py-2 bg-ink/3 border-b border-ink/10 text-xs font-ui text-ink/50">
            <span>Path</span>
            <span>Size</span>
            <span>Content Hash</span>
          </div>
          {ds.files.map((f, i) => (
            <div
              key={f.path}
              className={`grid grid-cols-[1fr_auto_auto] gap-4 px-4 py-2.5 text-xs ${
                i < ds.files.length - 1 ? "border-b border-ink/5" : ""
              }`}
            >
              <span className="font-mono text-ink/70 truncate">{f.path}</span>
              <span className="font-mono text-ink/50 text-right">
                {formatBytes(f.byte_size)}
              </span>
              <span className="font-mono text-ink/40 truncate max-w-[200px]" title={f.content_hash}>
                {f.content_hash.slice(0, 16)}…
              </span>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Proof Bundle Expander */}
      {proofBundle && (
        <motion.details
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, delay: 0.3 }}
          className="mt-8 border border-ink/10 rounded-sm"
        >
          <summary className="text-xs font-ui text-ink/50 cursor-pointer px-4 py-3 hover:bg-white/30">
            Verify independently — Raw proof bundle
          </summary>
          <pre className="text-xs font-mono text-ink/60 p-4 overflow-x-auto border-t border-ink/10">
            {proofBundle}
          </pre>
        </motion.details>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}
