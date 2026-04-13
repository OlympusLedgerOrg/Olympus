import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { getRecordProof } from "../lib/api";
import VerdictCard from "../components/VerdictCard";
import HashDisplay from "../components/HashDisplay";
import CopyButton from "../components/CopyButton";
import type { VerdictDetail } from "../lib/types";

export default function RecordDetailPage() {
  const { proof_id } = useParams<{ proof_id: string }>();

  const { data, isLoading, error } = useQuery({
    queryKey: ["record-proof", proof_id],
    queryFn: () => getRecordProof(proof_id!),
    enabled: !!proof_id,
  });

  if (isLoading) {
    return (
      <div className="text-center py-20">
        <p className="text-sm font-ui text-ink/50">Loading record…</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="text-center py-20">
        <h1 className="font-serif text-3xl text-ink mb-2">Record Not Found</h1>
        <p className="text-sm font-ui text-ink/50 mb-6">
          {error instanceof Error ? error.message : "Could not load record proof."}
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

  const details: VerdictDetail[] = [
    { key: "Proof ID", value: data.proof_id, status: "neutral", copyable: true },
    { key: "Record ID", value: data.record_id, status: "neutral", copyable: true },
    { key: "Shard ID", value: data.shard_id, status: "neutral" },
    { key: "Content Hash", value: data.content_hash, status: "ok", copyable: true },
    { key: "Merkle Root", value: data.merkle_root, status: "neutral", copyable: true },
    { key: "Ledger Entry Hash", value: data.ledger_entry_hash, status: "neutral", copyable: true },
    { key: "Committed", value: new Date(data.timestamp).toLocaleString(), status: "neutral" },
    ...(data.batch_id ? [{ key: "Batch ID", value: data.batch_id, status: "neutral" as const, copyable: true }] : []),
    ...(data.poseidon_root ? [{ key: "Poseidon Root", value: data.poseidon_root, status: "neutral" as const, copyable: true }] : []),
  ];

  const proofBundle = JSON.stringify(
    {
      proof_id: data.proof_id,
      content_hash: data.content_hash,
      merkle_root: data.merkle_root,
      merkle_proof: data.merkle_proof,
    },
    null,
    2
  );

  const downloadBundle = () => {
    const blob = new Blob([proofBundle], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `olympus-proof-${data.proof_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
        <h1 className="font-serif text-3xl md:text-4xl text-ink mb-2">
          Record Detail
        </h1>
        <div className="mb-6">
          <HashDisplay hash={data.content_hash} />
        </div>
      </motion.div>

      <VerdictCard verdict="verified" details={details} />

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.2, ease: "easeOut" }}
        className="mt-6 flex gap-3"
      >
        <span className="flex items-center gap-1 text-xs font-ui text-ink/50">
          <CopyButton text={window.location.href} />
          Copy verification link
        </span>
        <button
          type="button"
          onClick={downloadBundle}
          className="text-xs font-ui text-gold hover:text-gold/80 cursor-pointer"
        >
          Download proof bundle
        </button>
      </motion.div>

      {/* Raw Merkle Proof */}
      <motion.details
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.3 }}
        className="mt-8 border border-ink/10 rounded-sm"
      >
        <summary className="text-xs font-ui text-ink/50 cursor-pointer px-4 py-3 hover:bg-white/30">
          Merkle Proof Details
        </summary>
        <pre className="text-xs font-mono text-ink/60 p-4 overflow-x-auto border-t border-ink/10">
          {JSON.stringify(data.merkle_proof, null, 2)}
        </pre>
      </motion.details>
    </div>
  );
}
