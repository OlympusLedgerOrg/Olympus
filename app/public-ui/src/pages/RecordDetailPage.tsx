import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getRecordProof } from "../lib/api";
import { playGlitchSound } from "../lib/audio";
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
      <div style={{ textAlign: "center", padding: "5rem 0" }}>
        <p
          style={{
            color: "rgba(0,255,65,0.5)",
            fontSize: "0.8rem",
            animation: "flicker 1.5s infinite",
          }}
        >
          LOADING_RECORD…
        </p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div style={{ textAlign: "center", padding: "5rem 0" }}>
        <h1
          style={{
            fontSize: "1.5rem",
            marginBottom: "0.75rem",
            color: "#ff0055",
            textShadow: "0 0 8px #ff0055",
          }}
        >
          RECORD_NOT_FOUND
        </h1>
        <p
          style={{
            fontSize: "0.78rem",
            color: "rgba(0,255,65,0.4)",
            marginBottom: "1.5rem",
          }}
        >
          {error instanceof Error ? error.message : "Could not load record proof."}
        </p>
        <Link
          to="/"
          style={{
            fontSize: "0.7rem",
            color: "#ff0055",
            textDecoration: "none",
            letterSpacing: "0.06em",
          }}
          onMouseEnter={() => playGlitchSound("blip")}
        >
          ← BACK_TO_VERIFY
        </Link>
      </div>
    );
  }

  const details: VerdictDetail[] = [
    { key: "Proof ID", value: data.proof_id, status: "neutral", copyable: true },
    {
      key: "Record ID",
      value: data.record_id,
      status: "neutral",
      copyable: true,
    },
    { key: "Shard ID", value: data.shard_id, status: "neutral" },
    {
      key: "Content Hash",
      value: data.content_hash,
      status: "ok",
      copyable: true,
    },
    {
      key: "Merkle Root",
      value: data.merkle_root,
      status: "neutral",
      copyable: true,
    },
    {
      key: "Ledger Entry Hash",
      value: data.ledger_entry_hash,
      status: "neutral",
      copyable: true,
    },
    {
      key: "Committed",
      value: new Date(data.timestamp).toLocaleString(),
      status: "neutral",
    },
    ...(data.batch_id
      ? [
          {
            key: "Batch ID",
            value: data.batch_id,
            status: "neutral" as const,
            copyable: true,
          },
        ]
      : []),
    ...(data.poseidon_root
      ? [
          {
            key: "Poseidon Root",
            value: data.poseidon_root,
            status: "neutral" as const,
            copyable: true,
          },
        ]
      : []),
  ];

  const proofBundle = JSON.stringify(
    {
      proof_id: data.proof_id,
      content_hash: data.content_hash,
      merkle_root: data.merkle_root,
      merkle_proof: data.merkle_proof,
    },
    null,
    2,
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
        style={{
          fontSize: "0.68rem",
          color: "rgba(0,255,65,0.4)",
          textDecoration: "none",
          display: "inline-block",
          marginBottom: "1.75rem",
          letterSpacing: "0.06em",
          transition: "color 0.15s",
        }}
        onMouseEnter={() => playGlitchSound("blip")}
      >
        ← BACK_TO_VERIFY
      </Link>

      <div style={{ marginBottom: "2rem" }}>
        <h1
          style={{
            fontSize: "clamp(1.4rem, 4vw, 2rem)",
            margin: "0 0 1rem",
            textShadow: "0 0 10px #00FF41",
            letterSpacing: "0.05em",
          }}
        >
          RECORD_DETAIL
        </h1>
        <HashDisplay hash={data.content_hash} />
      </div>

      <VerdictCard verdict="verified" details={details} />

      <div
        style={{
          marginTop: "1.5rem",
          display: "flex",
          gap: "1.5rem",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            fontSize: "0.68rem",
            color: "rgba(0,255,65,0.4)",
          }}
        >
          <CopyButton text={window.location.href} />
          COPY_VERIFICATION_LINK
        </span>
        <button
          type="button"
          onClick={() => {
            downloadBundle();
            playGlitchSound("blip");
          }}
          style={{
            background: "transparent",
            border: "none",
            cursor: "pointer",
            fontSize: "0.68rem",
            color: "#ff0055",
            padding: 0,
            letterSpacing: "0.06em",
            fontFamily: "'DM Mono', monospace",
          }}
        >
          DOWNLOAD_PROOF_BUNDLE
        </button>
      </div>

      {/* Raw Merkle Proof */}
      <details
        style={{ marginTop: "2rem" }}
      >
        <summary
          style={{
            fontSize: "0.68rem",
            color: "rgba(0,255,65,0.4)",
            cursor: "pointer",
            padding: "0.75rem 1rem",
            background: "rgba(0,20,0,0.5)",
            border: "1px solid rgba(0,255,65,0.2)",
            letterSpacing: "0.06em",
            listStyle: "none",
          }}
          onMouseEnter={() => playGlitchSound("blip")}
        >
          [+] MERKLE_PROOF_DETAILS
        </summary>
        <pre
          style={{
            fontSize: "0.68rem",
            fontFamily: "'DM Mono', monospace",
            color: "rgba(0,255,65,0.6)",
            padding: "1rem",
            overflowX: "auto",
            background: "rgba(0,0,0,0.6)",
            border: "1px solid rgba(0,255,65,0.15)",
            borderTop: "none",
            margin: 0,
            lineHeight: 1.5,
          }}
        >
          {JSON.stringify(data.merkle_proof, null, 2)}
        </pre>
      </details>
    </div>
  );
}
