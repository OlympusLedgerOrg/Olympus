import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getDataset, verifyDataset } from "../lib/api";
import { playGlitchSound } from "../lib/audio";
import VerdictCard from "../components/VerdictCard";
import HashDisplay from "../components/HashDisplay";
import type { Verdict, VerdictDetail } from "../lib/types";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

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
      <div style={{ textAlign: "center", padding: "5rem 0" }}>
        <p
          style={{
            color: "rgba(0,255,65,0.5)",
            fontSize: "0.8rem",
            animation: "flicker 1.5s infinite",
          }}
        >
          LOADING_DATASET…
        </p>
      </div>
    );
  }

  if (detailQuery.error || !detailQuery.data) {
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
          DATASET_NOT_FOUND
        </h1>
        <p
          style={{
            fontSize: "0.78rem",
            color: "rgba(0,255,65,0.4)",
            marginBottom: "1.5rem",
          }}
        >
          {detailQuery.error instanceof Error
            ? detailQuery.error.message
            : "Could not load dataset."}
        </p>
        <Link
          to="/"
          style={{
            fontSize: "0.7rem",
            color: "#ff0055",
            textDecoration: "none",
            letterSpacing: "0.06em",
          }}
        >
          ← BACK_TO_VERIFY
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
    for (const [k, v] of Object.entries(vr.checks)) {
      if (
        !["commit_id_valid", "signature_valid", "chain_valid", "rfc3161_valid"].includes(k)
      ) {
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
        2,
      )
    : null;

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
        }}
        onMouseEnter={() => playGlitchSound("blip")}
      >
        ← BACK_TO_VERIFY
      </Link>

      <div style={{ marginBottom: "2rem" }}>
        <h1
          style={{
            fontSize: "clamp(1.2rem, 3.5vw, 1.8rem)",
            margin: "0 0 0.4rem",
            textShadow: "0 0 10px #00FF41",
            letterSpacing: "0.05em",
          }}
        >
          {ds.dataset_name.toUpperCase()}
        </h1>
        <p
          style={{
            fontSize: "0.68rem",
            color: "rgba(0,255,65,0.4)",
            margin: "0 0 1.25rem",
            letterSpacing: "0.06em",
          }}
        >
          V{ds.dataset_version} // {ds.license_spdx}
        </p>
      </div>

      {/* Metadata Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
          gap: "0.75rem",
          marginBottom: "1.5rem",
        }}
      >
        <div className="cyber-panel-sm" style={{ padding: "0.85rem 1rem" }}>
          <p
            style={{
              fontSize: "0.55rem",
              color: "rgba(0,255,65,0.35)",
              margin: "0 0 0.4rem",
              letterSpacing: "0.1em",
            }}
          >
            DATASET_ID
          </p>
          <HashDisplay hash={ds.dataset_id} label="DATASET_ID" />
        </div>
        <div className="cyber-panel-sm" style={{ padding: "0.85rem 1rem" }}>
          <p
            style={{
              fontSize: "0.55rem",
              color: "rgba(0,255,65,0.35)",
              margin: "0 0 0.4rem",
              letterSpacing: "0.1em",
            }}
          >
            COMMIT_ID
          </p>
          <p
            style={{
              fontFamily: "'DM Mono', monospace",
              fontSize: "0.68rem",
              color: "rgba(0,255,65,0.8)",
              wordBreak: "break-all",
              margin: 0,
            }}
          >
            {ds.commit_id}
          </p>
        </div>
        <div className="cyber-panel-sm" style={{ padding: "0.85rem 1rem" }}>
          <p
            style={{
              fontSize: "0.55rem",
              color: "rgba(0,255,65,0.35)",
              margin: "0 0 0.4rem",
              letterSpacing: "0.1em",
            }}
          >
            SOURCE_URI
          </p>
          <a
            href={ds.source_uri}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontSize: "0.68rem",
              color: "#ff0055",
              textDecoration: "none",
              wordBreak: "break-all",
            }}
          >
            {ds.source_uri}
          </a>
        </div>
        <div className="cyber-panel-sm" style={{ padding: "0.85rem 1rem" }}>
          <p
            style={{
              fontSize: "0.55rem",
              color: "rgba(0,255,65,0.35)",
              margin: "0 0 0.4rem",
              letterSpacing: "0.1em",
            }}
          >
            COMMITTED
          </p>
          <p
            style={{
              fontSize: "0.68rem",
              color: "rgba(0,255,65,0.7)",
              margin: 0,
            }}
          >
            {new Date(ds.epoch).toLocaleString()}
          </p>
        </div>
      </div>

      <VerdictCard verdict={verdict} details={verifyDetails} />

      {/* Files */}
      <div style={{ marginTop: "2.5rem" }}>
        <h2
          style={{
            fontSize: "0.65rem",
            letterSpacing: "0.12em",
            color: "rgba(0,255,65,0.45)",
            margin: "0 0 1rem",
          }}
        >
          FILES_({ds.files.length})
        </h2>
        <div
          style={{
            border: "1px solid rgba(0,255,65,0.2)",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr auto auto",
              gap: "1rem",
              padding: "0.5rem 1rem",
              background: "rgba(0,255,65,0.04)",
              borderBottom: "1px solid rgba(0,255,65,0.15)",
              fontSize: "0.58rem",
              color: "rgba(0,255,65,0.4)",
              letterSpacing: "0.08em",
            }}
          >
            <span>PATH</span>
            <span>SIZE</span>
            <span>HASH</span>
          </div>
          {ds.files.map((f, i) => (
            <div
              key={f.path}
              style={{
                display: "grid",
                gridTemplateColumns: "1fr auto auto",
                gap: "1rem",
                padding: "0.5rem 1rem",
                borderBottom:
                  i < ds.files.length - 1
                    ? "1px solid rgba(0,255,65,0.06)"
                    : "none",
                fontSize: "0.68rem",
                alignItems: "center",
              }}
            >
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  color: "rgba(0,255,65,0.7)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {f.path}
              </span>
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  color: "rgba(0,255,65,0.4)",
                  textAlign: "right",
                  whiteSpace: "nowrap",
                }}
              >
                {formatBytes(f.byte_size)}
              </span>
              <span
                style={{
                  fontFamily: "'DM Mono', monospace",
                  color: "rgba(0,255,65,0.35)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  maxWidth: "160px",
                }}
                title={f.content_hash}
              >
                {f.content_hash.slice(0, 14)}…
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Proof Bundle */}
      {proofBundle && (
        <details style={{ marginTop: "2rem" }}>
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
            [+] RAW_PROOF_BUNDLE — verify independently
          </summary>
          <pre
            style={{
              fontSize: "0.65rem",
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
            {proofBundle}
          </pre>
        </details>
      )}
    </div>
  );
}
