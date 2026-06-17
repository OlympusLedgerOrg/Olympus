import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getPublicStats, type PublicStatsResponse } from "../lib/api";
import { playGlitchSound } from "../lib/audio";
import type { Tab, VerdictState } from "../lib/types";
import { useHashVerification } from "../hooks/useHashVerification";
import { useProofVerification } from "../hooks/useProofVerification";
import { useFileCommit } from "../hooks/useFileCommit";
import { useWasmStatus } from "../hooks/useWasmStatus";
import { useAuditProof } from "../hooks/useAuditProof";
import { useRedactionAudit } from "../hooks/useRedactionAudit";
import { useRedactionCreate } from "../hooks/useRedactionCreate";
import { useSkin } from "../skins/SkinContext";
import CommandDeck from "../components/CommandDeck";
import CommitPrompt from "../components/CommitPrompt";
import HashDisplay from "../components/HashDisplay";
import ProofResultPanel from "../components/ProofResultPanel";
import RecentVerifications from "../components/RecentVerifications";
import StatCards from "../components/StatCards";
import TiltContainer from "../components/TiltContainer";
import HashTab from "../tabs/HashTab";
import AuditProofTab from "../tabs/AuditProofTab";
import RedactionTab from "../tabs/RedactionTab";
import RedactTab from "../tabs/RedactTab";

const FALLBACK_STATS: PublicStatsResponse = {
  nodes: 0,
  shards: 0,
  proofs: 0,
  sbts_issued: 0,
  uptime: "0s",
  uptime_seconds: 0,
};

export default function HomePage() {
  const [activeTab, setActiveTab] = useState<Tab>("hash");
  const [verdictResult, setVerdictResult] = useState<VerdictState | null>(null);
  const { skin } = useSkin();

  const statsQuery = useQuery({
    queryKey: ["public-stats"],
    queryFn: getPublicStats,
    staleTime: 15_000,
    refetchInterval: 30_000,
    gcTime: 0,
    placeholderData: FALLBACK_STATS,
    retry: false,           // don't spam retries while server is starting
    throwOnError: false,    // never let a stats fetch crash the page
  });
  const stats = statsQuery.data ?? FALLBACK_STATS;

  const hashHook = useHashVerification(setVerdictResult);
  const proofHook = useProofVerification(setVerdictResult);
  const fileHook = useFileCommit(setVerdictResult, hashHook.submitHash);
  const auditHook = useAuditProof();
  const redactionHook = useRedactionAudit();
  const redactCreateHook = useRedactionCreate();
  const { wasmError } = useWasmStatus();

  const switchTab = (id: Tab) => {
    setActiveTab(id);
    setVerdictResult(null);
    hashHook.setHashError(null);
    proofHook.setProofError(null);
    fileHook.resetCommit();
    auditHook.reset();
    redactionHook.reset();
    redactCreateHook.reset();
    playGlitchSound("blip");
  };

  const clearWorkspace = () => {
    setVerdictResult(null);
    hashHook.reset();
    proofHook.reset();
    fileHook.reset();
    auditHook.reset();
    redactionHook.reset();
    redactCreateHook.reset();
  };

  const isPending = hashHook.hashMutation.isPending || proofHook.proofMutation.isPending;
  const operationLabel = isPending
    ? "VERIFYING"
    : verdictResult
      ? `LOOKUP_${verdictResult.verdict.toUpperCase()}`
      : "IDLE";
  const tabs: { id: Tab; label: string }[] = [
    { id: "hash", label: "HASH_LOOKUP" },
    { id: "audit", label: "AUDIT_PROOF" },
    { id: "redaction", label: "REDACTION" },
    { id: "redact", label: "REDACT" },
  ];
  const statCards = [
    { label: "NODES", value: stats.nodes ?? stats.copies ?? 0 },
    { label: "PROOFS", value: stats.proofs },
    { label: "SHARDS", value: stats.shards },
    { label: "SBTS", value: stats.sbts_issued },
  ];

  return (
    <div>
      <div className={skin.classes.hero}>
        <div>
          <h1
            className={skin.classes.accentText}
            style={{
              fontSize: "clamp(1.8rem, 5vw, 3rem)",
              margin: "0 0 0.75rem",
              textShadow: skin.effects?.showGlow ? "0 0 12px currentColor" : "none",
              fontFamily: "'DM Mono', monospace",
            }}
          >
            VERIFY_TRUTH
          </h1>
          <p
            className={skin.classes.mutedText}
            style={{
              maxWidth: "600px",
              fontSize: "0.82rem",
              margin: 0,
              lineHeight: 1.65,
            }}
          >
            Independently verify Olympus hashes, documents, and proof bundles
            against the append-only ledger.
          </p>
        </div>
        <div className="status-stack">
          <span className={`status-pill status-${statsQuery.isError ? "err" : "ok"}`}>
            API_{statsQuery.isError ? "OFFLINE" : "LIVE"}
          </span>
          <span className={`status-pill status-${isPending ? "warn" : "neutral"}`}>
            {operationLabel}
          </span>
        </div>
      </div>

      <StatCards cards={statCards} onRefetch={() => void statsQuery.refetch()} />

      <CommandDeck activeTab={activeTab} onSelect={switchTab} />

      <div className="verify-grid">
        <div style={{ minWidth: 0 }}>
          <TiltContainer>
            <div className={skin.classes.panel} style={{ padding: 0 }}>
              <div role="tablist" className="tab-list">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    role="tab"
                    aria-selected={activeTab === tab.id}
                    className={
                      activeTab === tab.id
                        ? skin.classes.tabActive
                        : skin.classes.tabInactive
                    }
                    onClick={() => switchTab(tab.id)}
                    type="button"
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div style={{ padding: "1.5rem" }}>
                {activeTab === "hash" && (
                  <HashTab
                    hashInput={hashHook.hashInput}
                    setHashInput={(v) => {
                      hashHook.setHashInput(v);
                      hashHook.setHashError(null);
                    }}
                    hashError={hashHook.hashError}
                    hashStatus={hashHook.hashStatus}
                    isPending={isPending}
                    onSubmit={hashHook.submitHash}
                    onPaste={hashHook.pasteHash}
                    onClear={() => {
                      hashHook.reset();
                      fileHook.reset();
                      setVerdictResult(null);
                    }}
                    apiKey={hashHook.apiKey}
                    setApiKey={hashHook.setApiKey}
                    wasmError={wasmError}
                    onFile={fileHook.onFile}
                    onFileHash={fileHook.onHash}
                    onFileProgress={fileHook.onProgress}
                    fileProgress={fileHook.fileProgress}
                  />
                )}
                {activeTab === "audit" && (
                  <AuditProofTab
                    stage={auditHook.stage}
                    bundleName={auditHook.bundleName}
                    parsed={auditHook.parsed}
                    result={auditHook.result}
                    anchor={auditHook.anchor}
                    error={auditHook.error}
                    onBundleFile={auditHook.onBundleFile}
                    onBundleText={auditHook.onBundleText}
                    onAudit={() => void auditHook.audit()}
                    onReset={auditHook.reset}
                  />
                )}
                {activeTab === "redaction" && (
                  <RedactionTab
                    stage={redactionHook.stage}
                    fileName={redactionHook.fileName}
                    fileHash={redactionHook.fileHash}
                    fileProgress={redactionHook.fileProgress}
                    bundleName={redactionHook.bundleName}
                    parsed={redactionHook.parsed}
                    issuerPubkeyHex={redactionHook.issuerPubkeyHex}
                    issuerKeyAutofilled={redactionHook.issuerKeyAutofilled}
                    verified={redactionHook.verified}
                    verifyReason={redactionHook.verifyReason}
                    error={redactionHook.error}
                    onFile={redactionHook.onFile}
                    onBundleFile={redactionHook.onBundleFile}
                    onIssuerPubkey={redactionHook.setIssuerPubkey}
                    onAudit={() => void redactionHook.audit()}
                    onReset={redactionHook.reset}
                  />
                )}
                {activeTab === "redact" && <RedactTab hook={redactCreateHook} />}
              </div>
            </div>
          </TiltContainer>

          {verdictResult ? (
            <div>
              {verdictResult.displayHash && (
                <div style={{ marginTop: "1.5rem" }}>
                  <HashDisplay hash={verdictResult.displayHash} />
                </div>
              )}
              <ProofResultPanel verdict={verdictResult} />
              {verdictResult.verdict === "unknown" &&
                fileHook.droppedFile &&
                fileHook.commitStage !== "done" && (
                  <CommitPrompt
                    apiKey={fileHook.apiKey}
                    setApiKey={fileHook.setApiKey}
                    commitStage={fileHook.commitStage}
                    commitError={fileHook.commitError}
                    onCommit={fileHook.commitFile}
                    onReset={fileHook.resetCommit}
                    originalHash={fileHook.originalHash}
                    setOriginalHash={fileHook.setOriginalHash}
                  />
                )}
            </div>
          ) : (
            <div className="ready-panel">
              <span className="ready-dot" />
              <span>READY_FOR_INPUT</span>
            </div>
          )}
        </div>

        <aside className="console-side">
          <div className="side-panel">
            <div className="side-title">SESSION</div>
            <div className="flow-step" data-active={activeTab === "hash"}>
              <span>01</span>
              <strong>Hash lookup</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "audit"}>
              <span>02</span>
              <strong>Audit proof</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "redaction"}>
              <span>03</span>
              <strong>Redaction audit</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "redact"}>
              <span>04</span>
              <strong>Create redaction</strong>
            </div>
            <button
              type="button"
              className={skin.classes.buttonPrimary}
              onClick={clearWorkspace}
              style={{ width: "100%", marginTop: "1rem" }}
            >
              RESET_CONSOLE
            </button>
          </div>

          <RecentVerifications
            onSelect={(entry) => {
              switchTab("hash");
              hashHook.setHashInput(entry.hash);
              hashHook.submitHash(entry.hash);
            }}
          />
        </aside>
      </div>
    </div>
  );
}
