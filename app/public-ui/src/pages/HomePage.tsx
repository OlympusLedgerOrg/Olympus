import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getPublicStats, type PublicStatsResponse } from "../lib/api";
import { playGlitchSound } from "../lib/audio";
import type { Tab, VerdictState } from "../lib/types";
import { useHashVerification } from "../hooks/useHashVerification";
import { useProofVerification } from "../hooks/useProofVerification";
import { useFileCommit } from "../hooks/useFileCommit";
import { useJsonVerification } from "../hooks/useJsonVerification";
import { useSkin } from "../skins/SkinContext";
import CommitPrompt from "../components/CommitPrompt";
import HashDisplay from "../components/HashDisplay";
import RecentVerifications from "../components/RecentVerifications";
import StatCards from "../components/StatCards";
import TiltContainer from "../components/TiltContainer";
import VerdictCard from "../components/VerdictCard";
import HashTab from "../tabs/HashTab";
import FileTab from "../tabs/FileTab";
import JsonTab from "../tabs/JsonTab";
import ProofTab from "../tabs/ProofTab";

const FALLBACK_STATS: PublicStatsResponse = {
  copies: 0,
  shards: 0,
  proofs: 0,
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
  });
  const stats = statsQuery.data ?? FALLBACK_STATS;

  const hashHook = useHashVerification(setVerdictResult, activeTab);
  const proofHook = useProofVerification(setVerdictResult);
  const fileHook = useFileCommit(setVerdictResult, hashHook.submitHash);
  const jsonHook = useJsonVerification(setVerdictResult, hashHook.submitHash);

  const switchTab = (id: Tab) => {
    setActiveTab(id);
    setVerdictResult(null);
    hashHook.setHashError(null);
    proofHook.setProofError(null);
    jsonHook.setJsonError(null);
    fileHook.resetCommit();
    playGlitchSound("blip");
  };

  const clearWorkspace = () => {
    setVerdictResult(null);
    hashHook.reset();
    proofHook.reset();
    fileHook.reset();
    jsonHook.reset();
  };

  const isPending = hashHook.hashMutation.isPending || proofHook.proofMutation.isPending;
  const operationLabel = isPending
    ? "VERIFYING"
    : verdictResult
      ? verdictResult.verdict.toUpperCase()
      : "IDLE";
  const tabs: { id: Tab; label: string }[] = [
    { id: "hash", label: "HASH" },
    { id: "file", label: "FILE" },
    { id: "json", label: "JSON_DOC" },
    { id: "proof", label: "PROOF_BUNDLE" },
  ];
  const statCards = [
    { label: "COPIES", value: stats.copies },
    { label: "SHARDS", value: stats.shards },
    { label: "PROOFS", value: stats.proofs },
    { label: "UPTIME", value: stats.uptime, raw: true },
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
                      setVerdictResult(null);
                    }}
                  />
                )}
                {activeTab === "file" && (
                  <FileTab
                    fileHash={fileHook.fileHash}
                    fileProgress={fileHook.fileProgress}
                    commitContentHash={fileHook.commitContentHash}
                    isPending={isPending}
                    onHash={fileHook.onHash}
                    onProgress={fileHook.onProgress}
                    onFile={fileHook.onFile}
                    onVerify={() =>
                      fileHook.fileHash && hashHook.submitHash(fileHook.fileHash)
                    }
                  />
                )}
                {activeTab === "json" && (
                  <JsonTab
                    jsonInput={jsonHook.jsonInput}
                    setJsonInput={(v) => {
                      jsonHook.setJsonInput(v);
                      jsonHook.setJsonError(null);
                    }}
                    jsonError={jsonHook.jsonError}
                    jsonCanonical={jsonHook.jsonCanonical}
                    isPending={isPending}
                    onSubmit={jsonHook.submitJsonDoc}
                    onFormat={jsonHook.formatJson}
                    onMinify={jsonHook.minifyJson}
                  />
                )}
                {activeTab === "proof" && (
                  <ProofTab
                    proofInput={proofHook.proofInput}
                    setProofInput={(v) => {
                      proofHook.setProofInput(v);
                      proofHook.setProofError(null);
                    }}
                    proofError={proofHook.proofError}
                    isPending={isPending}
                    onSubmit={proofHook.submitProof}
                  />
                )}
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
              <VerdictCard
                verdict={verdictResult.verdict}
                details={verdictResult.details}
              />
              {verdictResult.verdict === "unknown" &&
                fileHook.droppedFile &&
                fileHook.commitStage !== "done" && (
                  <CommitPrompt
                    apiKey={fileHook.apiKey}
                    setApiKey={fileHook.setApiKey}
                    commitStage={fileHook.commitStage}
                    commitError={fileHook.commitError}
                    onCommit={fileHook.commitFile}
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
            <div className="flow-step" data-active={activeTab === "file"}>
              <span>02</span>
              <strong>Local file hash</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "json"}>
              <span>03</span>
              <strong>Canonical JSON</strong>
            </div>
            <div className="flow-step" data-active={activeTab === "proof"}>
              <span>04</span>
              <strong>Proof bundle</strong>
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
