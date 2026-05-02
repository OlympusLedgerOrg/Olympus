import { useEffect, useState } from "react";
import { clearRecentVerifications, getRecentVerifications } from "../lib/storage";
import type { RecentVerificationEntry, Verdict } from "../lib/types";

const verdictColor: Record<Verdict, string> = {
  verified: "#00FF41",
  failed: "#ff0055",
  unknown: "#f59e0b",
};

interface RecentVerificationsProps {
  onSelect?: (entry: RecentVerificationEntry) => void;
}

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function RecentVerifications({ onSelect }: RecentVerificationsProps) {
  const [entries, setEntries] = useState<RecentVerificationEntry[]>(() =>
    getRecentVerifications(),
  );

  useEffect(() => {
    const refresh = () => setEntries(getRecentVerifications());
    window.addEventListener("storage", refresh);
    window.addEventListener("focus", refresh);
    return () => {
      window.removeEventListener("storage", refresh);
      window.removeEventListener("focus", refresh);
    };
  }, []);

  return (
    <div className="side-panel">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: "1px solid rgba(0,255,65,0.15)",
          paddingBottom: "0.5rem",
          marginBottom: "0.75rem",
        }}
      >
        <div
          style={{
            fontSize: "0.58rem",
            opacity: 0.5,
            letterSpacing: "0.12em",
          }}
        >
          RECENT_LOGS
        </div>
        {entries.length > 0 && (
          <button
            type="button"
            className="icon-text-btn"
            onClick={() => {
              clearRecentVerifications();
              setEntries([]);
            }}
          >
            CLEAR
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-mark">EMPTY</div>
          <div>No verification logs in this browser.</div>
        </div>
      ) : (
        entries.map((entry) => (
          <button
            key={entry.hash + entry.timestamp}
            type="button"
            className="recent-row"
            onClick={() => onSelect?.(entry)}
          >
            <span
              style={{
                color: verdictColor[entry.verdict],
                flexShrink: 0,
                fontSize: "0.58rem",
              }}
            >
              [{entry.verdict.toUpperCase()}]
            </span>
            <span
              style={{
                color: "rgba(0,255,65,0.68)",
                fontFamily: "'DM Mono', monospace",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                flex: 1,
                textAlign: "left",
              }}
            >
              {entry.hash.slice(0, 18)}...
            </span>
            <span
              style={{
                color: "rgba(0,255,65,0.34)",
                flexShrink: 0,
                fontSize: "0.56rem",
              }}
            >
              {relativeTime(entry.timestamp)}
            </span>
          </button>
        ))
      )}
    </div>
  );
}
