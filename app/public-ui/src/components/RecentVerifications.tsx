import { useState, useEffect } from "react";
import { getRecentVerifications } from "../lib/storage";
import type { RecentVerificationEntry, Verdict } from "../lib/types";

const verdictColor: Record<Verdict, string> = {
  verified: "#00FF41",
  failed: "#ff0055",
  unknown: "#f59e0b",
};

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function RecentVerifications() {
  const [entries, setEntries] = useState<RecentVerificationEntry[]>(
    () => getRecentVerifications(),
  );

  useEffect(() => {
    const onStorage = () => setEntries(getRecentVerifications());
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  useEffect(() => {
    const onFocus = () => setEntries(getRecentVerifications());
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, []);

  if (entries.length === 0) return null;

  return (
    <div style={{ marginTop: "2.5rem" }}>
      <div
        style={{
          fontSize: "0.58rem",
          opacity: 0.4,
          borderBottom: "1px solid rgba(0,255,65,0.15)",
          paddingBottom: "0.5rem",
          marginBottom: "0.75rem",
          letterSpacing: "0.12em",
        }}
      >
        RECENT_LOGS
      </div>
      {entries.map((e) => (
        <div
          key={e.hash + e.timestamp}
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "0.75rem",
            fontSize: "0.65rem",
            padding: "0.4rem 0",
            borderBottom: "1px solid rgba(0,255,65,0.05)",
          }}
        >
          <span
            style={{
              color: verdictColor[e.verdict],
              flexShrink: 0,
              fontSize: "0.6rem",
            }}
          >
            [{e.verdict.toUpperCase()}]
          </span>
          <span
            style={{
              color: "rgba(0,255,65,0.6)",
              fontFamily: "'DM Mono', monospace",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              flex: 1,
            }}
          >
            {e.hash.slice(0, 14)}…
          </span>
          <span
            style={{
              color: "rgba(0,255,65,0.3)",
              flexShrink: 0,
              fontSize: "0.58rem",
            }}
          >
            {relativeTime(e.timestamp)}
          </span>
        </div>
      ))}
    </div>
  );
}
