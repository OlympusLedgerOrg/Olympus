import { useState, useEffect } from "react";
import { getRecentVerifications } from "../lib/storage";
import type { RecentVerificationEntry, Verdict } from "../lib/types";

const verdictDotColor: Record<Verdict, string> = {
  verified: "bg-verified",
  failed: "bg-failed",
  unknown: "bg-unknown",
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
    () => getRecentVerifications()
  );

  useEffect(() => {
    const onStorage = () => setEntries(getRecentVerifications());
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Re-read on focus to catch same-tab updates
  useEffect(() => {
    const onFocus = () => setEntries(getRecentVerifications());
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, []);

  if (entries.length === 0) return null;

  return (
    <div className="mt-8 lg:mt-0">
      <h3 className="text-xs font-ui text-ink/50 uppercase tracking-wider mb-3">
        Recent Verifications
      </h3>
      <div className="space-y-1">
        {entries.map((e) => (
          <div
            key={e.hash + e.timestamp}
            className="flex items-center gap-2 py-1.5 text-xs"
          >
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${verdictDotColor[e.verdict]}`}
            />
            <span className="font-mono text-ink/70 truncate max-w-[160px]">
              {e.hash.slice(0, 16)}…
            </span>
            <span className="text-ink/40 font-ui">{e.type}</span>
            <span className="text-ink/30 font-ui ml-auto">
              {relativeTime(e.timestamp)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
