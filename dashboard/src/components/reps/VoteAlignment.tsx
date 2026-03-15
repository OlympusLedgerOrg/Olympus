import type { VoteAlignmentSummary } from "@/lib/mocks/reps";
import { formatPercent } from "@/lib/utils/formatting";

export function VoteAlignment({
  alignment,
  score,
}: {
  alignment: VoteAlignmentSummary;
  score: number;
}) {
  const totalVotes = alignment.aligned + alignment.opposed + alignment.abstained;
  const alignedPct = totalVotes ? (alignment.aligned / totalVotes) * 100 : 0;
  const opposedPct = totalVotes ? (alignment.opposed / totalVotes) * 100 : 0;
  const abstainedPct = totalVotes ? (alignment.abstained / totalVotes) * 100 : 0;

  return (
    <div>
      <div className="flex items-center justify-between text-xs" style={{ color: "var(--color-text-muted)" }}>
        <span>Symbolic vote alignment</span>
        <span style={{ color: "var(--color-primary)" }}>{formatPercent(score)}</span>
      </div>
      <div
        className="mt-2 flex h-2 overflow-hidden"
        style={{ borderRadius: "999px", background: "var(--color-surface-muted)" }}
      >
        <span
          style={{
            width: `${alignedPct}%`,
            background: "var(--color-ok)",
          }}
        />
        <span
          style={{
            width: `${opposedPct}%`,
            background: "var(--color-danger)",
          }}
        />
        <span
          style={{
            width: `${abstainedPct}%`,
            background: "var(--color-text-muted)",
          }}
        />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs" style={{ color: "var(--color-text-muted)" }}>
        <div>
          <p style={{ color: "var(--color-ok)" }}>Aligned</p>
          <p>{alignment.aligned}</p>
        </div>
        <div>
          <p style={{ color: "var(--color-danger)" }}>Opposed</p>
          <p>{alignment.opposed}</p>
        </div>
        <div>
          <p>Abstained</p>
          <p>{alignment.abstained}</p>
        </div>
      </div>
      <p className="mt-3 text-xs" style={{ color: "var(--color-text-muted)" }}>
        Last updated {new Date(alignment.lastUpdated).toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
        })}
      </p>
    </div>
  );
}
