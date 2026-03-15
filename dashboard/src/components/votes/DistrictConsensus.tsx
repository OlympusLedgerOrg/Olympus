import type { VoteChoice } from "@/lib/mocks/bills";
import { formatPercent, formatNumber } from "@/lib/utils/formatting";

export function DistrictConsensus({
  totals,
  consensusPct,
  repVote,
  userVote,
  alignmentScore,
}: {
  totals: { yea: number; nay: number; abstain: number };
  consensusPct: number;
  repVote: VoteChoice;
  userVote: VoteChoice | null;
  alignmentScore: number;
}) {
  const total = totals.yea + totals.nay + totals.abstain;

  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
            District consensus
          </p>
          <h2 className="mt-2 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
            {formatPercent(consensusPct)} agreement
          </h2>
        </div>
        <p className="text-sm" style={{ color: "var(--color-text-muted)" }}>
          Total symbolic votes: {formatNumber(total)}
        </p>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
        <div className="border p-3" style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
          <p style={{ color: "var(--color-ok)" }}>Yea</p>
          <p className="mt-1 text-lg font-semibold" style={{ color: "var(--color-text)" }}>{formatNumber(totals.yea)}</p>
        </div>
        <div className="border p-3" style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
          <p style={{ color: "var(--color-danger)" }}>Nay</p>
          <p className="mt-1 text-lg font-semibold" style={{ color: "var(--color-text)" }}>{formatNumber(totals.nay)}</p>
        </div>
        <div className="border p-3" style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
          <p style={{ color: "var(--color-text-muted)" }}>Abstain</p>
          <p className="mt-1 text-lg font-semibold" style={{ color: "var(--color-text)" }}>{formatNumber(totals.abstain)}</p>
        </div>
      </div>

      <div className="mt-4 text-sm" style={{ color: "var(--color-text-muted)" }}>
        <p>
          Representative vote: <span style={{ color: "var(--color-primary)" }}>{repVote.toUpperCase()}</span>
        </p>
        <p className="mt-1">
          Your vote: <span style={{ color: "var(--color-primary)" }}>{userVote ? userVote.toUpperCase() : "Not cast"}</span>
        </p>
        <p className="mt-1">
          Alignment score: <span style={{ color: "var(--color-primary)" }}>{formatPercent(alignmentScore)}</span>
        </p>
      </div>
    </section>
  );
}
