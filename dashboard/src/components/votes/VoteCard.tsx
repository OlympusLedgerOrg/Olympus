import Link from "next/link";
import type { BillRecord } from "@/lib/mocks/bills";
import { formatPercent } from "@/lib/utils/formatting";

export function VoteCard({ bill }: { bill: BillRecord }) {
  return (
    <article
      className="border p-4"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
          <span>{bill.level}</span>
          <span>•</span>
          <span style={{ color: bill.status === "active" ? "var(--color-ok)" : "var(--color-text-muted)" }}>
            {bill.status}
          </span>
          <span>•</span>
          <span>{new Date(bill.introducedAt).toLocaleDateString("en-US")}</span>
        </div>
        <p className="text-xs" style={{ color: "var(--color-accent)" }}>
          热度 {bill.hotness}
        </p>
      </div>

      <h3 className="mt-3 text-lg font-semibold" style={{ color: "var(--color-primary)" }}>
        {bill.title}
      </h3>
      <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
        {bill.plainEnglishSummary}
      </p>
      <p className="mt-3 text-sm" style={{ color: "var(--color-text-muted)" }}>
        Key sponsors: {bill.sponsors.join(", ")}
      </p>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm">
        <p style={{ color: "var(--color-text-muted)" }}>
          Baseline alignment {formatPercent(bill.alignmentBaseline)} · Rep vote {bill.repVote.toUpperCase()}
        </p>
        <Link href={`/dashboard/votes/${bill.id}`} className="font-semibold" style={{ color: "var(--color-primary)" }}>
          Open vote →
        </Link>
      </div>
    </article>
  );
}
