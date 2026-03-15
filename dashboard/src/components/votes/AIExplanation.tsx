import type { BillRecord } from "@/lib/mocks/bills";

export function AIExplanation({ bill }: { bill: BillRecord }) {
  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
        AI explanation (mock)
      </p>
      <h2 className="mt-2 text-xl font-semibold" style={{ color: "var(--color-primary)" }}>
        Plain English summary
      </h2>
      <p className="mt-3 text-sm" style={{ color: "var(--color-text)" }}>
        {bill.plainEnglishSummary}
      </p>
      <p className="mt-4 text-sm" style={{ color: "var(--color-text-muted)" }}>
        <span className="font-semibold" style={{ color: "var(--color-text)" }}>
          What it means for your area:
        </span>{" "}
        {bill.areaImpact}
      </p>
      <p className="mt-4 text-sm" style={{ color: "var(--color-text-muted)" }}>
        <span className="font-semibold" style={{ color: "var(--color-text)" }}>
          Key sponsors:
        </span>{" "}
        {bill.sponsors.join(", ")}
      </p>
    </section>
  );
}
