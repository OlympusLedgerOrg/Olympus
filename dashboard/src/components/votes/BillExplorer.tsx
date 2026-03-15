import type { BillRecord, LegislationLevel, LegislationStatus } from "@/lib/mocks/bills";
import type { BillSortBy } from "@/lib/hooks/useBills";
import { VoteCard } from "@/components/votes/VoteCard";

export function BillExplorer({
  bills,
  search,
  setSearch,
  level,
  setLevel,
  billStatusFilter,
  setBillStatusFilter,
  sortBy,
  setSortBy,
}: {
  bills: BillRecord[];
  search: string;
  setSearch: (value: string) => void;
  level: LegislationLevel | "all";
  setLevel: (value: LegislationLevel | "all") => void;
  billStatusFilter: LegislationStatus | "all";
  setBillStatusFilter: (value: LegislationStatus | "all") => void;
  sortBy: BillSortBy;
  setSortBy: (value: BillSortBy) => void;
}) {
  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex-1 min-w-[220px]">
          <span className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Search bills
          </span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by bill, sponsor, or id"
            className="mt-2 w-full border px-3 py-2 text-sm"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              background: "var(--color-background)",
              color: "var(--color-text)",
            }}
          />
        </label>

        <label className="min-w-[130px]">
          <span className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Level
          </span>
          <select
            value={level}
            onChange={(event) => setLevel(event.target.value as LegislationLevel | "all")}
            className="mt-2 w-full border px-3 py-2 text-sm"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              background: "var(--color-background)",
              color: "var(--color-text)",
            }}
          >
            <option value="all">All</option>
            <option value="federal">Federal</option>
            <option value="state">State</option>
            <option value="local">Local</option>
          </select>
        </label>

        <label className="min-w-[130px]">
          <span className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Status
          </span>
          <select
            value={billStatusFilter}
            onChange={(event) => setBillStatusFilter(event.target.value as LegislationStatus | "all")}
            className="mt-2 w-full border px-3 py-2 text-sm"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              background: "var(--color-background)",
              color: "var(--color-text)",
            }}
          >
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </label>

        <label className="min-w-[140px]">
          <span className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Sort
          </span>
          <select
            value={sortBy}
            onChange={(event) => setSortBy(event.target.value as BillSortBy)}
            className="mt-2 w-full border px-3 py-2 text-sm"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              background: "var(--color-background)",
              color: "var(--color-text)",
            }}
          >
            <option value="date">Date</option>
            <option value="hotness">热度</option>
            <option value="alignment">Alignment</option>
          </select>
        </label>
      </div>

      <div className="mt-5 space-y-4">
        {bills.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-text-muted)" }}>
            No legislation matched your filters.
          </p>
        ) : (
          bills.map((bill) => <VoteCard key={bill.id} bill={bill} />)
        )}
      </div>
    </section>
  );
}
