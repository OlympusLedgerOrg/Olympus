"use client";

import Link from "next/link";
import { BillExplorer } from "@/components/votes/BillExplorer";
import { useBills } from "@/lib/hooks/useBills";
import { useVotes } from "@/lib/hooks/useVotes";

export default function VotesDashboardPage() {
  const bills = useBills();
  const votes = useVotes();

  return (
    <main className="flex min-h-screen flex-col items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full max-w-7xl space-y-6">
        <header className="space-y-4">
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl" style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}>
            Bill Explorer + Symbolic Voting
          </h1>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <p className="max-w-3xl" style={{ color: "var(--color-text-muted)" }}>
              Browse active and inactive legislation, read plain-English mock AI summaries, cast a symbolic vote, and compare your vote against district consensus and representative positions in real time.
            </p>
            <div className="text-sm" style={{ color: "var(--color-text-muted)" }}>
              Source: {bills.source} · Updated {new Date(bills.updatedAt).toLocaleString("en-US")}
            </div>
          </div>
          {bills.error ? <p className="text-sm" style={{ color: "var(--color-danger)" }}>{bills.error}</p> : null}
        </header>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-6 xl:col-span-8">
            <BillExplorer
              bills={bills.bills}
              search={bills.search}
              setSearch={bills.setSearch}
              level={bills.level}
              setLevel={bills.setLevel}
              billStatusFilter={bills.billStatusFilter}
              setBillStatusFilter={bills.setBillStatusFilter}
              sortBy={bills.sortBy}
              setSortBy={bills.setSortBy}
            />
          </div>

          <aside className="space-y-6 xl:col-span-4">
            <section className="border p-5" style={{ background: "var(--color-surface)", borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
              <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
                Vote rewards
              </p>
              <h2 className="mt-2 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
                {votes.rewards.totalEggs} eggs
              </h2>
              <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
                Votes cast: {votes.rewards.votesCast}
              </p>
            </section>

            <section className="border p-5" style={{ background: "var(--color-surface)", borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
                  Your vote history
                </p>
                {votes.updatedAt ? (
                  <span className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                    Live {new Date(votes.updatedAt).toLocaleTimeString("en-US")}
                  </span>
                ) : null}
              </div>

              <div className="mt-4 space-y-3">
                {votes.history.length === 0 ? (
                  <p className="text-sm" style={{ color: "var(--color-text-muted)" }}>
                    No symbolic votes yet.
                  </p>
                ) : (
                  votes.history.map((entry) => (
                    <div key={`${entry.billId}-${entry.updatedAt}`} className="border p-3" style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}>
                      <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
                        {entry.billId.toUpperCase()} · {entry.vote.toUpperCase()}
                      </p>
                      <p className="mt-1 text-xs" style={{ color: "var(--color-text-muted)" }}>
                        District {entry.district} · {new Date(entry.updatedAt).toLocaleString("en-US")}
                      </p>
                      <Link href={`/dashboard/votes/${entry.billId}`} className="mt-2 inline-block text-xs font-semibold" style={{ color: "var(--color-primary)" }}>
                        Open bill →
                      </Link>
                    </div>
                  ))
                )}
              </div>
            </section>
          </aside>
        </div>
      </div>
    </main>
  );
}
