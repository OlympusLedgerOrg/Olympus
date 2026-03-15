"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { AIExplanation } from "@/components/votes/AIExplanation";
import { DistrictConsensus } from "@/components/votes/DistrictConsensus";
import { VoteInterface } from "@/components/votes/VoteInterface";
import { useBills } from "@/lib/hooks/useBills";
import { useVotes } from "@/lib/hooks/useVotes";

export default function BillVoteDetailPage() {
  const params = useParams<{ billId: string }>();
  const billId = params.billId;
  const bills = useBills();
  const votes = useVotes(billId);
  const bill = bills.allBills.find((item) => item.id === billId) ?? null;

  if (!bill) {
    return (
      <main className="flex min-h-screen flex-col items-center px-4 py-8 sm:px-6 sm:py-12">
        <div className="w-full max-w-3xl space-y-4">
          <h1 className="text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
            Bill not found
          </h1>
          <p style={{ color: "var(--color-text-muted)" }}>
            The requested legislation record could not be located.
          </p>
          <Link href="/dashboard/votes" className="font-semibold" style={{ color: "var(--color-primary)" }}>
            ← Back to bill explorer
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen flex-col items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full max-w-6xl space-y-6">
        <header className="space-y-4">
          <Link href="/dashboard/votes" className="text-sm font-semibold" style={{ color: "var(--color-primary)" }}>
            ← Back to explorer
          </Link>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl" style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}>
            {bill.title}
          </h1>
          <p style={{ color: "var(--color-text-muted)" }}>
            {bill.id.toUpperCase()} · {bill.level} · Rep vote {bill.repVote.toUpperCase()} ({bill.repName})
          </p>
          {votes.error ? <p className="text-sm" style={{ color: "var(--color-danger)" }}>{votes.error}</p> : null}
        </header>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-6 xl:col-span-7">
            <AIExplanation bill={bill} />
            {votes.snapshot ? (
              <DistrictConsensus
                totals={votes.snapshot.totals}
                consensusPct={votes.snapshot.consensusPct}
                repVote={votes.snapshot.repVote}
                userVote={votes.snapshot.userVote}
                alignmentScore={votes.snapshot.alignmentScore}
              />
            ) : null}
          </div>

          <div className="space-y-6 xl:col-span-5">
            <VoteInterface
              selectedVote={votes.snapshot?.userVote ?? null}
              onVote={(vote) => {
                void votes.castVote(vote);
              }}
              status={votes.status}
              justEarned={votes.rewards.justEarned}
              totalEggs={votes.rewards.totalEggs}
            />
          </div>
        </div>
      </div>
    </main>
  );
}
