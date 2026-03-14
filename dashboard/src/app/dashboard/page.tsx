"use client";

import Link from "next/link";
import { VerificationBadge } from "@/components/auth/VerificationBadge";
import { ActivityCard } from "@/components/dashboard/ActivityCard";
import { EggVault } from "@/components/dashboard/EggVault";
import { ProofStream } from "@/components/dashboard/ProofStream";
import { QuickStats } from "@/components/dashboard/QuickStats";
import { useEggs } from "@/lib/hooks/useEggs";
import { useProofs } from "@/lib/hooks/useProofs";
import { useTheme } from "@/lib/hooks/useTheme";
import { formatCurrency, formatNumber } from "@/lib/utils/formatting";

export default function DashboardPage() {
  const { theme } = useTheme();
  const proofStream = useProofs();
  const eggVault = useEggs();

  const recentActivity = [
    ...proofStream.filteredProofs.slice(0, 2).map((proof) => ({
      id: proof.id,
      title: proof.title,
      description: proof.summary,
      timestamp: proof.createdAt,
      category: proof.type,
      metric: proof.blockLabel,
      amount: proof.rewardDelta * 0.85,
    })),
    {
      id: "vault-preview",
      title: "Rewards preview refreshed",
      description: `Pending payout recalculated for ${eggVault.activeLocation}.`,
      timestamp:
        proofStream.visibleProofs[0]?.createdAt ?? proofStream.filteredProofs[0]?.createdAt,
      category: "egg vault",
      metric: "location-adjusted",
      amount: eggVault.pendingRewards,
    },
  ];

  const quickStats = [
    {
      label: "Proof count",
      value: formatNumber(proofStream.totalProofs),
      detail: "Live relay + historical verifications",
    },
    {
      label: "Egg count",
      value: formatNumber(eggVault.totalEggs),
      detail: "Bronze through mythic vault holdings",
    },
    {
      label: "Pending rewards",
      value: formatCurrency(eggVault.pendingRewards),
      detail: "Mock claimable value at current location",
    },
    {
      label: "Active theme",
      value: theme,
      detail: "Palette and motion adapt to the current theme",
    },
  ];

  return (
    <main className="flex min-h-screen flex-col items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full max-w-7xl space-y-6">
        <header className="space-y-4">
          <h1
            className="text-3xl font-bold tracking-tight sm:text-4xl"
            style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}
          >
            Civic Dashboard
          </h1>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <p className="max-w-2xl" style={{ color: "var(--color-text-muted)" }}>
              Verified humans can access Olympus Civic features, inspect live proof
              activity, and preview egg rewards with theme-aware visibility across
              mobile, tablet, and desktop views.
            </p>
            <div className="text-sm" style={{ color: "var(--color-text-muted)" }}>
              12-column responsive layout · active theme <span style={{ color: "var(--color-primary)" }}>{theme}</span>
            </div>
          </div>
        </header>

        <VerificationBadge />

        <QuickStats items={quickStats} />

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-6 xl:col-span-8">
            <ProofStream
              filter={proofStream.filter}
              hasMore={proofStream.hasMore}
              liveCount={proofStream.liveCount}
              onCloseProof={proofStream.closeProof}
              onFilterChange={proofStream.setFilter}
              onLoadMore={proofStream.loadMore}
              onOpenProof={proofStream.openProof}
              proofs={proofStream.visibleProofs}
              selectedProof={proofStream.selectedProof}
              totalProofs={proofStream.totalProofs}
            />
          </div>

          <div className="space-y-6 xl:col-span-4">
            <EggVault vault={eggVault} />

            <section
              className="border p-5"
              style={{
                background: "var(--color-surface)",
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
            >
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p
                    className="text-xs uppercase tracking-[0.3em]"
                    style={{ color: "var(--color-text-muted)" }}
                  >
                    Recent activity
                  </p>
                  <h2 className="mt-2 text-xl font-semibold" style={{ color: "var(--color-primary)" }}>
                    What moved most recently
                  </h2>
                </div>
                <Link
                  href="/auth"
                  className="text-sm font-semibold"
                  style={{ color: "var(--color-primary)" }}
                >
                  Manage verification →
                </Link>
              </div>

              <div className="mt-5 space-y-3">
                {recentActivity.map((activity, index) => (
                  <ActivityCard
                    key={activity.id}
                    activity={activity}
                    priority={index === 0}
                  />
                ))}
              </div>
            </section>
          </div>
        </div>
      </div>
    </main>
  );
}
