"use client";

import { motion } from "framer-motion";
import type { UseEggsResult } from "@/lib/hooks/useEggs";
import { formatCurrency, formatNumber, formatPercent } from "@/lib/utils/formatting";

export function EggVault({ vault }: { vault: UseEggsResult }) {
  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p
            className="text-xs uppercase tracking-[0.3em]"
            style={{ color: "var(--color-text-muted)" }}
          >
            Egg Vault
          </p>
          <h2 className="mt-2 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
            {formatNumber(vault.totalEggs)} eggs secured
          </h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
            Active payout zone: {vault.activeLocation}
          </p>
        </div>
        <div className="text-right">
          <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
            Total vault value
          </p>
          <p className="text-xl font-semibold" style={{ color: "var(--color-accent)" }}>
            {formatCurrency(vault.totalValue)}
          </p>
        </div>
      </div>

      <div className="mt-6 space-y-4">
        {vault.tiers.map((tier) => {
          const progress = (tier.progressCurrent / tier.progressTarget) * 100;

          return (
            <div key={tier.tier} className="space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
                    {tier.label}
                  </p>
                  <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                    {formatNumber(tier.count)} eggs · {formatCurrency(tier.count * tier.unitValue)}
                  </p>
                </div>
                <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                  {tier.progressCurrent}/{tier.progressTarget} to next boost
                </p>
              </div>
              <div
                className="h-2 overflow-hidden"
                style={{
                  background: "var(--color-surface-muted)",
                  borderRadius: "999px",
                }}
              >
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.min(progress, 100)}%` }}
                  transition={{ duration: 0.5 }}
                  className="h-full"
                  style={{
                    background: `linear-gradient(90deg, ${tier.accent}, var(--color-primary))`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div
        className="mt-6 border p-4"
        style={{
          background: "var(--color-surface-muted)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
        }}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
              Next tier progress
            </p>
            <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
              {vault.nextUnlock.label} unlock at{" "}
              {formatPercent((vault.nextUnlock.progressCurrent / vault.nextUnlock.progressTarget) * 100)}
            </p>
          </div>
          <button
            type="button"
            onClick={vault.claimRewards}
            disabled={vault.pendingRewards <= 0}
            className="border px-4 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              color: "var(--color-primary)",
            }}
          >
            Claim rewards
          </button>
        </div>
        <div className="mt-4">
          <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
            Pending rewards
          </p>
          <p className="text-lg font-semibold" style={{ color: "var(--color-accent)" }}>
            {formatCurrency(vault.pendingRewards)}
          </p>
          {vault.lastClaimAmount ? (
            <p className="mt-2 text-xs" style={{ color: "var(--color-ok)" }}>
              Mock claim completed for {formatCurrency(vault.lastClaimAmount)}.
            </p>
          ) : null}
          <p className="sr-only" aria-live="polite">
            {vault.claimAnnouncement}
          </p>
        </div>
      </div>

      <div className="mt-6">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
            Location-adjusted payout preview
          </p>
          <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
            Preview only
          </p>
        </div>
        <div className="mt-3 space-y-3">
          {vault.payoutPreview.map((preview) => (
            <div
              key={preview.label}
              className="flex items-center justify-between gap-3 border-b pb-3 last:border-b-0 last:pb-0"
              style={{ borderColor: "var(--color-border)" }}
            >
              <div>
                <p className="text-sm" style={{ color: "var(--color-text)" }}>
                  {preview.label}
                </p>
                <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                  Multiplier ×{preview.multiplier.toFixed(2)}
                </p>
              </div>
              <p className="text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
                {formatCurrency(preview.projectedReward)}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
