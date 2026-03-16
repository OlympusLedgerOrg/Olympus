"use client";

import { motion } from "framer-motion";
import type { UseEggsResult } from "@/lib/hooks/useEggs";
import { formatCurrency, formatNumber, formatPercent } from "@/lib/utils/formatting";

export function EggVault({ vault }: { vault: UseEggsResult }) {
  const rarityColors = {
    common: "#94a3b8",
    rare: "#3b82f6",
    epic: "#8b5cf6",
    legendary: "#f59e0b",
    mythic: "#ec4899",
  } as const;

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
            {formatNumber(vault.totalEggs)} soulbound eggs secured
          </h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
            Active payout zone: {vault.activeLocation} · payout = rarity × discovery difficulty
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
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
                      {tier.label}
                    </p>
                    <span
                      className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.2em]"
                      style={{
                        background: `${rarityColors[tier.rarity]}22`,
                        color: rarityColors[tier.rarity],
                      }}
                    >
                      {tier.rarity}
                    </span>
                    <span className="text-[11px]" style={{ color: "var(--color-text-muted)" }}>
                      Difficulty {tier.difficulty}/5
                    </span>
                  </div>
                  <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                    {formatNumber(tier.soulboundCount)} SBTs · avg payout{" "}
                    {formatCurrency(tier.unitValue)}
                  </p>
                </div>
                <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
                  {tier.supplyLabel}
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
            disabled={!vault.canPayout}
            className="border px-4 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
            style={{
              borderColor: "var(--color-border)",
              borderRadius: "var(--radius)",
              color: "var(--color-primary)",
            }}
          >
            Burn SBTs for payout
          </button>
        </div>
        <div className="mt-4">
          <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
            Claimable payout
          </p>
          <p className="text-lg font-semibold" style={{ color: "var(--color-accent)" }}>
            {formatCurrency(vault.pendingRewards)}
          </p>
          <p className="mt-2 text-xs" style={{ color: "var(--color-text-muted)" }}>
            Minimum burn threshold: {formatCurrency(vault.minimumPayout)}
          </p>
          {!vault.canPayout ? (
            <p className="mt-2 text-xs" style={{ color: "var(--color-text-muted)" }}>
              Add more discoveries to unlock payout eligibility.
            </p>
          ) : null}
          {vault.lastClaimAmount ? (
            <p className="mt-2 text-xs" style={{ color: "var(--color-ok)" }}>
              Mock burn completed for {vault.lastBurnCount} eggs ·{" "}
              {formatCurrency(vault.lastClaimAmount)}.
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
                  Multiplier ×{preview.multiplier.toFixed(2)} · {preview.note}
                </p>
              </div>
              <p className="text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
                {formatCurrency(preview.projectedReward)}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
            Featured discoveries
          </p>
          <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
            Generic music cues with fan-recognizable patterns
          </p>
        </div>
        <div className="mt-3 space-y-3">
          {vault.featuredEggs.map((egg) => (
            <div
              key={egg.tokenId}
              className="border p-3"
              style={{
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
                background: "var(--color-surface-muted)",
              }}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
                      {egg.name}
                    </p>
                    <span
                      className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.2em]"
                      style={{
                        background: `${rarityColors[egg.rarity]}22`,
                        color: rarityColors[egg.rarity],
                      }}
                    >
                      {egg.rarity}
                    </span>
                    <span className="text-[11px]" style={{ color: "var(--color-text-muted)" }}>
                      Difficulty {egg.discoveryDifficulty}/5
                    </span>
                  </div>
                  <p className="mt-1 text-xs" style={{ color: "var(--color-text-muted)" }}>
                    {egg.description}
                  </p>
                  <p className="mt-2 text-xs" style={{ color: "var(--color-text-muted)" }}>
                    Vibe: {egg.vibe}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
                    {formatCurrency(egg.estimatedPayout)}
                  </p>
                  <p className="text-[11px]" style={{ color: "var(--color-text-muted)" }}>
                    #{egg.secretNumber ?? "—"}
                  </p>
                </div>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <span style={{ color: "var(--color-text-muted)" }}>
                  {new Date(egg.discoveredAt).toLocaleDateString()} · block {egg.discoveryBlock}
                </span>
                <span style={{ color: egg.claimedAt ? "var(--color-danger)" : "var(--color-ok)" }}>
                  {egg.claimedAt ? "Burned for payout" : "Soulbound"}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 border p-4" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold" style={{ color: "var(--color-text)" }}>
              Leaderboard + rarity index
            </p>
            <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
              Network snapshot for scarce civic and music discoveries
            </p>
          </div>
          <div className="text-right text-xs" style={{ color: "var(--color-text-muted)" }}>
            {formatNumber(vault.leaderboard.totalEggsFound)} eggs found ·{" "}
            {formatNumber(vault.leaderboard.totalMusicEggsFound)} music eggs
          </div>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div
            className="border p-3"
            style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}
          >
            <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
              Rarest egg
            </p>
            <p className="mt-2 text-sm font-semibold" style={{ color: "var(--color-text)" }}>
              {vault.leaderboard.rarestEgg.name}
            </p>
            <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
              {vault.leaderboard.rarestEgg.supply} · found by {vault.leaderboard.rarestEgg.foundBy}
            </p>
            <p className="mt-2 text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
              {formatCurrency(vault.leaderboard.rarestEgg.value)}
            </p>
          </div>

          <div
            className="border p-3"
            style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}
          >
            <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
              Top collection
            </p>
            <p className="mt-2 text-sm font-semibold" style={{ color: "var(--color-text)" }}>
              {vault.leaderboard.mostValuableCollection.holder}
            </p>
            <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
              {formatNumber(vault.leaderboard.mostValuableCollection.eggs)} eggs
            </p>
            <p className="mt-2 text-sm font-semibold" style={{ color: "var(--color-accent)" }}>
              {formatCurrency(vault.leaderboard.mostValuableCollection.value)}
            </p>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {vault.rarityBreakdown.map((item) => (
            <div
              key={item.rarity}
              className="flex items-center justify-between gap-3"
              style={{ color: "var(--color-text-muted)" }}
            >
              <div className="flex items-center gap-2">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ background: rarityColors[item.rarity] }}
                />
                <span className="text-xs uppercase tracking-[0.2em]">{item.rarity}</span>
              </div>
              <span className="text-xs font-semibold">{formatCurrency(item.value)}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
