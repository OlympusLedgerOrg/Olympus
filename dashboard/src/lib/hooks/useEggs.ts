"use client";

import { useMemo, useState } from "react";
import {
  buildTierSummaries,
  calculateCollectionValue,
  calculateEggPayoutValue,
  mockEggCollection,
  mockEggLeaderboard,
  mockEggVaultMeta,
  mockPayoutPreview,
} from "@/lib/mocks/eggs";

export function useEggs() {
  const [claimedAt, setClaimedAt] = useState<string | null>(null);
  const [lastClaimAmount, setLastClaimAmount] = useState<number | null>(null);
  const [lastBurnCount, setLastBurnCount] = useState(0);
  const [claimAnnouncement, setClaimAnnouncement] = useState("");

  const eggs = useMemo(
    () =>
      mockEggCollection.map((egg) =>
        claimedAt
          ? {
              ...egg,
              claimedAt,
              burnedInTx: `0xburn${egg.tokenId.replace(/[^0-9]/g, "").padStart(4, "0")}`,
            }
          : egg,
      ),
    [claimedAt],
  );

  const eligibleEggs = useMemo(() => eggs.filter((egg) => !egg.claimedAt), [eggs]);

  const totalCollectionValue = useMemo(
    () => calculateCollectionValue(eggs, mockEggVaultMeta.activeLocation),
    [eggs],
  );

  const claimableCollectionValue = useMemo(
    () => calculateCollectionValue(eligibleEggs, mockEggVaultMeta.activeLocation),
    [eligibleEggs],
  );

  const totalEggs = useMemo(() => eggs.length, [eggs]);

  const totalValue = totalCollectionValue.total;

  const tiers = useMemo(
    () => buildTierSummaries(eggs, mockEggVaultMeta.activeLocation),
    [eggs],
  );

  const nextUnlock = useMemo(
    () => tiers.find((tier) => tier.progressCurrent < tier.progressTarget) ?? tiers[tiers.length - 1],
    [tiers],
  );

  const pendingRewards = claimableCollectionValue.total;
  const canPayout = claimableCollectionValue.canPayout;

  const featuredEggs = useMemo(
    () =>
      eggs
        .map((egg) => ({
          ...egg,
          estimatedPayout: calculateEggPayoutValue(egg, mockEggVaultMeta.activeLocation),
        }))
        .sort((left, right) => right.estimatedPayout - left.estimatedPayout)
        .slice(0, 4),
    [eggs],
  );

  const rarityBreakdown = useMemo(
    () =>
      (Object.entries(totalCollectionValue.breakdown.byRarity) as Array<[string, number]>)
        .map(([rarity, value]) => ({
          rarity,
          value,
        }))
        .sort((left, right) => right.value - left.value),
    [totalCollectionValue],
  );

  const payoutPreview = useMemo(
    () =>
      mockPayoutPreview.map((preview) => ({
        ...preview,
        projectedReward: pendingRewards * preview.multiplier,
      })),
    [pendingRewards],
  );

  const claimRewards = () => {
    if (!canPayout || claimedAt) {
      return;
    }

    setLastClaimAmount(pendingRewards);
    setLastBurnCount(eligibleEggs.length);
    setClaimedAt(new Date().toISOString());
    setClaimAnnouncement(
      `Burned ${eligibleEggs.length} soulbound eggs for $${pendingRewards.toFixed(2)}.`,
    );
  };

  return {
    activeLocation: mockEggVaultMeta.activeLocation,
    canPayout,
    claimRewards,
    claimAnnouncement,
    featuredEggs,
    lastClaimAmount,
    lastBurnCount,
    leaderboard: mockEggLeaderboard,
    minimumPayout: mockEggVaultMeta.minimumPayout,
    nextUnlock,
    payoutPreview,
    pendingRewards,
    rarityBreakdown,
    tiers,
    totalEggs,
    totalValue,
  };
}

export type UseEggsResult = ReturnType<typeof useEggs>;
