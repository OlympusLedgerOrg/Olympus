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
  type EggRarity,
} from "@/lib/mocks/eggs";

function createMockBurnTxHash(tokenId: string): string {
  const tokenHex = tokenId
    .split("")
    .map((character) => character.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 64);

  return `0x${tokenHex.padEnd(64, "0")}`;
}

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
              burnedInTx: createMockBurnTxHash(egg.tokenId),
            }
          : egg,
      ),
    [claimedAt],
  );

  const eligibleEggs = useMemo(() => eggs.filter((egg) => !egg.claimedAt), [eggs]);

  const totalCollectionValue = useMemo(
    () => calculateCollectionValue(eggs),
    [eggs],
  );

  const claimableCollectionValue = useMemo(
    () => calculateCollectionValue(eligibleEggs),
    [eligibleEggs],
  );

  const totalEggs = useMemo(() => eggs.length, [eggs]);

  const totalValue = totalCollectionValue.total;

  const tiers = useMemo(
    () => buildTierSummaries(eggs),
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
          estimatedPayout: calculateEggPayoutValue(egg),
        }))
        .sort((left, right) => right.estimatedPayout - left.estimatedPayout)
        .slice(0, 4),
    [eggs],
  );

  const rarityBreakdown = useMemo(
    () =>
      (Object.entries(totalCollectionValue.breakdown.byRarity) as Array<[EggRarity, number]>)
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
    if (claimedAt) {
      setClaimAnnouncement("Soulbound payout already completed for this mock collection.");
      return;
    }

    if (!canPayout) {
      setClaimAnnouncement(
        `You need at least $${mockEggVaultMeta.minimumPayout.toFixed(2)} to burn for payout.`,
      );
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
