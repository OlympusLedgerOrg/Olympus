"use client";

import { useMemo, useState } from "react";
import {
  mockEggTiers,
  mockEggVaultMeta,
  mockPayoutPreview,
} from "@/lib/mocks/eggs";

export function useEggs() {
  const [pendingRewards, setPendingRewards] = useState(mockEggVaultMeta.pendingRewards);
  const [lastClaimAmount, setLastClaimAmount] = useState<number | null>(null);
  const [claimAnnouncement, setClaimAnnouncement] = useState("");

  const totalEggs = useMemo(
    () => mockEggTiers.reduce((sum, tier) => sum + tier.count, 0),
    [],
  );

  const totalValue = useMemo(
    () => mockEggTiers.reduce((sum, tier) => sum + tier.count * tier.unitValue, 0),
    [],
  );

  const nextUnlock = useMemo(
    () =>
      mockEggTiers.find((tier) => tier.progressCurrent < tier.progressTarget) ??
      mockEggTiers[mockEggTiers.length - 1],
    [],
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
    if (pendingRewards <= 0) {
      return;
    }

    // Mock-only claim flow: reflect a successful payout locally without backend I/O.
    setLastClaimAmount(pendingRewards);
    setClaimAnnouncement(`Rewards claimed for $${pendingRewards.toFixed(2)}.`);
    setPendingRewards(0);
  };

  return {
    activeLocation: mockEggVaultMeta.activeLocation,
    claimRewards,
    claimAnnouncement,
    lastClaimAmount,
    nextUnlock,
    payoutPreview,
    pendingRewards,
    tiers: mockEggTiers,
    totalEggs,
    totalValue,
  };
}

export type UseEggsResult = ReturnType<typeof useEggs>;
