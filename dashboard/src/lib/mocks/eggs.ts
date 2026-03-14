export type EggTier = "bronze" | "silver" | "gold" | "mythic";

export interface EggTierSummary {
  tier: EggTier;
  label: string;
  count: number;
  unitValue: number;
  progressCurrent: number;
  progressTarget: number;
  accent: string;
}

export interface LocationPayoutPreview {
  label: string;
  multiplier: number;
}

export const mockEggTiers: EggTierSummary[] = [
  {
    tier: "bronze",
    label: "Bronze",
    count: 42,
    unitValue: 1.25,
    progressCurrent: 42,
    progressTarget: 60,
    accent: "#b45309",
  },
  {
    tier: "silver",
    label: "Silver",
    count: 18,
    unitValue: 2.4,
    progressCurrent: 18,
    progressTarget: 24,
    accent: "#94a3b8",
  },
  {
    tier: "gold",
    label: "Gold",
    count: 7,
    unitValue: 4.8,
    progressCurrent: 7,
    progressTarget: 10,
    accent: "#ca8a04",
  },
  {
    tier: "mythic",
    label: "Mythic",
    count: 2,
    unitValue: 12,
    progressCurrent: 2,
    progressTarget: 5,
    accent: "#7c3aed",
  },
];

export const mockPayoutPreview: LocationPayoutPreview[] = [
  { label: "ZIP3 local baseline", multiplier: 1 },
  { label: "Regional density uplift", multiplier: 1.14 },
  { label: "Civic priority district", multiplier: 1.28 },
];

export const mockEggVaultMeta = {
  activeLocation: "ZIP3 · 021",
  pendingRewards: 63.4,
};
