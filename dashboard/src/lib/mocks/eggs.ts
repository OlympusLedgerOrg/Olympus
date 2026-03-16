export type EggTier = "bronze" | "silver" | "gold" | "mythic" | "music";
export type EggRarity = "common" | "rare" | "epic" | "legendary" | "mythic";
export type DiscoveryDifficulty = 1 | 2 | 3 | 4 | 5;
export type EggAesthetic =
  | "first-light"
  | "lucky"
  | "manuscript"
  | "polaroid"
  | "romance"
  | "serpent"
  | "twilight"
  | "vault"
  | "woodland";

export interface EggSBT {
  tokenId: string;
  eggId: string;
  tier: EggTier;
  rarity: EggRarity;
  discoveryDifficulty: DiscoveryDifficulty;
  discoveredBy: string;
  discoveredAt: string;
  discoveryMethod: string;
  discoveryBlock: number;
  proofHash: string;
  ledgerEntry: string;
  name: string;
  description: string;
  image: string;
  aesthetic?: EggAesthetic;
  secretNumber?: number;
  vibe?: string;
  payoutMultiplier: number;
  claimedAt?: string;
  burnedInTx?: string;
}

export interface MusicEggDefinition {
  id: string;
  name: string;
  tier: "music";
  rarity: EggRarity;
  difficulty: DiscoveryDifficulty;
  description: string;
  hint: string;
  discoveryMethod: string;
  rewardMultiplier: number;
  secretNumber: number;
  vibe: string;
  aesthetic: EggAesthetic;
  maxSupply: number;
  currentSupply: number;
}

export interface EggTierSummary {
  tier: EggTier;
  label: string;
  count: number;
  unitValue: number;
  progressCurrent: number;
  progressTarget: number;
  accent: string;
  rarity: EggRarity;
  difficulty: DiscoveryDifficulty;
  soulboundCount: number;
  supplyLabel: string;
}

export interface LocationPayoutPreview {
  label: string;
  multiplier: number;
  note: string;
}

export interface CollectionValueBreakdown {
  byTier: Partial<Record<EggTier, number>>;
  byRarity: Partial<Record<EggRarity, number>>;
  byDifficulty: Partial<Record<DiscoveryDifficulty, number>>;
}

export interface CollectionValue {
  total: number;
  breakdown: CollectionValueBreakdown;
  canPayout: boolean;
}

export interface EggLeaderboardStats {
  totalEggsFound: number;
  totalMusicEggsFound: number;
  rarestEgg: {
    name: string;
    foundBy: string;
    supply: string;
    value: number;
  };
  mostValuableCollection: {
    holder: string;
    value: number;
    eggs: number;
  };
  byRarity: Record<
    EggRarity,
    {
      total: number;
      uniqueHolders: number;
    }
  >;
}

const TIER_VALUES: Record<EggTier, number> = {
  bronze: 0.25,
  silver: 0.5,
  gold: 1,
  mythic: 2.5,
  music: 13,
};

const RARITY_MULTIPLIERS: Record<EggRarity, number> = {
  common: 1,
  rare: 2,
  epic: 4,
  legendary: 8,
  mythic: 16,
};

const DIFFICULTY_MULTIPLIERS: Record<DiscoveryDifficulty, number> = {
  1: 1,
  2: 1.5,
  3: 2,
  4: 3,
  5: 5,
};

const AESTHETIC_MULTIPLIERS: Record<EggAesthetic, number> = {
  "first-light": 1.13,
  lucky: 1.13,
  manuscript: 1.13,
  polaroid: 1.13,
  romance: 1.13,
  serpent: 1.13,
  twilight: 1.13,
  vault: 2.13,
  woodland: 1.13,
};

const TIER_META: Record<
  EggTier,
  {
    label: string;
    accent: string;
    progressTarget: number;
    rarity: EggRarity;
    difficulty: DiscoveryDifficulty;
  }
> = {
  bronze: {
    label: "Bronze",
    accent: "#b45309",
    progressTarget: 3,
    rarity: "common",
    difficulty: 1,
  },
  silver: {
    label: "Silver",
    accent: "#94a3b8",
    progressTarget: 2,
    rarity: "rare",
    difficulty: 2,
  },
  gold: {
    label: "Gold",
    accent: "#ca8a04",
    progressTarget: 2,
    rarity: "epic",
    difficulty: 3,
  },
  mythic: {
    label: "Mythic",
    accent: "#7c3aed",
    progressTarget: 2,
    rarity: "legendary",
    difficulty: 4,
  },
  music: {
    label: "Music",
    accent: "#ec4899",
    progressTarget: 5,
    rarity: "mythic",
    difficulty: 5,
  },
};

const PAYOUT_CAPS: Record<string, number> = {
  "ZIP3 · 021": 65000,
  "ZIP3 · 606": 65000,
};

export const MUSIC_EGGS: MusicEggDefinition[] = [
  {
    id: "lucky-13",
    name: "The Lucky Number",
    tier: "music",
    rarity: "legendary",
    difficulty: 4,
    description: "Found at the perfect moment.",
    hint: "Some numbers are luckier than others.",
    discoveryMethod: "Click during the perfect moment of any minute.",
    rewardMultiplier: 5,
    secretNumber: 13,
    vibe: "A feeling of youthful confusion and defiance.",
    aesthetic: "lucky",
    maxSupply: 13,
    currentSupply: 4,
  },
  {
    id: "golden-era",
    name: "The Golden Era",
    tier: "music",
    rarity: "epic",
    difficulty: 5,
    description: "Found by true believers.",
    hint: "The year that changed everything.",
    discoveryMethod: "Show your dedication 1989 times.",
    rewardMultiplier: 8,
    secretNumber: 1989,
    vibe: "Youthful freedom in a vibrant city.",
    aesthetic: "polaroid",
    maxSupply: 89,
    currentSupply: 18,
  },
  {
    id: "snake-king",
    name: "The Snake King",
    tier: "music",
    rarity: "legendary",
    difficulty: 5,
    description: "Rise from the ashes.",
    hint: "Leave the old version behind.",
    discoveryMethod: "Score 13 in the hidden snake game.",
    rewardMultiplier: 7.5,
    secretNumber: 13,
    vibe: "A declaration that past versions of oneself are gone.",
    aesthetic: "serpent",
    maxSupply: 13,
    currentSupply: 7,
  },
  {
    id: "pulled-thread",
    name: "The Pulled Thread",
    tier: "music",
    rarity: "mythic",
    difficulty: 5,
    description: "Something old, something new.",
    hint: "Comfort can hide in unexpected places.",
    discoveryMethod: "Find the 1-in-a-million brown glyph.",
    rewardMultiplier: 13,
    secretNumber: 1,
    vibe: "Comfort found in unexpected places.",
    aesthetic: "woodland",
    maxSupply: 1,
    currentSupply: 1,
  },
  {
    id: "the-manuscript",
    name: "The Manuscript",
    tier: "music",
    rarity: "legendary",
    difficulty: 4,
    description: "What remains when everything else is gone.",
    hint: "The only thing left is the record.",
    discoveryMethod: 'Type "the manuscript" in the document viewer.',
    rewardMultiplier: 6,
    secretNumber: 13,
    vibe: "Quiet closure after a long chapter.",
    aesthetic: "manuscript",
    maxSupply: 13,
    currentSupply: 5,
  },
  {
    id: "mysterious-door",
    name: "The Mysterious Door",
    tier: "music",
    rarity: "epic",
    difficulty: 4,
    description: "It only opens when you least expect it.",
    hint: "The witching hour has its own rules.",
    discoveryMethod: "Click the mysterious door at 3 AM or 3 PM.",
    rewardMultiplier: 5.5,
    secretNumber: 3,
    vibe: "A quiet detour into a colder season.",
    aesthetic: "twilight",
    maxSupply: 89,
    currentSupply: 21,
  },
  {
    id: "lucky-visitor",
    name: "The Lucky Visitor",
    tier: "music",
    rarity: "rare",
    difficulty: 3,
    description: "Some people have all the luck.",
    hint: "The thirteenth time changes everything.",
    discoveryMethod: "Visit the site 13 times.",
    rewardMultiplier: 4,
    secretNumber: 13,
    vibe: "A red-hot streak of sudden fortune.",
    aesthetic: "lucky",
    maxSupply: 1300,
    currentSupply: 211,
  },
  {
    id: "declaration",
    name: "The Declaration",
    tier: "music",
    rarity: "epic",
    difficulty: 4,
    description: "Say it now or lose the moment.",
    hint: "A sudden interruption changes the room.",
    discoveryMethod: "Hover over the title 13 times.",
    rewardMultiplier: 5,
    secretNumber: 13,
    vibe: "A bold decision made without permission.",
    aesthetic: "manuscript",
    maxSupply: 89,
    currentSupply: 16,
  },
  {
    id: "witching-hour",
    name: "The Witching Hour",
    tier: "music",
    rarity: "legendary",
    difficulty: 5,
    description: "The late-night version has extra secrets.",
    hint: "Look for 13 hidden tracks after midnight.",
    discoveryMethod: "Find all 13 hidden tracks at the witching hour.",
    rewardMultiplier: 8,
    secretNumber: 3,
    vibe: "Restless thoughts in a city that never sleeps.",
    aesthetic: "twilight",
    maxSupply: 13,
    currentSupply: 3,
  },
  {
    id: "year-that-changed-everything",
    name: "The Year That Changed Everything",
    tier: "music",
    rarity: "legendary",
    difficulty: 5,
    description: "A date that turns into lore.",
    hint: "The 89th day is the one to watch.",
    discoveryMethod: "Visit on the 89th day of the year.",
    rewardMultiplier: 7.5,
    secretNumber: 89,
    vibe: "A flashbulb memory of reinvention.",
    aesthetic: "polaroid",
    maxSupply: 89,
    currentSupply: 11,
  },
  {
    id: "where-it-began",
    name: "Where It All Began",
    tier: "music",
    rarity: "rare",
    difficulty: 3,
    description: "The first of many.",
    hint: "Be among the first and stay curious.",
    discoveryMethod: "Be among the first 1000 users.",
    rewardMultiplier: 3.5,
    secretNumber: 2006,
    vibe: "Small-town optimism at the start of something bigger.",
    aesthetic: "first-light",
    maxSupply: 1000,
    currentSupply: 612,
  },
  {
    id: "valentine",
    name: "The Valentine",
    tier: "music",
    rarity: "rare",
    difficulty: 3,
    description: "Love in the time of civic engagement.",
    hint: "Share the proof with someone you trust.",
    discoveryMethod: "Share a verified vote with someone.",
    rewardMultiplier: 3.5,
    secretNumber: 14,
    vibe: "A bright, open-hearted celebration.",
    aesthetic: "romance",
    maxSupply: 1300,
    currentSupply: 248,
  },
  {
    id: "the-vault",
    name: "From The Vault",
    tier: "music",
    rarity: "mythic",
    difficulty: 5,
    description: "Things kept hidden, finally revealed.",
    hint: "Look in the most unexpected place.",
    discoveryMethod: "Find the secret vault in the codebase.",
    rewardMultiplier: 13,
    secretNumber: 13,
    vibe: "A lost recording uncovered after years in storage.",
    aesthetic: "vault",
    maxSupply: 1,
    currentSupply: 0,
  },
];

export function calculateEggPayoutValue(egg: EggSBT, userLocation: string): number {
  let value = TIER_VALUES[egg.tier];
  value *= RARITY_MULTIPLIERS[egg.rarity];
  value *= DIFFICULTY_MULTIPLIERS[egg.discoveryDifficulty];

  if (egg.aesthetic) {
    value *= AESTHETIC_MULTIPLIERS[egg.aesthetic];
  }

  return Math.min(value, PAYOUT_CAPS[userLocation] ?? 65000);
}

export function calculateCollectionValue(eggs: EggSBT[], userLocation: string): CollectionValue {
  const breakdown: CollectionValueBreakdown = {
    byTier: {},
    byRarity: {},
    byDifficulty: {},
  };

  const total = eggs.reduce((sum, egg) => {
    const value = calculateEggPayoutValue(egg, userLocation);

    breakdown.byTier[egg.tier] = (breakdown.byTier[egg.tier] ?? 0) + value;
    breakdown.byRarity[egg.rarity] = (breakdown.byRarity[egg.rarity] ?? 0) + value;
    breakdown.byDifficulty[egg.discoveryDifficulty] =
      (breakdown.byDifficulty[egg.discoveryDifficulty] ?? 0) + value;

    return sum + value;
  }, 0);

  return {
    total,
    breakdown,
    canPayout: total >= 100,
  };
}

export function buildTierSummaries(eggs: EggSBT[], userLocation: string): EggTierSummary[] {
  return (Object.keys(TIER_META) as EggTier[]).map((tier) => {
    const tierEggs = eggs.filter((egg) => egg.tier === tier);
    const tierValue = tierEggs.reduce(
      (sum, egg) => sum + calculateEggPayoutValue(egg, userLocation),
      0,
    );
    const meta = TIER_META[tier];

    return {
      tier,
      label: meta.label,
      count: tierEggs.length,
      unitValue: tierEggs.length > 0 ? tierValue / tierEggs.length : 0,
      progressCurrent: tierEggs.length,
      progressTarget: meta.progressTarget,
      accent: meta.accent,
      rarity: meta.rarity,
      difficulty: meta.difficulty,
      soulboundCount: tierEggs.length,
      supplyLabel:
        tier === "music"
          ? `${tierEggs.length}/${meta.progressTarget} music discoveries highlighted`
          : `${tierEggs.length} civic SBT${tierEggs.length === 1 ? "" : "s"} secured`,
    };
  });
}

const now = Date.now();

export const mockEggCollection: EggSBT[] = [
  {
    tokenId: "egg-sbt-001",
    eggId: "ballot-witness",
    tier: "bronze",
    rarity: "common",
    discoveryDifficulty: 1,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 24 * 14).toISOString(),
    discoveryMethod: "Verified a local ballot receipt.",
    discoveryBlock: 198401,
    proofHash: "b3:01f2ac91",
    ledgerEntry: "ledger:egg:001",
    name: "Ballot Witness",
    description: "Earned by completing a verified civic action.",
    image: "ipfs://egg-vault/ballot-witness.png",
    vibe: "Steady participation in public life.",
    payoutMultiplier: 1,
  },
  {
    tokenId: "egg-sbt-002",
    eggId: "streak-keeper",
    tier: "silver",
    rarity: "rare",
    discoveryDifficulty: 2,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 24 * 10).toISOString(),
    discoveryMethod: "Maintained a nine-proof verification streak.",
    discoveryBlock: 198544,
    proofHash: "b3:021afee4",
    ledgerEntry: "ledger:egg:002",
    name: "Streak Keeper",
    description: "Rewards consistent participation over time.",
    image: "ipfs://egg-vault/streak-keeper.png",
    vibe: "Momentum built through repeat participation.",
    payoutMultiplier: 1.5,
  },
  {
    tokenId: "egg-sbt-003",
    eggId: "committee-scribe",
    tier: "gold",
    rarity: "epic",
    discoveryDifficulty: 3,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 24 * 7).toISOString(),
    discoveryMethod: "Completed a perfect committee attendance cycle.",
    discoveryBlock: 198887,
    proofHash: "b3:03981c26",
    ledgerEntry: "ledger:egg:003",
    name: "Committee Scribe",
    description: "Marks unusually strong civic follow-through.",
    image: "ipfs://egg-vault/committee-scribe.png",
    vibe: "High-conviction service with visible impact.",
    payoutMultiplier: 2,
  },
  {
    tokenId: "egg-sbt-004",
    eggId: "guardian-archivist",
    tier: "mythic",
    rarity: "legendary",
    discoveryDifficulty: 4,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 24 * 3).toISOString(),
    discoveryMethod: "Helped reconcile an archival proof mismatch.",
    discoveryBlock: 199114,
    proofHash: "b3:04cc1db7",
    ledgerEntry: "ledger:egg:004",
    name: "Guardian Archivist",
    description: "Reserved for extraordinary contributions to integrity checks.",
    image: "ipfs://egg-vault/guardian-archivist.png",
    vibe: "Calm stewardship under scrutiny.",
    payoutMultiplier: 3,
  },
  {
    tokenId: "egg-sbt-005",
    eggId: "lucky-13",
    tier: "music",
    rarity: "legendary",
    discoveryDifficulty: 4,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 36).toISOString(),
    discoveryMethod: "Clicked during the perfect moment of a minute.",
    discoveryBlock: 199221,
    proofHash: "b3:0504d2af",
    ledgerEntry: "ledger:egg:005",
    name: "The Lucky Number",
    description: "A non-transferable discovery tied to impeccable timing.",
    image: "ipfs://egg-vault/lucky-13.png",
    aesthetic: "lucky",
    secretNumber: 13,
    vibe: "Defiant energy wrapped around an auspicious number.",
    payoutMultiplier: 5,
  },
  {
    tokenId: "egg-sbt-006",
    eggId: "golden-era",
    tier: "music",
    rarity: "epic",
    discoveryDifficulty: 5,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 24).toISOString(),
    discoveryMethod: "Showed dedication 1989 times on a hidden hotspot.",
    discoveryBlock: 199347,
    proofHash: "b3:06dc7fe1",
    ledgerEntry: "ledger:egg:006",
    name: "The Golden Era",
    description: "An obvious-to-fans, generic-to-lawyers music discovery.",
    image: "ipfs://egg-vault/golden-era.png",
    aesthetic: "polaroid",
    secretNumber: 1989,
    vibe: "A bright, urban rush captured like an old instant photo.",
    payoutMultiplier: 8,
  },
  {
    tokenId: "egg-sbt-007",
    eggId: "snake-king",
    tier: "music",
    rarity: "legendary",
    discoveryDifficulty: 5,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 16).toISOString(),
    discoveryMethod: "Scored 13 in the hidden serpent game.",
    discoveryBlock: 199401,
    proofHash: "b3:078d9fa3",
    ledgerEntry: "ledger:egg:007",
    name: "The Snake King",
    description: "A soulbound reward for players who survive the serpent run.",
    image: "ipfs://egg-vault/snake-king.png",
    aesthetic: "serpent",
    secretNumber: 13,
    vibe: "Reinvention with a darker, sharper edge.",
    payoutMultiplier: 7.5,
  },
  {
    tokenId: "egg-sbt-008",
    eggId: "pulled-thread",
    tier: "music",
    rarity: "mythic",
    discoveryDifficulty: 5,
    discoveredBy: "0xC1V1C...",
    discoveredAt: new Date(now - 1000 * 60 * 60 * 6).toISOString(),
    discoveryMethod: "Found the one-in-a-million brown glyph in the interface.",
    discoveryBlock: 199512,
    proofHash: "b3:08f4cab2",
    ledgerEntry: "ledger:egg:008",
    name: "The Pulled Thread",
    description: "A 1/1 discovery that turns pattern recognition into payout power.",
    image: "ipfs://egg-vault/pulled-thread.png",
    aesthetic: "woodland",
    secretNumber: 1,
    vibe: "Warm comfort hidden beneath a weathered texture.",
    payoutMultiplier: 13,
  },
];

export const mockEggVaultMeta = {
  activeLocation: "ZIP3 · 021",
  minimumPayout: 100,
};

export const mockEggTiers = buildTierSummaries(
  mockEggCollection,
  mockEggVaultMeta.activeLocation,
);

export const mockCollectionValue = calculateCollectionValue(
  mockEggCollection,
  mockEggVaultMeta.activeLocation,
);

export const mockPayoutPreview: LocationPayoutPreview[] = [
  {
    label: "ZIP3 local baseline",
    multiplier: 1,
    note: "Soulbound burn value at your current civic zone.",
  },
  {
    label: "Regional density uplift",
    multiplier: 1.14,
    note: "Applies when discovery density is verified across the district.",
  },
  {
    label: "Civic priority district",
    multiplier: 1.28,
    note: "Reserved for high-need areas with active participation boosts.",
  },
];

export const mockEggLeaderboard: EggLeaderboardStats = {
  totalEggsFound: 89234,
  totalMusicEggsFound: 417,
  rarestEgg: {
    name: "The Pulled Thread",
    foundBy: "listener.eth",
    supply: "1/1",
    value: 1175.2,
  },
  mostValuableCollection: {
    holder: "archive.fm.eth",
    value: 47892,
    eggs: 134,
  },
  byRarity: {
    common: { total: 50000, uniqueHolders: 12000 },
    rare: { total: 15000, uniqueHolders: 4500 },
    epic: { total: 5000, uniqueHolders: 1200 },
    legendary: { total: 1000, uniqueHolders: 450 },
    mythic: { total: 89, uniqueHolders: 76 },
  },
};
