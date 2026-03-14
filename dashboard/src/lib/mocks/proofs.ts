export type ProofType = "vote" | "verification" | "egg-earned";

export interface ProofRecord {
  id: string;
  type: ProofType;
  title: string;
  summary: string;
  actor: string;
  location: string;
  createdAt: string;
  hash: string;
  status: "verified" | "pending" | "queued";
  blockLabel: string;
  rewardDelta: number;
  details: string[];
}

const proofTemplates: Array<
  Omit<ProofRecord, "id" | "createdAt" | "hash"> & { timestampOffsetMinutes: number }
> = [
  {
    type: "verification",
    title: "Humanity proof accepted",
    summary: "Zip3-preserving liveness proof committed to the civic shard.",
    actor: "Verifier node 07",
    location: "ZIP3 · 021",
    timestampOffsetMinutes: 2,
    status: "verified",
    blockLabel: "Shard civic/verify#441",
    rewardDelta: 12,
    details: [
      "Circuit: humanity-v2",
      "Witness verified against epoch 188",
      "Settlement window: 14 minutes",
    ],
  },
  {
    type: "vote",
    title: "Delegated vote proof",
    summary: "Ballot commitment verified with receipt routed to the proof relay.",
    actor: "Ward 4 coordinator",
    location: "District 4",
    timestampOffsetMinutes: 7,
    status: "verified",
    blockLabel: "Shard civic/vote#903",
    rewardDelta: 8,
    details: [
      "Receipt anchor: pollbook-2211",
      "Jurisdiction bundle included in batch 56",
      "Eligibility proof remains private",
    ],
  },
  {
    type: "egg-earned",
    title: "Mythic egg fragment minted",
    summary: "High-trust relay delivered an egg fragment after proof finality.",
    actor: "Rewards oracle",
    location: "National pool",
    timestampOffsetMinutes: 14,
    status: "pending",
    blockLabel: "Rewards stream#118",
    rewardDelta: 18,
    details: [
      "Tier multiplier: x2.4",
      "Payout held until next settlement",
      "Source proof: integrity-rollup-18",
    ],
  },
  {
    type: "verification",
    title: "Guardian replay check",
    summary: "Historical proof replayed and matched canonical ledger output.",
    actor: "Guardian replica 02",
    location: "Replica mesh",
    timestampOffsetMinutes: 28,
    status: "verified",
    blockLabel: "Audit replay#052",
    rewardDelta: 6,
    details: [
      "Canonical hash matches source shard",
      "Replay lag: 42 seconds",
      "No divergence detected",
    ],
  },
  {
    type: "vote",
    title: "Municipal vote inclusion",
    summary: "Append-only proof confirmed against the precinct Merkle root.",
    actor: "Civic worker 19",
    location: "Precinct 11",
    timestampOffsetMinutes: 36,
    status: "queued",
    blockLabel: "Shard civic/vote#895",
    rewardDelta: 4,
    details: [
      "Inclusion proof depth: 14",
      "Final settlement pending precinct close",
      "Observer quorum reached",
    ],
  },
  {
    type: "egg-earned",
    title: "Silver egg bundle unlocked",
    summary: "Consistent verification streak produced a silver vault reward.",
    actor: "Vault distributor",
    location: "ZIP3 · 606",
    timestampOffsetMinutes: 48,
    status: "verified",
    blockLabel: "Vault payout#331",
    rewardDelta: 15,
    details: [
      "Streak length: 9 proofs",
      "Regional multiplier: x1.18",
      "Claimable at next refresh",
    ],
  },
  {
    type: "verification",
    title: "Cross-shard consistency proof",
    summary: "Proof relay compared two shard headers and confirmed append-only growth.",
    actor: "Consistency monitor",
    location: "Shard bridge",
    timestampOffsetMinutes: 63,
    status: "verified",
    blockLabel: "Bridge consistency#104",
    rewardDelta: 10,
    details: [
      "Consistency window: 3 epochs",
      "Header pair signed by quorum",
      "Result exported to archive",
    ],
  },
  {
    type: "vote",
    title: "Petition threshold proof",
    summary: "Community petition met the signature threshold with canonical receipts.",
    actor: "Petition relay",
    location: "Metro zone",
    timestampOffsetMinutes: 81,
    status: "verified",
    blockLabel: "Petition ledger#028",
    rewardDelta: 7,
    details: [
      "Threshold reached: 10,240 signers",
      "Duplicate receipts discarded",
      "Observer snapshot archived",
    ],
  },
];

function buildHash(seed: number): string {
  return `0x${(seed * 2654435761).toString(16).padStart(16, "0").slice(0, 16)}${seed
    .toString(16)
    .padStart(8, "0")}`;
}

export const mockProofs: ProofRecord[] = proofTemplates.map((proof, index) => ({
  ...proof,
  id: `proof-${index + 1}`,
  createdAt: new Date(Date.now() - proof.timestampOffsetMinutes * 60 * 1000).toISOString(),
  hash: buildHash(index + 17),
}));

export function createRealtimeProof(seed: number): ProofRecord {
  const template = proofTemplates[seed % proofTemplates.length];
  const now = new Date();

  return {
    ...template,
    id: `proof-live-${seed}-${now.getTime()}`,
    createdAt: now.toISOString(),
    hash: buildHash(seed + 97),
    title: `${template.title} · live`,
    summary: `Realtime relay: ${template.summary.toLowerCase()}`,
    status: "verified",
    blockLabel: `${template.blockLabel} · live`,
  };
}
