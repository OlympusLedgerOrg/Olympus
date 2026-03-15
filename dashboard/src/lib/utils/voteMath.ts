import type { DistrictVoteTotals, VoteChoice } from "@/lib/mocks/bills";

const ALIGNMENT_TABLE: Record<VoteChoice, Record<VoteChoice, number>> = {
  yea: { yea: 100, nay: 0, abstain: 50 },
  nay: { yea: 0, nay: 100, abstain: 50 },
  abstain: { yea: 50, nay: 50, abstain: 100 },
};

export function calculateTotalVotes(totals: DistrictVoteTotals): number {
  return totals.yea + totals.nay + totals.abstain;
}

export function calculateDistrictConsensus(totals: DistrictVoteTotals): number {
  const total = calculateTotalVotes(totals);
  if (!total) {
    return 0;
  }
  return (Math.max(totals.yea, totals.nay, totals.abstain) / total) * 100;
}

export function calculateVoteAlignment(vote: VoteChoice | null, repVote: VoteChoice): number {
  if (!vote) {
    return 0;
  }
  return ALIGNMENT_TABLE[vote][repVote];
}

export function calculateEggReward(isFirstVoteForBill: boolean): number {
  return isFirstVoteForBill ? 12 : 0;
}

export function normalizeVote(input: string | null | undefined): VoteChoice | null {
  if (input === "yea" || input === "nay" || input === "abstain") {
    return input;
  }
  return null;
}
