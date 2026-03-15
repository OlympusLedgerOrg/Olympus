import { NextResponse, type NextRequest } from "next/server";
import { mockBillFeed, type BillRecord, type DistrictVoteTotals, type VoteChoice } from "@/lib/mocks/bills";
import {
  calculateDistrictConsensus,
  calculateEggReward,
  calculateTotalVotes,
  calculateVoteAlignment,
  normalizeVote,
} from "@/lib/utils/voteMath";

type StoredVote = {
  billId: string;
  userId: string;
  district: string;
  vote: VoteChoice;
  createdAt: string;
  updatedAt: string;
  eggsEarned: number;
};

type VoteApiSnapshot = {
  billId: string;
  district: string;
  repVote: VoteChoice;
  totals: DistrictVoteTotals;
  totalVotes: number;
  consensusPct: number;
  userVote: VoteChoice | null;
  alignmentScore: number;
};

const DEFAULT_DISTRICT = "WA-01";

const globalVoteStore = globalThis as unknown as {
  olympusVoteStore?: Map<string, StoredVote>;
};

const voteStore = globalVoteStore.olympusVoteStore ?? new Map<string, StoredVote>();
globalVoteStore.olympusVoteStore = voteStore;

function getBill(billId: string): BillRecord {
  const bill = mockBillFeed.bills.find((item) => item.id === billId);
  if (!bill) {
    throw new Error("Bill not found");
  }
  return bill;
}

function combineTotals(
  bill: BillRecord,
  district: string,
  userVotes: StoredVote[],
): DistrictVoteTotals {
  const baseline = bill.districtTotals[district] ?? bill.districtTotals[DEFAULT_DISTRICT] ?? {
    yea: 0,
    nay: 0,
    abstain: 0,
  };

  const additions = userVotes.reduce(
    (acc, entry) => {
      acc[entry.vote] += 1;
      return acc;
    },
    { yea: 0, nay: 0, abstain: 0 } satisfies DistrictVoteTotals,
  );

  return {
    yea: baseline.yea + additions.yea,
    nay: baseline.nay + additions.nay,
    abstain: baseline.abstain + additions.abstain,
  };
}

function buildVoteSnapshot(
  bill: BillRecord,
  district: string,
  userId: string,
): VoteApiSnapshot {
  const billVotes = [...voteStore.values()].filter(
    (entry) => entry.billId === bill.id && entry.district === district,
  );
  const userVote = voteStore.get(`${userId}:${bill.id}`)?.vote ?? null;
  const totals = combineTotals(bill, district, billVotes);

  return {
    billId: bill.id,
    district,
    repVote: bill.repVote,
    totals,
    totalVotes: calculateTotalVotes(totals),
    consensusPct: calculateDistrictConsensus(totals),
    userVote,
    alignmentScore: calculateVoteAlignment(userVote, bill.repVote),
  };
}

function buildVoteHistory(userId: string) {
  return [...voteStore.values()]
    .filter((entry) => entry.userId === userId)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function getUserId(request: NextRequest): string {
  return request.headers.get("x-olympus-user")?.trim() || "verified-human-demo";
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const billId = searchParams.get("billId");
  const district = searchParams.get("district") || DEFAULT_DISTRICT;
  const userId = getUserId(request);

  let snapshot: VoteApiSnapshot | null = null;
  if (billId) {
    try {
      snapshot = buildVoteSnapshot(getBill(billId), district, userId);
    } catch {
      return NextResponse.json({ error: "Bill not found" }, { status: 404 });
    }
  }

  const history = buildVoteHistory(userId);
  const totalEggs = history.reduce((sum, item) => sum + item.eggsEarned, 0);

  return NextResponse.json(
    {
      updatedAt: new Date().toISOString(),
      snapshot,
      history,
      rewards: {
        totalEggs,
        votesCast: history.length,
      },
    },
    { status: 200 },
  );
}

export async function POST(request: NextRequest) {
  const userId = getUserId(request);
  const payload = (await request.json()) as {
    billId?: string;
    vote?: string;
    district?: string;
  };

  const billId = payload.billId?.trim();
  const vote = normalizeVote(payload.vote);
  const district = payload.district?.trim() || DEFAULT_DISTRICT;

  if (!billId || !vote) {
    return NextResponse.json({ error: "billId and a valid vote are required" }, { status: 400 });
  }

  let bill: BillRecord;
  try {
    bill = getBill(billId);
  } catch {
    return NextResponse.json({ error: "Bill not found" }, { status: 404 });
  }

  const key = `${userId}:${billId}`;
  const existing = voteStore.get(key);
  const now = new Date().toISOString();
  const eggsEarned = calculateEggReward(!existing);

  voteStore.set(key, {
    billId,
    userId,
    district,
    vote,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    eggsEarned: (existing?.eggsEarned ?? 0) + eggsEarned,
  });

  const snapshot = buildVoteSnapshot(bill, district, userId);
  const history = buildVoteHistory(userId);
  const totalEggs = history.reduce((sum, item) => sum + item.eggsEarned, 0);

  return NextResponse.json(
    {
      updatedAt: now,
      snapshot,
      history,
      rewards: {
        justEarned: eggsEarned,
        totalEggs,
        votesCast: history.length,
      },
    },
    { status: 200 },
  );
}
