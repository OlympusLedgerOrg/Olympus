"use client";

import { useAuth } from "@/lib/hooks/useAuth";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { DistrictVoteTotals, VoteChoice } from "@/lib/mocks/bills";

type VoteStatus = "idle" | "loading" | "error";

type VoteHistoryEntry = {
  billId: string;
  userId: string;
  district: string;
  vote: VoteChoice;
  createdAt: string;
  updatedAt: string;
  eggsEarned: number;
};

type VoteSnapshot = {
  billId: string;
  district: string;
  repVote: VoteChoice;
  totals: DistrictVoteTotals;
  totalVotes: number;
  consensusPct: number;
  userVote: VoteChoice | null;
  alignmentScore: number;
};

type VoteResponse = {
  updatedAt: string;
  snapshot: VoteSnapshot | null;
  history: VoteHistoryEntry[];
  rewards: {
    totalEggs: number;
    votesCast: number;
    justEarned?: number;
  };
};

const REFRESH_MS = 5000;
const DEFAULT_DISTRICT = "WA-01";

export function useVotes(billId?: string) {
  const { walletAddress, verificationRecord } = useAuth();
  const userId = useMemo(
    () => walletAddress ?? verificationRecord?.personhoodId ?? "verified-human-demo",
    [verificationRecord?.personhoodId, walletAddress],
  );

  const [status, setStatus] = useState<VoteStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [history, setHistory] = useState<VoteHistoryEntry[]>([]);
  const [snapshot, setSnapshot] = useState<VoteSnapshot | null>(null);
  const [rewards, setRewards] = useState({ totalEggs: 0, votesCast: 0, justEarned: 0 });

  const loadVotes = useCallback(async () => {
    setStatus("loading");
    try {
      const query = billId
        ? `?billId=${encodeURIComponent(billId)}&district=${encodeURIComponent(DEFAULT_DISTRICT)}`
        : "";
      const response = await fetch(`/api/votes${query}`, {
        headers: {
          "x-olympus-user": userId,
        },
      });
      if (!response.ok) {
        throw new Error(`Request failed with ${response.status}`);
      }
      const data = (await response.json()) as VoteResponse;
      setUpdatedAt(data.updatedAt);
      setSnapshot(data.snapshot);
      setHistory(data.history);
      setRewards({
        totalEggs: data.rewards.totalEggs,
        votesCast: data.rewards.votesCast,
        justEarned: data.rewards.justEarned ?? 0,
      });
      setStatus("idle");
      setError(null);
    } catch (loadError) {
      console.warn("Failed to load vote snapshot.", loadError);
      setStatus("error");
      setError("Unable to sync live vote totals. Retrying shortly.");
    }
  }, [billId, userId]);

  useEffect(() => {
    void loadVotes();
    const interval = window.setInterval(() => {
      void loadVotes();
    }, REFRESH_MS);

    return () => {
      window.clearInterval(interval);
    };
  }, [loadVotes]);

  const castVote = useCallback(
    async (vote: VoteChoice) => {
      if (!billId) {
        return;
      }

      setStatus("loading");
      try {
        const response = await fetch("/api/votes", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-olympus-user": userId,
          },
          body: JSON.stringify({
            billId,
            vote,
            district: DEFAULT_DISTRICT,
          }),
        });

        if (!response.ok) {
          throw new Error(`Request failed with ${response.status}`);
        }

        const data = (await response.json()) as VoteResponse;
        setUpdatedAt(data.updatedAt);
        setSnapshot(data.snapshot);
        setHistory(data.history);
        setRewards({
          totalEggs: data.rewards.totalEggs,
          votesCast: data.rewards.votesCast,
          justEarned: data.rewards.justEarned ?? 0,
        });
        setStatus("idle");
        setError(null);
      } catch (voteError) {
        console.warn("Failed to cast vote.", voteError);
        setStatus("error");
        setError("Vote submission failed. Please retry.");
      }
    },
    [billId, userId],
  );

  return {
    status,
    error,
    updatedAt,
    history,
    snapshot,
    rewards,
    castVote,
    userId,
  };
}
