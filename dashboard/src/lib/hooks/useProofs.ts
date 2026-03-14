"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  createRealtimeProof,
  mockProofs,
  type ProofRecord,
  type ProofType,
} from "@/lib/mocks/proofs";

export type ProofFilter = "all" | ProofType;

const PAGE_SIZE = 5;
const LIVE_REFRESH_MS = 9000;
const MAX_PROOFS = 24;

export function useProofs() {
  const [proofs, setProofs] = useState<ProofRecord[]>(mockProofs);
  const [filter, setFilter] = useState<ProofFilter>("all");
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [selectedProofId, setSelectedProofId] = useState<string | null>(null);
  const [liveCount, setLiveCount] = useState(0);
  const liveSeedRef = useRef(mockProofs.length + 1);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setProofs((current) => {
        const nextProof = createRealtimeProof(liveSeedRef.current);
        liveSeedRef.current += 1;
        return current.length < MAX_PROOFS
          ? [nextProof, ...current]
          : [nextProof, ...current.slice(0, MAX_PROOFS - 1)];
      });
      setLiveCount((count) => count + 1);
    }, LIVE_REFRESH_MS);

    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
  }, [filter]);

  const filteredProofs = useMemo(() => {
    if (filter === "all") {
      return proofs;
    }

    return proofs.filter((proof) => proof.type === filter);
  }, [filter, proofs]);

  const selectedProof =
    proofs.find((proof) => proof.id === selectedProofId) ?? null;

  return {
    filter,
    filteredProofs,
    hasMore: filteredProofs.length > visibleCount,
    liveCount,
    loadMore: () => setVisibleCount((count) => count + PAGE_SIZE),
    selectedProof,
    setFilter,
    visibleProofs: filteredProofs.slice(0, visibleCount),
    totalProofs: proofs.length,
    openProof: (proofId: string) => setSelectedProofId(proofId),
    closeProof: () => setSelectedProofId(null),
  };
}
