"use client";

import { useEffect, useMemo, useState } from "react";
import { mockRepFeed, type RepFeed, type RepresentativeProfile } from "@/lib/mocks/reps";

type RepStatus = "idle" | "loading" | "error";

type RepMetadata = Omit<RepFeed, "reps">;

export function useReps() {
  const [reps, setReps] = useState<RepresentativeProfile[]>(mockRepFeed.reps);
  const [metadata, setMetadata] = useState<RepMetadata>({
    state: mockRepFeed.state,
    updatedAt: mockRepFeed.updatedAt,
    source: mockRepFeed.source,
  });
  const [status, setStatus] = useState<RepStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [selectedRepId, setSelectedRepId] = useState<string | null>(
    mockRepFeed.reps[0]?.id ?? null,
  );

  useEffect(() => {
    let active = true;

    const load = async () => {
      setStatus("loading");
      try {
        const response = await fetch("/api/reps");
        if (!response.ok) {
          throw new Error(`Request failed with ${response.status}`);
        }
        const data = (await response.json()) as RepFeed;
        if (!active) {
          return;
        }
        setReps(data.reps);
        setMetadata({
          state: data.state,
          updatedAt: data.updatedAt,
          source: data.source,
        });
        setError(null);
        setStatus("idle");
      } catch (loadError) {
        if (!active) {
          return;
        }
        console.warn("Failed to load reps feed, using mock data.", loadError);
        setReps(mockRepFeed.reps);
        setMetadata({
          state: mockRepFeed.state,
          updatedAt: mockRepFeed.updatedAt,
          source: mockRepFeed.source,
        });
        setError("Unable to reach the Congress API mock. Showing cached briefing data.");
        setStatus("error");
      }
    };

    load();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!selectedRepId && reps.length > 0) {
      setSelectedRepId(reps[0].id);
    }
  }, [reps, selectedRepId]);

  const selectedRep = useMemo(
    () => reps.find((rep) => rep.id === selectedRepId) ?? null,
    [reps, selectedRepId],
  );

  return {
    reps,
    selectedRep,
    selectedRepId,
    setSelectedRepId,
    status,
    error,
    metadata,
  };
}
