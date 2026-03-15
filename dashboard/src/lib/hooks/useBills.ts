"use client";

import { useEffect, useMemo, useState } from "react";
import { mockBillFeed, type BillFeed, type BillRecord, type LegislationLevel, type LegislationStatus } from "@/lib/mocks/bills";

export type BillSortBy = "date" | "hotness" | "alignment";

type BillStatus = "idle" | "loading" | "error";

export function useBills() {
  const [allBills, setAllBills] = useState<BillRecord[]>(mockBillFeed.bills);
  const [status, setStatus] = useState<BillStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string>(mockBillFeed.updatedAt);
  const [source, setSource] = useState<string>(mockBillFeed.source);
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<LegislationLevel | "all">("all");
  const [billStatusFilter, setBillStatusFilter] = useState<LegislationStatus | "all">("active");
  const [sortBy, setSortBy] = useState<BillSortBy>("date");

  useEffect(() => {
    let active = true;

    const load = async () => {
      setStatus("loading");
      try {
        const response = await fetch("/api/bills");
        if (!response.ok) {
          throw new Error(`Request failed with ${response.status}`);
        }
        const feed = (await response.json()) as BillFeed;
        if (!active) {
          return;
        }
        setAllBills(feed.bills);
        setUpdatedAt(feed.updatedAt);
        setSource(feed.source);
        setStatus("idle");
        setError(null);
      } catch (loadError) {
        if (!active) {
          return;
        }
        console.warn("Failed to load bills feed, using mock feed.", loadError);
        setAllBills(mockBillFeed.bills);
        setUpdatedAt(mockBillFeed.updatedAt);
        setSource(mockBillFeed.source);
        setStatus("error");
        setError("Unable to sync latest legislation feed. Showing cached bills.");
      }
    };

    load();

    return () => {
      active = false;
    };
  }, []);

  const bills = useMemo(() => {
    const query = search.trim().toLowerCase();

    const filtered = allBills.filter((bill) => {
      const levelMatch = level === "all" || bill.level === level;
      const statusMatch = billStatusFilter === "all" || bill.status === billStatusFilter;
      const queryMatch =
        !query ||
        bill.title.toLowerCase().includes(query) ||
        bill.sponsors.some((sponsor) => sponsor.toLowerCase().includes(query)) ||
        bill.id.toLowerCase().includes(query);

      return levelMatch && statusMatch && queryMatch;
    });

    return [...filtered].sort((left, right) => {
      if (sortBy === "hotness") {
        return right.hotness - left.hotness;
      }
      if (sortBy === "alignment") {
        return right.alignmentBaseline - left.alignmentBaseline;
      }
      return right.introducedAt.localeCompare(left.introducedAt);
    });
  }, [allBills, billStatusFilter, level, search, sortBy]);

  return {
    bills,
    allBills,
    status,
    error,
    source,
    updatedAt,
    search,
    setSearch,
    level,
    setLevel,
    billStatusFilter,
    setBillStatusFilter,
    sortBy,
    setSortBy,
  };
}
