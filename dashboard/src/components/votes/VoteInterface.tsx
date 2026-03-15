"use client";

import { useMemo } from "react";
import type { VoteChoice } from "@/lib/mocks/bills";

const OPTIONS: VoteChoice[] = ["yea", "nay", "abstain"];

export function VoteInterface({
  selectedVote,
  onVote,
  status,
  justEarned,
  totalEggs,
}: {
  selectedVote: VoteChoice | null;
  onVote: (vote: VoteChoice) => void;
  status: "idle" | "loading" | "error";
  justEarned: number;
  totalEggs: number;
}) {
  const shareText = useMemo(
    () => `I just cast a symbolic ${selectedVote ? selectedVote.toUpperCase() : ""} vote on Olympus Civic Dashboard.`,
    [selectedVote],
  );

  const onShare = async () => {
    if (!selectedVote || typeof navigator === "undefined") {
      return;
    }
    if (navigator.share) {
      await navigator.share({
        title: "Olympus symbolic vote",
        text: shareText,
      });
      return;
    }
    await navigator.clipboard.writeText(shareText);
  };

  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
        Symbolic voting
      </p>
      <h2 className="mt-2 text-xl font-semibold" style={{ color: "var(--color-primary)" }}>
        One human = one vote
      </h2>
      <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
        You can update your stance at any time, but only one verified ballot per bill is counted for your identity.
      </p>

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
        {OPTIONS.map((option) => {
          const isSelected = selectedVote === option;
          return (
            <button
              key={option}
              type="button"
              onClick={() => onVote(option)}
              disabled={status === "loading"}
              className="border px-4 py-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                borderColor: isSelected ? "var(--color-primary)" : "var(--color-border)",
                borderRadius: "var(--radius)",
                color: isSelected ? "var(--color-primary)" : "var(--color-text)",
                background: isSelected ? "var(--color-surface-muted)" : "var(--color-background)",
              }}
            >
              {option.toUpperCase()}
            </button>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm" style={{ color: "var(--color-text-muted)" }}>
        <div>
          <p>Egg rewards earned: <span style={{ color: "var(--color-accent)" }}>{totalEggs}</span></p>
          {justEarned > 0 ? (
            <p style={{ color: "var(--color-ok)" }}>+{justEarned} eggs from this vote</p>
          ) : null}
        </div>
        <button
          type="button"
          onClick={() => {
            void onShare();
          }}
          disabled={!selectedVote}
          className="border px-3 py-2 font-semibold disabled:opacity-60"
          style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)", color: "var(--color-primary)" }}
        >
          Share vote
        </button>
      </div>
    </section>
  );
}
