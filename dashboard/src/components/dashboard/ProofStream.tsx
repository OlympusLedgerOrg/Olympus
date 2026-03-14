"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useTheme } from "@/lib/hooks/useTheme";
import type { ProofFilter } from "@/lib/hooks/useProofs";
import type { ProofRecord } from "@/lib/mocks/proofs";
import { formatNumber, formatRelativeTime } from "@/lib/utils/formatting";

interface ProofStreamProps {
  filter: ProofFilter;
  hasMore: boolean;
  liveCount: number;
  onCloseProof: () => void;
  onFilterChange: (filter: ProofFilter) => void;
  onLoadMore: () => void;
  onOpenProof: (proofId: string) => void;
  proofs: ProofRecord[];
  selectedProof: ProofRecord | null;
  totalProofs: number;
}

const filterOptions: Array<{ label: string; value: ProofFilter }> = [
  { label: "All", value: "all" },
  { label: "Votes", value: "vote" },
  { label: "Verifications", value: "verification" },
  { label: "Egg earned", value: "egg-earned" },
];

export function ProofStream({
  filter,
  hasMore,
  liveCount,
  onCloseProof,
  onFilterChange,
  onLoadMore,
  onOpenProof,
  proofs,
  selectedProof,
  totalProofs,
}: ProofStreamProps) {
  const { theme } = useTheme();

  const motionProps =
    theme === "fight-club"
      ? { whileHover: { scale: 1.01, boxShadow: "0 0 24px rgba(0,255,65,0.18)" } }
      : theme === "professional"
        ? { whileHover: { y: -2, boxShadow: "0 10px 30px rgba(15,118,110,0.08)" } }
        : theme === "accessibility"
          ? { whileHover: { scale: 1.005 } }
          : { whileHover: { y: -1 } };

  return (
    <>
      <section
        className="border p-5"
        style={{
          background: "var(--color-surface)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
        }}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p
              className="text-xs uppercase tracking-[0.3em]"
              style={{ color: "var(--color-text-muted)" }}
            >
              Proof Stream
            </p>
            <h2 className="mt-2 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
              Live verification feed
            </h2>
            <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
              Mock socket connected · {formatNumber(totalProofs)} proofs in memory · {liveCount} live updates
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span
              className="inline-flex h-2.5 w-2.5 rounded-full"
              style={{ background: "var(--color-ok)" }}
            />
            <span style={{ color: "var(--color-text-muted)" }}>Realtime relay active</span>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          {filterOptions.map((option) => {
            const active = filter === option.value;

            return (
              <button
                key={option.value}
                type="button"
                onClick={() => onFilterChange(option.value)}
                className="border px-3 py-2 text-sm"
                style={{
                  background: active ? "var(--color-surface-muted)" : "transparent",
                  borderColor: "var(--color-border)",
                  borderRadius: "var(--radius)",
                  color: active ? "var(--color-primary)" : "var(--color-text-muted)",
                }}
              >
                {option.label}
              </button>
            );
          })}
        </div>

        <div className="mt-6 space-y-3">
          {proofs.map((proof, index) => (
            <motion.button
              key={proof.id}
              type="button"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.03, duration: 0.25 }}
              onClick={() => onOpenProof(proof.id)}
              className="w-full border p-4 text-left"
              style={{
                background: "var(--color-surface-muted)",
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
              {...motionProps}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.2em]">
                    <span style={{ color: "var(--color-primary)" }}>{proof.type}</span>
                    <span style={{ color: "var(--color-text-muted)" }}>{proof.status}</span>
                    <span style={{ color: "var(--color-text-muted)" }}>{proof.blockLabel}</span>
                  </div>
                  <div>
                    <h3 className="text-base font-semibold" style={{ color: "var(--color-text)" }}>
                      {proof.title}
                    </h3>
                    <p className="mt-1 text-sm" style={{ color: "var(--color-text-muted)" }}>
                      {proof.summary}
                    </p>
                  </div>
                </div>
                <div className="text-right text-xs" style={{ color: "var(--color-text-muted)" }}>
                  <p>{proof.actor}</p>
                  <p>{proof.location}</p>
                  <p className="mt-2">{formatRelativeTime(proof.createdAt)}</p>
                </div>
              </div>
            </motion.button>
          ))}
        </div>

        {hasMore ? (
          <div className="mt-5">
            <button
              type="button"
              onClick={onLoadMore}
              className="border px-4 py-2 text-sm font-semibold"
              style={{
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
                color: "var(--color-primary)",
              }}
            >
              Load more proofs
            </button>
          </div>
        ) : null}
      </section>

      <AnimatePresence>
        {selectedProof ? (
          <motion.div
            className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-4 md:items-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onCloseProof}
          >
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 24 }}
              transition={{ duration: 0.25 }}
              className="w-full max-w-2xl border p-6"
              style={{
                background: "var(--color-surface)",
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
              onClick={(event) => event.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p
                    className="text-xs uppercase tracking-[0.3em]"
                    style={{ color: "var(--color-text-muted)" }}
                  >
                    Full proof
                  </p>
                  <h3 className="mt-2 text-xl font-semibold" style={{ color: "var(--color-primary)" }}>
                    {selectedProof.title}
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={onCloseProof}
                  className="text-sm"
                  style={{ color: "var(--color-text-muted)" }}
                >
                  Close
                </button>
              </div>

              <div className="mt-5 grid gap-4 md:grid-cols-2">
                <div
                  className="border p-4"
                  style={{
                    background: "var(--color-surface-muted)",
                    borderColor: "var(--color-border)",
                    borderRadius: "var(--radius)",
                  }}
                >
                  <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
                    Proof hash
                  </p>
                  <p className="mt-2 break-all text-sm" style={{ color: "var(--color-text)" }}>
                    {selectedProof.hash}
                  </p>
                  <p className="mt-3 text-xs" style={{ color: "var(--color-text-muted)" }}>
                    {selectedProof.blockLabel}
                  </p>
                </div>
                <div
                  className="border p-4"
                  style={{
                    background: "var(--color-surface-muted)",
                    borderColor: "var(--color-border)",
                    borderRadius: "var(--radius)",
                  }}
                >
                  <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
                    Reward delta
                  </p>
                  <p className="mt-2 text-lg font-semibold" style={{ color: "var(--color-accent)" }}>
                    +{selectedProof.rewardDelta} eggs
                  </p>
                  <p className="mt-3 text-xs" style={{ color: "var(--color-text-muted)" }}>
                    {selectedProof.actor} · {selectedProof.location}
                  </p>
                </div>
              </div>

              <div className="mt-5">
                <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
                  Verification trace
                </p>
                <ul className="mt-3 space-y-2">
                  {selectedProof.details.map((detail) => (
                    <li
                      key={detail}
                      className="border p-3 text-sm"
                      style={{
                        background: "var(--color-surface-muted)",
                        borderColor: "var(--color-border)",
                        borderRadius: "var(--radius)",
                        color: "var(--color-text)",
                      }}
                    >
                      {detail}
                    </li>
                  ))}
                </ul>
              </div>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </>
  );
}
