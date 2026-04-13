import { motion } from "framer-motion";
import type { Verdict, VerdictDetail } from "../lib/types";
import CopyButton from "./CopyButton";

const verdictConfig: Record<
  Verdict,
  { border: string; icon: string; title: string; description: string }
> = {
  verified: {
    border: "border-l-verified",
    icon: "✓",
    title: "Record Intact",
    description:
      "This record matches its cryptographic commitment exactly.",
  },
  failed: {
    border: "border-l-failed",
    icon: "✗",
    title: "Verification Failed",
    description:
      "This record does not match its commitment — possible tampering.",
  },
  unknown: {
    border: "border-l-unknown",
    icon: "?",
    title: "Not on Ledger",
    description:
      "This hash has not been committed to the Olympus ledger.",
  },
};

const statusDot: Record<string, string> = {
  ok: "bg-verified",
  err: "bg-failed",
  warn: "bg-unknown",
  neutral: "bg-neutral",
};

interface VerdictCardProps {
  verdict: Verdict;
  details?: VerdictDetail[];
}

export default function VerdictCard({ verdict, details = [] }: VerdictCardProps) {
  const cfg = verdictConfig[verdict];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: "easeOut" }}
      className={`border-l-4 ${cfg.border} bg-white/60 rounded-sm p-6 mt-6`}
    >
      <div className="flex items-center gap-3 mb-2">
        <span
          className={`text-2xl font-serif ${
            verdict === "verified"
              ? "text-verified"
              : verdict === "failed"
                ? "text-failed"
                : "text-unknown"
          }`}
        >
          {cfg.icon}
        </span>
        <h2 className="text-xl font-serif text-ink">{cfg.title}</h2>
      </div>
      <p className="text-sm text-ink/70 mb-4 font-ui">{cfg.description}</p>

      {details.length > 0 && (
        <div className="space-y-0 border-t border-ink/10">
          {details.map((d, i) => (
            <motion.div
              key={d.key}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration: 0.2,
                delay: 0.03 * i,
                ease: "easeOut",
              }}
              className="flex items-start justify-between py-2.5 border-b border-ink/5 gap-4"
            >
              <span className="flex items-center gap-2 text-xs text-ink/50 font-ui shrink-0 min-w-[120px]">
                {d.status && (
                  <span
                    className={`inline-block w-1.5 h-1.5 rounded-full ${
                      statusDot[d.status] ?? "bg-neutral"
                    }`}
                  />
                )}
                {d.key}
              </span>
              <span className="text-xs font-mono text-ink/80 break-all text-right flex items-center gap-1">
                {d.value}
                {d.copyable && <CopyButton text={d.value} />}
              </span>
            </motion.div>
          ))}
        </div>
      )}
    </motion.div>
  );
}
