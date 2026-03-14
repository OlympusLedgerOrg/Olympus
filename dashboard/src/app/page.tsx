"use client";

import { motion } from "framer-motion";
import { useTheme } from "@/lib/hooks/useTheme";

export default function Home() {
  const { theme } = useTheme();

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 py-12">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-2xl w-full space-y-8"
      >
        <h1
          className="text-4xl font-bold tracking-tight"
          style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}
        >
          Olympus Dashboard
        </h1>

        <p style={{ color: "var(--color-text-muted)" }}>
          Append-only public ledger for government documents. Cryptographic
          guarantees for document integrity and provenance.
        </p>

        <div className="grid gap-4 sm:grid-cols-2">
          {[
            { title: "Ledger", desc: "View committed entries and chain state" },
            { title: "Documents", desc: "Browse canonicalized document hashes" },
            { title: "Proofs", desc: "Inspect Merkle inclusion proofs" },
            { title: "Shards", desc: "Monitor shard header sequences" },
          ].map((card) => (
            <motion.div
              key={card.title}
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 300 }}
              className="p-4 border"
              style={{
                background: "var(--color-surface)",
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
            >
              <h2
                className="text-lg font-semibold mb-1"
                style={{ color: "var(--color-accent)" }}
              >
                {card.title}
              </h2>
              <p
                className="text-sm"
                style={{ color: "var(--color-text-muted)" }}
              >
                {card.desc}
              </p>
            </motion.div>
          ))}
        </div>

        <div
          className="p-4 border text-sm"
          style={{
            background: "var(--color-surface-muted)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
            fontFamily: "var(--font-mono)",
            color: "var(--color-text-muted)",
          }}
        >
          <p>
            Active theme:{" "}
            <code style={{ color: "var(--color-primary)" }}>{theme}</code>
          </p>
        </div>
      </motion.div>
    </main>
  );
}
