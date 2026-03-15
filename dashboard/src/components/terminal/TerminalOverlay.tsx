"use client";

import { AnimatePresence, motion } from "framer-motion";
import { FullscreenTerminal } from "@/components/terminal/FullscreenTerminal";

export function TerminalOverlay({ open }: { open: boolean }) {
  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 p-6 sm:p-10"
          style={{ background: "rgba(0, 0, 0, 0.95)", color: "var(--color-primary)" }}
        >
          <FullscreenTerminal />
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
