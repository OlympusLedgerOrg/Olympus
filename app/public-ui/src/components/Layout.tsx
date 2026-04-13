import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const isHome = location.pathname === "/";

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-ink/10 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 no-underline">
            <span className="text-gold text-lg">◆</span>
            <span className="font-serif text-xl text-ink">Olympus</span>
            <span className="text-xs font-ui text-ink/40 ml-1 hidden sm:inline">
              Public Verification Ledger
            </span>
          </Link>
          <nav className="flex gap-4 text-xs font-ui">
            <Link
              to="/"
              className={`no-underline transition-colors ${
                isHome ? "text-ink" : "text-ink/50 hover:text-ink"
              }`}
            >
              Verify
            </Link>
          </nav>
        </div>
      </header>

      <main className="flex-1 px-6 py-8">
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, ease: "easeOut" }}
          className="max-w-5xl mx-auto"
        >
          {children}
        </motion.div>
      </main>

      <footer className="border-t border-ink/10 px-6 py-4 mt-auto">
        <div className="max-w-5xl mx-auto text-center text-xs font-ui text-ink/30">
          Olympus Public Verification Ledger — Append-only. Independently
          verifiable.
        </div>
      </footer>
    </div>
  );
}
