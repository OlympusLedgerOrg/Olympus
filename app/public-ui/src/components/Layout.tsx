import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import GlyphRain from "./GlyphRain";
import CrtOverlay from "./CrtOverlay";

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();

  return (
    <div
      style={{
        backgroundColor: "#050505",
        color: "#00FF41",
        minHeight: "100vh",
        fontFamily: "'DM Mono', monospace",
        position: "relative",
        overflowX: "hidden",
      }}
    >
      <CrtOverlay />
      <GlyphRain active />

      {/* Header */}
      <header
        style={{
          padding: "1.1rem 2rem",
          borderBottom: "1px solid rgba(0,255,65,0.18)",
          background: "rgba(0,0,0,0.92)",
          position: "relative",
          zIndex: 10,
        }}
      >
        <div
          style={{
            maxWidth: "1100px",
            margin: "0 auto",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Link
            to="/"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.85rem",
              textDecoration: "none",
              color: "inherit",
            }}
          >
            <span style={{ fontSize: "1.3rem", color: "#ff0055" }}>[ø]</span>
            <span style={{ letterSpacing: "0.32em", fontSize: "0.78rem" }}>
              OLYMPUS_PROTOCØL
            </span>
          </Link>

          <div style={{ display: "flex", alignItems: "center", gap: "2rem" }}>
            <nav style={{ display: "flex", gap: "1.5rem" }}>
              <Link
                to="/"
                style={{
                  fontSize: "0.62rem",
                  letterSpacing: "0.1em",
                  textDecoration: "none",
                  color:
                    location.pathname === "/"
                      ? "#00FF41"
                      : "rgba(0,255,65,0.45)",
                  textShadow:
                    location.pathname === "/" ? "0 0 6px #00FF41" : "none",
                  transition: "all 0.15s",
                }}
              >
                VERIFY
              </Link>
            </nav>
            <div
              style={{
                color: "#ff0055",
                fontSize: "0.55rem",
                animation: "flicker 2.4s infinite",
                letterSpacing: "0.08em",
              }}
            >
              ● ENCRYPTED
            </div>
          </div>
        </div>
      </header>

      {/* Main */}
      <main
        style={{
          maxWidth: "1100px",
          margin: "0 auto",
          padding: "3rem 1.75rem 5rem",
          position: "relative",
          zIndex: 2,
        }}
      >
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, ease: "easeOut" }}
        >
          {children}
        </motion.div>
      </main>

      <footer
        style={{
          padding: "1.5rem",
          borderTop: "1px solid rgba(0,255,65,0.08)",
          textAlign: "center",
          fontSize: "0.55rem",
          opacity: 0.3,
          letterSpacing: "0.1em",
          position: "relative",
          zIndex: 2,
        }}
      >
        © 2024–2026 OLYMPUS_PROTOCØL // PROJECT_MAYHEM // NO_TRUST_REQUIRED
      </footer>
    </div>
  );
}
