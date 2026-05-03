import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import GlyphRain from "./GlyphRain";
import CrtOverlay from "./CrtOverlay";
import SkylineBackdrop from "./SkylineBackdrop";
import GlitchMentorPopups from "./GlitchMentorPopups";
import SkinSelector from "./SkinSelector";
import { useSkin } from "../skins/SkinContext";

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const { skin } = useSkin();
  const fx = skin.effects ?? {};

  // Derive header/nav colours from current skin so chrome stays readable.
  const isLight = skin.id === "basic";
  const isAmber = skin.id === "terminal";
  const headerBg = isLight ? "rgba(255,255,255,0.97)" : "rgba(0,0,0,0.92)";
  const headerBorder = isLight
    ? "1px solid #e2e8f0"
    : isAmber
      ? "1px solid rgba(228,181,90,0.18)"
      : "1px solid rgba(0,255,65,0.18)";

  const navActive = isLight ? "#1d4ed8" : isAmber ? "#e4b55a" : "#00FF41";
  const navInactive = isLight
    ? "#64748b"
    : isAmber
      ? "rgba(228,181,90,0.45)"
      : "rgba(0,255,65,0.45)";
  const navGlow = (active: boolean) => {
    if (!active) return "none";
    if (isLight) return "none";
    if (isAmber) return "0 0 6px #e4b55a";
    return "0 0 6px #00FF41";
  };
  const logoAccent = isLight ? "#1d4ed8" : "#ff0055";
  const logoText = isLight ? "#0f172a" : "inherit";
  const encryptedColor = isLight ? "#dc2626" : isAmber ? "#e4b55a" : "#ff0055";

  return (
    <div
      className={skin.classes.page}
      style={{
        fontFamily: "'DM Mono', monospace",
        position: "relative",
        overflowX: "hidden",
      }}
    >
      {fx.showSkyscraperBackdrop && <SkylineBackdrop />}
      {fx.showScanlines && <CrtOverlay />}
      {fx.showGlitchMentor && <GlitchMentorPopups />}
      {skin.id === "glitch" && <GlyphRain active />}

      {/* Header */}
      <header
        style={{
          padding: "1.1rem 2rem",
          borderBottom: headerBorder,
          background: headerBg,
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
              color: logoText,
            }}
          >
            <span style={{ fontSize: "1.3rem", color: logoAccent }}>[ø]</span>
            <span style={{ letterSpacing: "0.32em", fontSize: "0.78rem" }}>
              OLYMPUS_PROTOCØL
            </span>
          </Link>

          <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
            <nav style={{ display: "flex", gap: "1.5rem" }}>
              {[
                { to: "/", label: "ACCESS" },
                { to: "/verify", label: "VERIFY" },
              ].map(({ to, label }) => {
                const active = location.pathname === to;
                return (
                  <Link
                    key={to}
                    to={to}
                    style={{
                      fontSize: "0.62rem",
                      letterSpacing: "0.1em",
                      textDecoration: "none",
                      color: active ? navActive : navInactive,
                      textShadow: navGlow(active),
                      transition: "all 0.15s",
                    }}
                  >
                    {label}
                  </Link>
                );
              })}
              <Link
                to="/admin"
                style={{
                  fontSize: "0.62rem",
                  letterSpacing: "0.1em",
                  textDecoration: "none",
                  color:
                    location.pathname === "/admin"
                      ? isLight
                        ? "#dc2626"
                        : "#ff0055"
                      : isLight
                        ? "#ef4444"
                        : "rgba(255,0,85,0.4)",
                  textShadow:
                    location.pathname === "/admin" && !isLight
                      ? "0 0 6px #ff0055"
                      : "none",
                  transition: "all 0.15s",
                }}
              >
                ADMIN
              </Link>
            </nav>

            <SkinSelector />

            <div
              style={{
                color: encryptedColor,
                fontSize: "0.55rem",
                animation: skin.id === "glitch" ? "flicker 2.4s infinite" : "none",
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
          borderTop: isLight ? "1px solid #e2e8f0" : "1px solid rgba(0,255,65,0.08)",
          textAlign: "center",
          fontSize: "0.55rem",
          opacity: 0.4,
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
