import { Suspense, lazy } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import GlyphRain from "./GlyphRain";
import CrtOverlay from "./CrtOverlay";
import GlitchMentorPopups from "./GlitchMentorPopups";
import SkinSelector from "./SkinSelector";
import WhoAmIChip from "./WhoAmIChip";
import { useSkin } from "../skins/SkinContext";
import { hasStoredAdminKey } from "../lib/storage";

// SkylineBackdrop is the biggest paint surface in the app (parallax,
// per-cell window grid animations, neon-smiley drop-shadow stack). It
// is opt-in via skin.effects.showSkyscraperBackdrop and dynamically
// imported so users who never flip it on don't even download the
// component bundle.
const SkylineBackdrop = lazy(() => import("./SkylineBackdrop"));

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const { skin } = useSkin();
  const fx = skin.effects ?? {};
  // ⚠ Audit L-UI-5: client-side route gating is UX-only, not a security
  // boundary. Hiding the KEYS/USERS/SBTs nav entries from non-admin sessions
  // is a convenience; a user who pastes an admin-scoped path directly into
  // the address bar will reach the page, and protection comes entirely from
  // the backend's per-route scope check (Axum middleware/auth.rs). Never
  // treat `canManageKeys` as authoritative — if you need to gate behaviour,
  // use the backend's response, not this flag.
  const canManageKeys = hasStoredAdminKey();

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
      {fx.showSkyscraperBackdrop && (
        <Suspense fallback={null}>
          <SkylineBackdrop />
        </Suspense>
      )}
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
            title="OLYMPUS_PROTOCØL"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.85rem",
              textDecoration: "none",
              color: logoText,
            }}
          >
            <span style={{ fontSize: "1.3rem", color: logoAccent, fontFamily: "var(--font-logo)" }}>[ø]</span>
            <span style={{ letterSpacing: "0.32em", fontSize: "0.78rem", fontFamily: "var(--font-logo)" }}>
              OLYMPUS_PROTOCØL
            </span>
          </Link>

          <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
            <nav style={{ display: "flex", gap: "1.5rem" }}>
              {[
                { to: "/verify", label: "VERIFY" },
                ...(canManageKeys ? [{ to: "/keys", label: "KEYS" }] : []),
                ...(canManageKeys ? [{ to: "/admin/users", label: "USERS" }] : []),
                ...(canManageKeys ? [{ to: "/credentials", label: "SBTs" }] : []),
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
            </nav>

            <SkinSelector />

            <WhoAmIChip />

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
