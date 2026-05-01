/**
 * OlympusPublicApp — Shell / entry point for the public verification dashboard.
 *
 * Wires together the verification engine (useVerificationEngine) and the
 * selected UX skin.  The active skin is stored in `localStorage` so the user's
 * preference persists across reloads.
 *
 * Skins
 * ─────
 * • mayhem  — "Project Mayhem" brutalist terminal (default)
 * • basic   — Clean, reassuring, general-audience UI
 * • forensic — Dense analytical UI for investigators
 *
 * The skin selector is rendered as a small floating badge so it never
 * interferes with the skin's own layout.
 */

import { useState, type FC } from "react";
import { useVerificationEngine } from "./verificationEngine";
import { MayhemSkin } from "./skins/MayhemSkin";
import { BasicSkin } from "./skins/BasicSkin";
import { ForensicSkin } from "./skins/ForensicSkin";

export type SkinId = "mayhem" | "basic" | "forensic";

const SKIN_LABELS: Record<SkinId, string> = {
  mayhem: "[ø] Mayhem",
  basic: "☑ Basic",
  forensic: "⌗ Forensic",
};

const STORAGE_KEY = "olympus_skin";

function readStoredSkin(): SkinId {
  try {
    const stored = localStorage.getItem(STORAGE_KEY) as SkinId | null;
    if (stored && stored in SKIN_LABELS) return stored;
  } catch {
    // localStorage unavailable
  }
  return "mayhem";
}

function storeSkin(skin: SkinId): void {
  try {
    localStorage.setItem(STORAGE_KEY, skin);
  } catch {
    // ignore
  }
}

export interface OlympusPublicAppProps {
  /** FastAPI root URL. Defaults to "" (same origin / Vite proxy). */
  apiBase?: string;
  /** Override the initial skin selection (ignores localStorage). */
  defaultSkin?: SkinId;
}

/**
 * Main entry point for the public verification dashboard.
 *
 * Instantiates the verification engine and delegates rendering to the active
 * skin component.  A small skin-switcher badge is rendered in the top-right
 * corner and is intentionally outside the skin's own DOM so each skin can
 * freely control its full layout.
 */
const OlympusPublicApp: FC<OlympusPublicAppProps> = ({
  apiBase,
  defaultSkin,
}) => {
  const [skin, setSkin] = useState<SkinId>(defaultSkin ?? readStoredSkin());
  const [switcherOpen, setSwitcherOpen] = useState<boolean>(false);

  const engine = useVerificationEngine({ apiBase });

  const handleSkinChange = (id: SkinId): void => {
    setSkin(id);
    storeSkin(id);
    setSwitcherOpen(false);
  };

  return (
    <>
      {/* ── Skin switcher ── */}
      <div
        style={{
          position: "fixed",
          top: "0.75rem",
          right: "0.75rem",
          zIndex: 10000,
        }}
      >
        <button
          type="button"
          aria-label="Switch verification skin"
          title="Switch UI skin"
          onClick={() => setSwitcherOpen((v) => !v)}
          style={{
            padding: "0.3rem 0.65rem",
            fontSize: "0.62rem",
            fontFamily: "'DM Mono', monospace, monospace",
            background:
              skin === "mayhem"
                ? "rgba(0,20,0,0.9)"
                : skin === "forensic"
                  ? "rgba(15,23,42,0.9)"
                  : "rgba(255,255,255,0.9)",
            color:
              skin === "mayhem"
                ? "rgba(0,255,65,0.8)"
                : skin === "forensic"
                  ? "#6b7280"
                  : "#6b7280",
            border:
              skin === "mayhem"
                ? "1px solid rgba(0,255,65,0.3)"
                : skin === "forensic"
                  ? "1px solid #374151"
                  : "1px solid #e5e7eb",
            borderRadius: "0.375rem",
            cursor: "pointer",
            letterSpacing: "0.05em",
            boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
            transition: "all 0.15s",
          }}
        >
          SKIN: {SKIN_LABELS[skin]}
        </button>

        {switcherOpen && (
          <div
            style={{
              position: "absolute",
              top: "calc(100% + 0.4rem)",
              right: 0,
              background:
                skin === "mayhem" ? "rgba(0,10,0,0.97)" : skin === "forensic" ? "#0f172a" : "#fff",
              border:
                skin === "mayhem"
                  ? "1px solid rgba(0,255,65,0.3)"
                  : skin === "forensic"
                    ? "1px solid #374151"
                    : "1px solid #e5e7eb",
              borderRadius: "0.375rem",
              overflow: "hidden",
              boxShadow: "0 4px 16px rgba(0,0,0,0.25)",
              minWidth: "10rem",
            }}
          >
            {(Object.entries(SKIN_LABELS) as [SkinId, string][]).map(
              ([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => handleSkinChange(id)}
                  style={{
                    display: "block",
                    width: "100%",
                    padding: "0.6rem 1rem",
                    textAlign: "left",
                    background: skin === id ? (id === "mayhem" ? "rgba(0,255,65,0.07)" : id === "forensic" ? "#1d4ed820" : "#f3f4f6") : "transparent",
                    color:
                      id === "mayhem"
                        ? skin === "mayhem"
                          ? "#00FF41"
                          : "rgba(0,255,65,0.7)"
                        : id === "forensic"
                          ? "#d1d5db"
                          : "#374151",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "0.72rem",
                    fontFamily: "inherit",
                    letterSpacing: "0.03em",
                    transition: "background 0.12s",
                  }}
                >
                  {label}
                  {skin === id && (
                    <span style={{ marginLeft: "0.5rem", opacity: 0.6, fontSize: "0.6rem" }}>
                      ← active
                    </span>
                  )}
                </button>
              ),
            )}
          </div>
        )}
      </div>

      {/* ── Active skin ── */}
      {skin === "mayhem" && <MayhemSkin {...engine} />}
      {skin === "basic" && <BasicSkin {...engine} />}
      {skin === "forensic" && <ForensicSkin {...engine} />}
    </>
  );
};

export default OlympusPublicApp;
