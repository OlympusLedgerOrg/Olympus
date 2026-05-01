/**
 * olympus-full.tsx — Olympus Public Verification Dashboard
 * "Project Mayhem" Edition
 *
 * This file is now a thin compatibility shim.  All logic and UI have been
 * extracted into the modular `features/public/` architecture:
 *
 *   features/public/
 *     OlympusPublicApp.tsx      — shell with skin switcher
 *     verificationEngine.ts     — useVerificationEngine hook (all logic)
 *     skins/
 *       MayhemSkin.tsx          — original brutalist terminal UI
 *       BasicSkin.tsx           — clean general-audience UI
 *       ForensicSkin.tsx        — dense analytical investigator UI
 *
 * Existing callers of `<OlympusFull apiBase="..." />` continue to work
 * unchanged — they now render OlympusPublicApp which defaults to MayhemSkin.
 *
 * Required peer dependency:
 *   npm install blake3-wasm@^2.1.5
 */

import type { FC } from "react";
import OlympusPublicApp from "../features/public/OlympusPublicApp";

export interface OlympusFullProps {
  /** FastAPI root URL. Defaults to same origin (relative paths). */
  apiBase?: string;
}

/**
 * Olympus Public Verification Dashboard.
 *
 * Mounts the full modular app (OlympusPublicApp) with the MayhemSkin active
 * by default.  Use OlympusPublicApp directly for skin-selection control.
 */
const OlympusFull: FC<OlympusFullProps> = ({ apiBase }) => (
  <OlympusPublicApp apiBase={apiBase} defaultSkin="mayhem" />
);

export default OlympusFull;
