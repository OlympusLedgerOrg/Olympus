import { createContext, useContext } from "react";
import { SKIN_REGISTRY, DEFAULT_SKIN_ID } from "./registry";
import type { SkinDefinition, SkinId } from "./types";

export interface SkinContextValue {
  skin: SkinDefinition;
  skinId: SkinId;
  setSkinId: (id: SkinId) => void;
}

export const STORAGE_KEY = "olympus_skin";

export const SkinContext = createContext<SkinContextValue | null>(null);

export function loadSkinId(): SkinId {
  try {
    const stored = localStorage.getItem(STORAGE_KEY) as SkinId | null;
    return stored && stored in SKIN_REGISTRY ? stored : DEFAULT_SKIN_ID;
  } catch {
    // localStorage may be unavailable in hardened/private-browsing contexts.
    return DEFAULT_SKIN_ID;
  }
}

/** Consume the active skin. Must be used inside <SkinProvider>. */
export function useSkin(): SkinContextValue {
  const ctx = useContext(SkinContext);
  if (!ctx) throw new Error("useSkin must be used within a <SkinProvider>");
  return ctx;
}
