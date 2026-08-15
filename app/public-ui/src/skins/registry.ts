import type { SkinDefinition, SkinId } from "./types";

export const SKIN_REGISTRY: Record<SkinId, SkinDefinition> = {
  glitch: {
    id: "glitch",
    label: "GLITCH",
    description: "Cyberpunk green-on-black with Tyler Durden energy",
    effects: {
      showGlitchMentor: true,
      // Default off: the skyscraper backdrop is the highest-cost
      // paint surface (parallax + mousemove + per-cell window
      // animations + neon-smiley drop-shadow stack). Under WSL/llvmpipe
      // it's the dominant cursor-jitter source. Operators who want
      // the full aesthetic can flip this back via the skin selector
      // or by editing registry.ts directly.
      showSkyscraperBackdrop: false,
      showScanlines: true,
      showGlow: true,
    },
  },

  basic: {
    id: "basic",
    label: "BASIC",
    description: "Clean minimal verifier — production-friendly light mode",
    effects: {
      showGlitchMentor: false,
      showSkyscraperBackdrop: false,
      showScanlines: false,
      showGlow: false,
    },
  },

  terminal: {
    id: "terminal",
    label: "TERMINAL",
    description: "Dark amber command-line terminal",
    effects: {
      showGlitchMentor: false,
      showSkyscraperBackdrop: false,
      showScanlines: true,
      showGlow: false,
    },
  },
};

export const DEFAULT_SKIN_ID: SkinId = "glitch";
