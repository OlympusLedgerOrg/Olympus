import type { SkinDefinition, SkinId } from "./types";

export const SKIN_REGISTRY: Record<SkinId, SkinDefinition> = {
  glitch: {
    id: "glitch",
    label: "GLITCH",
    description: "Cyberpunk green-on-black with Tyler Durden energy",
    classes: {
      page: "skin-page-glitch",
      hero: "console-hero",
      card: "cyber-panel-sm",
      panel: "cyber-panel",
      buttonPrimary: "cyber-button",
      buttonSecondary: "icon-text-btn",
      input: "cyber-input",
      tabActive: "tab-btn",
      tabInactive: "tab-btn",
      accentText: "skin-accent",
      mutedText: "skin-muted",
    },
    effects: {
      showGlitchMentor: true,
      showSkyscraperBackdrop: true,
      showScanlines: true,
      showGlow: true,
    },
  },

  basic: {
    id: "basic",
    label: "BASIC",
    description: "Clean minimal verifier — production-friendly light mode",
    classes: {
      page: "skin-page-basic",
      hero: "console-hero",
      card: "basic-card",
      panel: "basic-panel",
      buttonPrimary: "basic-button",
      buttonSecondary: "basic-icon-btn",
      input: "basic-input",
      tabActive: "basic-tab-active",
      tabInactive: "basic-tab",
      accentText: "skin-accent",
      mutedText: "skin-muted",
    },
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
    classes: {
      page: "skin-page-terminal",
      hero: "console-hero",
      card: "term-card",
      panel: "term-panel",
      buttonPrimary: "term-button",
      buttonSecondary: "term-icon-btn",
      input: "term-input",
      tabActive: "term-tab-active",
      tabInactive: "term-tab",
      accentText: "skin-accent",
      mutedText: "skin-muted",
    },
    effects: {
      showGlitchMentor: false,
      showSkyscraperBackdrop: false,
      showScanlines: true,
      showGlow: false,
    },
  },
};

export const DEFAULT_SKIN_ID: SkinId = "glitch";
