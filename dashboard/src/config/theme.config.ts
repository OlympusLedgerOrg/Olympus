/** Theme configuration for the Olympus dashboard. */

export const THEME_STORAGE_KEY = "olympus-theme" as const;

export type ThemeName = "fight-club" | "professional" | "minimal" | "accessibility";

export interface ThemeConfig {
  name: ThemeName;
  label: string;
  description: string;
}

export const themes: ThemeConfig[] = [
  {
    name: "fight-club",
    label: "Fight Club",
    description: "Matrix-style terminal aesthetic with glyph rain",
  },
  {
    name: "professional",
    label: "Professional",
    description: "Clean, modern interface for production use",
  },
  {
    name: "minimal",
    label: "Minimal",
    description: "Stripped-down interface with minimal chrome",
  },
  {
    name: "accessibility",
    label: "Accessibility",
    description: "High-contrast theme optimized for screen readers",
  },
];

export const DEFAULT_THEME: ThemeName = "fight-club";

/** Characters used in the glyph rain animation. */
export const GLYPH_CHARS = "01アイウエオカキクケコ";

/** Glyph rain canvas opacity. */
export const GLYPH_RAIN_OPACITY = 0.15;
