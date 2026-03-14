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

/** Font size in pixels for glyph rain characters. */
export const GLYPH_FONT_SIZE = 16;

/** Alpha for the trailing fade rectangle (lower = longer trails). */
export const GLYPH_TRAIL_FADE = 0.05;

/** Probability threshold for resetting a glyph column (higher = longer columns). */
export const GLYPH_RESET_THRESHOLD = 0.975;

/** Fallback color for glyph rain when CSS variable is unavailable. */
export const GLYPH_RAIN_COLOR = "#00ff41";
