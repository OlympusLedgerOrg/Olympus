export type SkinId = "glitch" | "basic" | "terminal";

export interface SkinDefinition {
  id: SkinId;
  label: string;
  description: string;
  /**
   * Behavioural toggles only. Appearance is expressed entirely through the
   * `html.skin-*` token blocks in index.css + styles/ods.css — a skin no
   * longer maps component roles to bespoke class names.
   */
  effects?: {
    /** Show the Tyler Durden glitch mentor popups. */
    showGlitchMentor?: boolean;
    /** Show the SVG skyline backdrop. */
    showSkyscraperBackdrop?: boolean;
    /** Show the CRT scanline overlay. */
    showScanlines?: boolean;
    /** Apply neon glow to headings and active elements. */
    showGlow?: boolean;
  };
}
