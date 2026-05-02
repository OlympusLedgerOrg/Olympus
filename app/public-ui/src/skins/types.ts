export type SkinId = "glitch" | "basic" | "terminal";

export interface SkinDefinition {
  id: SkinId;
  label: string;
  description: string;
  classes: {
    /** Root wrapper — sets page background and default text colour. */
    page: string;
    /** Console-hero / page title area. */
    hero: string;
    /** Small stat cards. */
    card: string;
    /** Main verification panel. */
    panel: string;
    /** Primary CTA button (Verify, Submit…). */
    buttonPrimary: string;
    /** Secondary action button (PASTE, FORMAT, SAMPLE…). */
    buttonSecondary: string;
    /** Text inputs and textareas. */
    input: string;
    /** Active tab button. */
    tabActive: string;
    /** Inactive tab button. */
    tabInactive: string;
    /** Accent / highlight text colour class. */
    accentText: string;
    /** Muted / secondary text colour class. */
    mutedText: string;
  };
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
