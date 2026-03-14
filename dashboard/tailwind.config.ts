import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--color-background)",
        foreground: "var(--color-text)",
        surface: "var(--color-surface)",
        "surface-muted": "var(--color-surface-muted)",
        primary: "var(--color-primary)",
        accent: "var(--color-accent)",
        border: "var(--color-border)",
        danger: "var(--color-danger)",
      },
      fontFamily: {
        body: ["var(--font-body)"],
        mono: ["var(--font-mono)"],
      },
      borderRadius: {
        theme: "var(--radius)",
      },
      animation: {
        flicker: "flicker 4s infinite",
      },
      keyframes: {
        flicker: {
          "0%, 100%": { opacity: "1" },
          "92%": { opacity: "1" },
          "93%": { opacity: "0.8" },
          "94%": { opacity: "1" },
          "96%": { opacity: "0.9" },
          "97%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
