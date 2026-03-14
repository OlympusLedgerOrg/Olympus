"use client";

import { themes, type ThemeName } from "@/config/theme.config";
import { useTheme } from "@/lib/hooks/useTheme";

/**
 * Dropdown to switch between available themes.
 */
export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="fixed top-3 right-3 z-[1000]">
      <select
        value={theme}
        onChange={(e) => setTheme(e.target.value as ThemeName)}
        aria-label="Select theme"
        className="rounded px-2 py-1 text-sm border cursor-pointer"
        style={{
          background: "var(--color-surface)",
          color: "var(--color-text)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
        }}
      >
        {themes.map((t) => (
          <option key={t.name} value={t.name}>
            {t.label}
          </option>
        ))}
      </select>
    </div>
  );
}
