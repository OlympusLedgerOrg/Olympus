"use client";

import {
  createContext,
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  DEFAULT_THEME,
  THEME_STORAGE_KEY,
  type ThemeName,
} from "@/config/theme.config";

export interface ThemeContextValue {
  theme: ThemeName;
  setTheme: (theme: ThemeName) => void;
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);

/**
 * Provides the current theme via React context, persists choice in
 * localStorage, and applies `data-theme` to the document root element.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(DEFAULT_THEME);

  /* Hydrate from localStorage on mount */
  useEffect(() => {
    try {
      const stored = localStorage.getItem(THEME_STORAGE_KEY);
      if (
        stored === "fight-club" ||
        stored === "professional" ||
        stored === "minimal" ||
        stored === "accessibility"
      ) {
        setThemeState(stored);
      }
    } catch {
      /* localStorage unavailable – keep default */
    }
  }, []);

  /* Sync data-theme attribute whenever theme changes */
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const setTheme = useCallback((next: ThemeName) => {
    setThemeState(next);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      /* localStorage unavailable – ignore */
    }
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
