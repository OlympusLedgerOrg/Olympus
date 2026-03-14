"use client";

import { useContext } from "react";
import { ThemeContext } from "@/components/layout/ThemeProvider";

/**
 * Hook to access the current theme and setter.
 * Must be used within a ThemeProvider.
 */
export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}
