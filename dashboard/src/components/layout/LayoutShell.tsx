"use client";

import { type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeProvider } from "@/components/layout/ThemeProvider";
import { GlyphRain } from "@/components/layout/GlyphRain";
import { ThemeSwitcher } from "@/components/ui/ThemeSwitcher";
import { useTheme } from "@/lib/hooks/useTheme";

function LayoutContent({ children }: { children: ReactNode }) {
  const { theme } = useTheme();

  return (
    <>
      <AnimatePresence>
        {theme === "fight-club" && (
          <motion.div
            key="glyph-rain"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
          >
            <GlyphRain />
          </motion.div>
        )}
      </AnimatePresence>
      <ThemeSwitcher />
      {children}
    </>
  );
}

/**
 * Client-side layout shell that wraps children with ThemeProvider and
 * conditionally renders glyph rain for the fight-club theme.
 */
export function LayoutShell({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider>
      <LayoutContent>{children}</LayoutContent>
    </ThemeProvider>
  );
}
