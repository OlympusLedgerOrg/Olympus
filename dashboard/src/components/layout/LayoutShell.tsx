"use client";

import { type ReactNode, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeProvider } from "@/components/layout/ThemeProvider";
import { GlyphRain } from "@/components/layout/GlyphRain";
import { ThemeSwitcher } from "@/components/ui/ThemeSwitcher";
import { WalletConnectProvider } from "@/components/auth/WalletConnect";
import { AuthProvider } from "@/lib/hooks/useAuth";
import { useTheme } from "@/lib/hooks/useTheme";
import { TerminalOverlay } from "@/components/terminal/TerminalOverlay";
import { useTerminalHotkey } from "@/components/terminal/useTerminalHotkey";

function LayoutContent({ children }: { children: ReactNode }) {
  const { theme } = useTheme();
  const [terminalOpen, setTerminalOpen] = useState(false);

  useTerminalHotkey(
    () => setTerminalOpen(true),
    () => setTerminalOpen(false),
  );

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
      <TerminalOverlay open={terminalOpen} />
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
      <WalletConnectProvider>
        <AuthProvider>
          <LayoutContent>{children}</LayoutContent>
        </AuthProvider>
      </WalletConnectProvider>
    </ThemeProvider>
  );
}
