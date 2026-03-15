"use client";

import { useEffect } from "react";

export function useTerminalHotkey(open: () => void, close: () => void) {
  useEffect(() => {
    function handler(event: KeyboardEvent) {
      if (event.ctrlKey && event.key === "`") {
        event.preventDefault();
        open();
      }

      if (event.key === "Escape") {
        close();
      }
    }

    window.addEventListener("keydown", handler);
    return () => {
      window.removeEventListener("keydown", handler);
    };
  }, [close, open]);
}
