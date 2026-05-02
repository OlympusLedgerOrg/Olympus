import { useCallback, useEffect, useMemo, useState } from "react";
import { SKIN_REGISTRY } from "./registry";
import type { SkinId } from "./types";
import { SkinContext, STORAGE_KEY, loadSkinId } from "./SkinContext";

export function SkinProvider({ children }: { children: React.ReactNode }) {
  const [skinId, setSkinIdState] = useState<SkinId>(loadSkinId);

  const setSkinId = useCallback((id: SkinId) => {
    setSkinIdState(id);
    localStorage.setItem(STORAGE_KEY, id);
  }, []);

  const skin = SKIN_REGISTRY[skinId];

  // Stamp the current skin on <html> so skin-scoped CSS selectors work.
  useEffect(() => {
    const root = document.documentElement;
    for (const id of Object.keys(SKIN_REGISTRY)) {
      root.classList.remove(`skin-${id}`);
    }
    root.classList.add(`skin-${skinId}`);
  }, [skinId]);

  const value = useMemo(
    () => ({ skin, skinId, setSkinId }),
    [skin, skinId, setSkinId],
  );

  return <SkinContext.Provider value={value}>{children}</SkinContext.Provider>;
}
