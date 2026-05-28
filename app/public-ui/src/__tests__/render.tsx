/**
 * Shared test helpers for React component tests.
 *
 * `renderWithSkin` wraps the supplied tree in <SkinProvider> so any
 * component that calls `useSkin()` (i.e. anything in `src/components/`,
 * `src/tabs/`, `src/pages/` that pulls a class set from the active skin)
 * can be rendered in isolation without throwing
 *   `useSkin must be used within a <SkinProvider>`.
 */
import { render, type RenderOptions, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { SkinProvider } from "../skins/SkinProvider";

export function renderWithSkin(
  ui: ReactElement,
  options?: Omit<RenderOptions, "wrapper">,
): RenderResult {
  return render(ui, { wrapper: SkinProvider, ...options });
}
