import { useEffect, useState } from "react";
import { checkWasmAvailable } from "../lib/blake3";

export type WasmStatus = "loading" | "ready" | "error";

/**
 * Proactively checks whether the BLAKE3 WASM module is usable in the current
 * browser environment (e.g., it will fail when the site's Content Security
 * Policy blocks `wasm-unsafe-eval`).
 *
 * Returns:
 *   - `wasmStatus`: "loading" while the probe is in flight, "ready" on
 *     success, "error" if the module could not be loaded.
 *   - `wasmError`: human-readable error message when `wasmStatus === "error"`,
 *     null otherwise.
 */
export function useWasmStatus() {
  const [wasmStatus, setWasmStatus] = useState<WasmStatus>("loading");
  const [wasmError, setWasmError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    checkWasmAvailable()
      .then(() => {
        if (!cancelled) setWasmStatus("ready");
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setWasmStatus("error");
          setWasmError(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return { wasmStatus, wasmError };
}
