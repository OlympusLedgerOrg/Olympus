// SPDX-License-Identifier: Apache-2.0

/**
 * useReleaseChannel — which build of Olympus is this?
 *
 * Reads the build-time channel stamp from `/health` (see
 * `src-tauri/src/server/handlers.rs::release_metadata` and
 * `docs/plans/preview-release-channel.md`). The Rust const is the single
 * source of truth: it is stamped by `src-tauri/build.rs` into the same binary
 * that carries the ZK ceremony artifacts, so it cannot drift from the thing it
 * describes the way a separate frontend-side build define could.
 *
 * Returns `null` while the server is still starting. Callers must treat that
 * as "unknown", not as "stable" — a preview build must never render as a
 * production one just because the probe has not landed yet.
 */
import { useQuery } from "@tanstack/react-query";
import { getReleaseInfo, type ReleaseInfo } from "../lib/api";

export interface ReleaseChannelState {
  /** `null` until `/health` answers. */
  info: ReleaseInfo | null;
  /** True only once the server has positively reported the preview channel. */
  isPreview: boolean;
}

export function useReleaseChannel(): ReleaseChannelState {
  const query = useQuery({
    queryKey: ["release-info"],
    queryFn: getReleaseInfo,
    // The value is a compile-time constant of the running binary, so it can
    // never change while the app is open. Fetch once and keep it.
    staleTime: Infinity,
    gcTime: Infinity,
    // The server may not be up yet on first paint; keep retrying so the
    // banner appears as soon as it is.
    retry: true,
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 5000),
    refetchOnWindowFocus: false,
  });

  const info = query.data ?? null;
  return { info, isPreview: info?.channel === "preview" };
}
