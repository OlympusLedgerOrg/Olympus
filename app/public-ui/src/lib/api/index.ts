// SPDX-License-Identifier: Apache-2.0

/**
 * API client for the Olympus FastAPI backend — facade re-exporting every
 * domain module. Split by domain across `lib/api/*.ts`; import sites use
 * `from "../lib/api"` (or `"./api"`) unchanged, resolving to this directory's
 * `index.ts` exactly as they resolved to the flat `api.ts` before the split.
 */

export * from "./core";
export * from "./verification";
export * from "./zk";
export * from "./redaction";

export type { V3Bundle, V3Segment } from "../redactionBinding";
