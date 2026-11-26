// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// The prompt character budget, in one place and with no dependencies.
//
// Ollama truncates an oversized prompt SILENTLY — no error, no warning — so a
// budget larger than the window the model will really get means the model
// answers confidently from a partial view while the caller's own truncation
// notes claim everything was sent. The budget therefore has to be derived from
// the EFFECTIVE `num_ctx` (configured value clamped to what the model declares),
// and every caller that builds a prompt must derive it the same way. `backend`
// owns that window; this module owns the arithmetic both `mcp-server` and
// `qwen-local` apply to it. It is dependency-free on purpose: `qwen-local`
// imports the Ollama client lazily so `--check` works before
// `npm install --prefix tools/wiserepo`, but its budget must still come from
// the same formula rather than a second copy of these numbers.

// ~3 chars/token is deliberately pessimistic for this codebase (paths, diff
// markers and dense Rust prose all over-tokenize).
export const CHARS_PER_TOKEN_ESTIMATE = 3;

// Keeps room for the answer so the prompt and the completion fit in one window.
export const OUTPUT_TOKEN_RESERVE = 4_096;

// Ollama's own default window is sized from available VRAM and lands at 4096 on
// a CPU-only box. This is the base default when `WISEREPO_NUM_CTX` is unset;
// `backend.mjs` reads the env var over it.
export const DEFAULT_NUM_CTX = 16_384;

/**
 * Character budget for one prompt, from the window the model will really get.
 *
 * Callers pass `effectiveNumCtx()`: the configured value clamped to what the
 * model declares it can hold. A budget derived from a window the model does not
 * have is the silent-truncation bug this exists to prevent.
 */
export function budgetCharsFor(numCtx) {
  return Math.max(1_024, numCtx - OUTPUT_TOKEN_RESERVE) * CHARS_PER_TOKEN_ESTIMATE;
}
