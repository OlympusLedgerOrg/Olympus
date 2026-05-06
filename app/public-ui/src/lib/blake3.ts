/**
 * Browser-side BLAKE3 hashing via WebAssembly.
 *
 * Uses the `blake3-wasm` package's web-optimised WASM build.  The WASM module
 * is loaded lazily on the first call; subsequent calls reuse the already-
 * initialised module.
 *
 * Vite resolves the `?url` import to a cache-busted URL for the `.wasm`
 * binary, which is then fetched and instantiated by the WASM JS glue.
 */

// ─── CONTRACT ─────────────────────────────────────────────────────────────────
//
// This file and frontend/src/lib/olympus-crypto.ts share the same BLAKE3 init
// logic and must be kept behaviorally identical.
//
// Why two files exist:
//   frontend/ is a migration source directory with no package.json — it cannot
//   import from app/public-ui/ without a monorepo workspace setup.  Until that
//   workspace is established the init logic must be kept in sync manually.
//   If you change one file, change the other.
//
// Plain BLAKE3 (hashBytes) = content addressing, display, API lookups.
// Domain-separated (OLY:LEAF:V1, OLY:NODE:V1) = SMT internals.
// NEVER compare a plain hashBytes output against a domain-separated hash.
// They hash the same data but produce different values — that's intentional.
// Comparing them is always a bug.
//
// ─────────────────────────────────────────────────────────────────────────────

import init, {
  hash as _wasmHash,
  create_hasher as _createHasher,
} from "blake3-wasm/dist/wasm/web/blake3_js";
import blake3WasmUrl from "blake3-wasm/dist/wasm/web/blake3_js_bg.wasm?url";

/** Resolves once the WASM binary has been fetched and instantiated. */
let initPromise: ReturnType<typeof init> | null = null;

function ensureInit(): ReturnType<typeof init> {
  if (!initPromise) {
    initPromise = init(blake3WasmUrl).then(
      (r) => r,
      (err: unknown) => {
        // Clear the cached promise so the caller can retry after transient failures.
        initPromise = null;
        const msg = err instanceof Error ? err.message : String(err);
        // Detect Content Security Policy rejections so we can give users a
        // clear, actionable message instead of a raw WASM compile error.
        const isCsp =
          /disallowed by embedder|Content Security Policy|wasm-unsafe-eval/i.test(
            msg,
          );
        throw new Error(
          isCsp
            ? "BLAKE3 WASM is blocked by this browser's Content Security Policy. " +
              "All BLAKE3 hashing and verification are unavailable in this environment."
            : `BLAKE3 WASM failed to initialize: ${msg}`,
        );
      },
    );
  }
  return initPromise;
}

/**
 * Proactively check whether the BLAKE3 WASM module can be loaded.
 * Resolves with no value on success; rejects with a user-friendly Error on failure.
 * Safe to call multiple times — the resolved module is cached after the first success.
 */
export async function checkWasmAvailable(): Promise<void> {
  await ensureInit();
}

/**
 * Hash a raw byte buffer with BLAKE3 and return the 64-char lowercase hex
 * digest.
 */
export async function hashBytes(data: Uint8Array): Promise<string> {
  await ensureInit();
  const out = new Uint8Array(32);
  _wasmHash(data, out);
  // ABI guard: blake3-wasm fills `out` in-place. If the calling convention ever
  // breaks, out stays all-zero and we'd silently commit wrong hashes to the ledger.
  // BLAKE3 of any input (including empty) is never all-zero, so this catches all cases.
  if (out.every((b) => b === 0)) {
    throw new Error(
      "BLAKE3 WASM produced all-zero digest — possible ABI mismatch. " +
        "Do not commit hashes from this session.",
    );
  }
  return toHex(out);
}

/**
 * Hash a `File` object in 4 MB chunks, calling `onProgress(0–100)` as each
 * chunk is processed.  Returns the 64-char BLAKE3 hex digest.
 *
 * Bytes never leave the device — hashing happens entirely in-browser.
 */
export async function hashFile(
  file: File,
  onProgress?: (pct: number) => void,
): Promise<string> {
  await ensureInit();

  const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
  const total = file.size;

  if (total === 0) {
    // Empty file: hash an empty byte array
    const out = new Uint8Array(32);
    _wasmHash(new Uint8Array(0), out);
    // ABI guard: BLAKE3 of an empty buffer is non-zero; all-zero means ABI is broken.
    if (out.every((b) => b === 0)) {
      throw new Error(
        "BLAKE3 WASM produced all-zero digest — possible ABI mismatch. " +
          "Do not commit hashes from this session.",
      );
    }
    onProgress?.(100);
    return toHex(out);
  }

  // Use streaming hasher for chunked progress reporting
  const hasher = _createHasher();
  let offset = 0;

  try {
    while (offset < total) {
      const slice = file.slice(offset, offset + CHUNK_SIZE);
      const buf = await slice.arrayBuffer();
      hasher.update(new Uint8Array(buf));
      offset += buf.byteLength;
      onProgress?.(Math.round((offset / total) * 100));
    }

    // Finalise: read the 32-byte digest
    const out = new Uint8Array(32);
    hasher.digest(out);
    // ABI guard: blake3-wasm fills `out` in-place via hasher.digest(). All-zero means ABI is broken.
    if (out.every((b) => b === 0)) {
      throw new Error(
        "BLAKE3 WASM produced all-zero digest — possible ABI mismatch. " +
          "Do not commit hashes from this session.",
      );
    }
    return toHex(out);
  } finally {
    // WASM memory is not garbage-collected by the JS engine; free() is mandatory.
    hasher.free();
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
