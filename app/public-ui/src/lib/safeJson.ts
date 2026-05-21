/**
 * safeJson — fetch wrapper that never throws on HTML/non-JSON responses.
 *
 * The Tauri asset server returns an HTML 404 page for any path it doesn't
 * know about, including /auth/register when the Axum server isn't up yet.
 * Standard `res.json()` throws a SyntaxError in that case, which our
 * try/catch re-wraps as a generic "Could not create account" error,
 * hiding the real cause.
 *
 * Usage:
 *   const { ok, status, data, text } = await safeJsonFetch(url, init);
 *   if (!ok || !data) { /* handle air-gap / server-down case *\/ }
 */

export interface SafeJsonResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  /** Raw body text — useful for error messages and debugging. */
  text: string;
}

export async function safeJsonFetch<T>(
  url: string,
  init?: RequestInit,
): Promise<SafeJsonResult<T>> {
  let res: Response;
  try {
    res = await fetch(url, init);
  } catch (networkErr) {
    // Network-level failure (offline, CORS preflight blocked, etc.)
    return { ok: false, status: 0, data: null, text: String(networkErr) };
  }

  const text = await res.text().catch(() => "");
  let data: T | null = null;
  try {
    if (text.trimStart().startsWith("{") || text.trimStart().startsWith("[")) {
      data = JSON.parse(text) as T;
    }
  } catch {
    // Body is HTML or plain text — leave data as null.
  }

  return { ok: res.ok, status: res.status, data, text };
}
