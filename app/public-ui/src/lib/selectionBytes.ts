/**
 * Map a `<textarea>` selection index to a byte offset in the original UTF-8 text.
 *
 * Two traps this avoids, both of which would silently redact the wrong bytes:
 *
 *  1. **Multi-byte characters.** `selectionStart` counts UTF-16 code units, not
 *     bytes. A document with non-ASCII content (curly quotes, em-dashes,
 *     accented or CJK names) has character index ≠ byte index, so the offset
 *     must go through `TextEncoder`, never `string.length`.
 *
 *  2. **CRLF normalization.** A textarea normalizes `\r\n` (and lone `\r`) to a
 *     single `\n` in its `.value`, and `selectionStart` indexes that normalized
 *     string — while the original file bytes still contain the `\r`. Mapping the
 *     normalized index straight onto the raw text drifts by one byte per CRLF
 *     before the selection. This walks the original text, consuming one
 *     normalized position per `\r\n`/`\r`/char, to land on the true byte offset.
 *
 * When the original has no `\r`, this reduces exactly to
 * `TextEncoder().encode(text.slice(0, index)).length`.
 */
export function selectionToByteOffset(originalText: string, normIndex: number): number {
  if (normIndex <= 0) return 0;
  let normCount = 0;
  let i = 0;
  while (i < originalText.length && normCount < normIndex) {
    if (originalText[i] === "\r" && originalText[i + 1] === "\n") {
      i += 2; // CRLF collapses to a single normalized '\n'
    } else {
      i += 1; // plain char, or lone CR (also normalized to '\n')
    }
    normCount += 1;
  }
  return new TextEncoder().encode(originalText.slice(0, i)).length;
}
