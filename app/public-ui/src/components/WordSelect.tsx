// SPDX-License-Identifier: Apache-2.0

/**
 * ADR-0029 B-3 (frontend): pick committed **words** to hide in a `pdf-textrun`
 * document.
 *
 * A word-granularity commitment turns the producer checklist from "a few dozen
 * indirect objects" into "every word on every page", so the object affordance
 * stops working: a flat list of several hundred `#id` rows is not something an
 * operator can find a name in. This component makes the listing searchable and
 * shows each word's text, which is the only thing that makes word redaction
 * usable at all.
 *
 * **Selection is a suggestion, not an authority** (ADR-0029 §5). The ids leaving
 * here are re-validated server-side against the committed manifest, and the cut
 * and leaf binding happen in Rust. A wrong row costs the operator a bad
 * selection, never a bad commitment.
 *
 * Container leaves (`skeleton` / `object`) are listed by *count* rather than as
 * rows. They are not hideable — the server rejects them with a bound check — and
 * showing several hundred unselectable rows would bury the words this view
 * exists to surface. The count is shown because silently omitting committed
 * segments would misrepresent what the document contains.
 */

import { useDeferredValue, useMemo, useState } from "react";

import type { RedactionSegmentDescription } from "../lib/api";

/** Rows rendered at once. A page of dense text runs to a few hundred words and a
 *  long document to tens of thousands; past this the list is unusable anyway and
 *  the operator should be searching, so cap it and say so rather than paying to
 *  render rows nobody scrolls to. */
export const MAX_VISIBLE_WORDS = 400;

export interface WordSelectProps {
  /** Committed segments from `POST /redaction/describe`, in `segmentId` order. */
  segments: readonly RedactionSegmentDescription[];
  /** Segment ids currently checked. */
  selectedIds: readonly number[];
  onToggle: (segmentId: number) => void;
  onClear: () => void;
  busy?: boolean;
  /** Theme colours, threaded from the tab so this matches its surroundings.
   *  `purple` is an unclosed `rgba(r,g,b,` prefix, as elsewhere in this UI. */
  purple: string;
  accent: string;
}

/**
 * Searchable checklist of the committed words in a `pdf-textrun` document.
 * Renders only the redactable word segments; container leaves are summarised as
 * a count beneath the list. See the module docs for why.
 */
export function WordSelect({
  segments,
  selectedIds,
  onToggle,
  onClear,
  busy = false,
  purple,
  accent,
}: WordSelectProps) {
  const [query, setQuery] = useState("");
  // Typing a letter re-filters thousands of rows; defer so keystrokes stay
  // responsive and the list catches up.
  const deferredQuery = useDeferredValue(query);

  const words = useMemo(() => segments.filter((s) => s.redactable), [segments]);
  const containerCount = segments.length - words.length;

  const matches = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    if (!q) return words;
    return words.filter((w) => w.text?.toLowerCase().includes(q));
  }, [words, deferredQuery]);

  const visible = matches.slice(0, MAX_VISIBLE_WORDS);
  const hiddenByCap = matches.length - visible.length;
  const selectedSet = useMemo(() => new Set(selectedIds), [selectedIds]);
  // Selections can sit outside the current filter, so count against everything
  // rather than what is on screen — otherwise "clear all" looks like a no-op.
  const selectedWordCount = words.filter((w) => selectedSet.has(w.segmentId)).length;

  return (
    <div style={{ marginTop: "0.85rem" }} data-testid="word-select">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "0.35rem",
        }}
      >
        <span style={{ fontSize: "0.62rem", color: `${purple}0.6)`, letterSpacing: "0.08em" }}>
          WORDS — check to hide ({selectedWordCount}/{words.length} hidden)
        </span>
        {selectedWordCount > 0 && (
          <button
            type="button"
            onClick={onClear}
            disabled={busy}
            style={{
              background: "none",
              border: "none",
              color: `${purple}0.6)`,
              cursor: "pointer",
              fontSize: "0.62rem",
            }}
          >
            clear all
          </button>
        )}
      </div>

      <input
        type="search"
        value={query}
        disabled={busy}
        onChange={(e) => {
          setQuery(e.target.value);
        }}
        placeholder="search words…"
        aria-label="Search committed words"
        style={{
          width: "100%",
          padding: "0.35rem 0.5rem",
          marginBottom: "0.35rem",
          fontSize: "0.68rem",
          color: accent,
          background: "rgba(0,0,0,0.35)",
          border: `1px solid ${purple}0.25)`,
          borderRadius: "6px",
        }}
      />

      <div
        style={{
          maxHeight: "16rem",
          overflowY: "auto",
          border: `1px solid ${purple}0.25)`,
          borderRadius: "6px",
          background: "rgba(0,0,0,0.25)",
        }}
      >
        {visible.length === 0 && (
          <div style={{ padding: "0.6rem", fontSize: "0.68rem", color: `${purple}0.6)` }}>
            {words.length === 0 ? "No words committed." : "No words match that search."}
          </div>
        )}
        {visible.map((w) => {
          const checked = selectedSet.has(w.segmentId);
          return (
            <label
              key={w.segmentId}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                padding: "0.35rem 0.6rem",
                fontSize: "0.68rem",
                color: checked ? "#ff8a8a" : accent,
                borderBottom: `1px solid ${purple}0.12)`,
                cursor: busy ? "default" : "pointer",
              }}
            >
              <input
                type="checkbox"
                checked={checked}
                disabled={busy}
                onChange={() => {
                  onToggle(w.segmentId);
                }}
                aria-label={`Hide word ${w.text ?? `#${w.segmentId.toString()}`}`}
              />
              <span
                style={{
                  flex: 1,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  textDecoration: checked ? "line-through" : "none",
                }}
              >
                {/* A word whose bytes did not decode to printable text shows its
                    id alone rather than mojibake — the server sends null there. */}
                {w.text ?? <em style={{ opacity: 0.6 }}>#{w.segmentId}</em>}
              </span>
              {w.page !== null && (
                <span style={{ flex: "0 0 auto", opacity: 0.55, fontSize: "0.6rem" }}>
                  p{w.page}
                </span>
              )}
            </label>
          );
        })}
      </div>

      <div style={{ marginTop: "0.3rem", fontSize: "0.6rem", color: `${purple}0.55)` }}>
        {hiddenByCap > 0 && (
          <>
            Showing {MAX_VISIBLE_WORDS} of {matches.length} matches — search to narrow.{" "}
          </>
        )}
        {containerCount > 0 && (
          <>
            {containerCount} container {containerCount === 1 ? "leaf" : "leaves"}{" "}
            {containerCount === 1 ? "binds" : "bind"} the document and cannot be hidden.
          </>
        )}
      </div>
    </div>
  );
}
