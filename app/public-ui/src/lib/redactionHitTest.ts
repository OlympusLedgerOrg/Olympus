// SPDX-License-Identifier: Apache-2.0

/**
 * ADR-0029 A.5-4: map a drag-box drawn on a rendered page back to the committed
 * object ids underneath it.
 *
 * **The whole module exists because two coordinate systems disagree about `y`.**
 * `placements[]` from `POST /redaction/describe` are in **PDF user space**:
 * origin bottom-left, y increasing *upwards*, units in points, and the origin is
 * the page box's own corner (a `/MediaBox` need not start at `0 0`). A canvas is
 * the opposite: origin top-left, y increasing *downwards*, units in CSS pixels
 * after the render scale. Getting that flip wrong does not crash — it silently
 * selects the object mirrored about the page's horizontal axis, which is exactly
 * the kind of mis-redaction that must never happen quietly.
 *
 * Nothing here is a trust boundary. The box only *proposes* object ids; the
 * server re-validates every id against the committed manifest before cutting
 * anything (ADR-0029 §5), so a wrong rect costs the user a bad suggestion, never
 * a bad commitment.
 */

import type { RedactionObjectDescription, RedactionPlacement } from "./api";

/** A rectangle in canvas/CSS pixel space: origin top-left, y down. */
export interface CanvasRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * A page's box as pdf.js reports it (`page.view`), in PDF user space:
 * `[x0, y0, x1, y1]` with `(x0, y0)` the bottom-left corner.
 */
export type PageBox = readonly [number, number, number, number];

/**
 * Convert a placement to canvas pixels for the page it sits on.
 *
 * `scale` is the pdf.js viewport scale the page was rendered at, so the result
 * is directly comparable to pointer coordinates taken from the canvas element.
 */
export function placementToCanvasRect(
  placement: RedactionPlacement,
  pageBox: PageBox,
  scale: number,
): CanvasRect {
  const [x0, y0, , y1] = pageBox;
  // x is a straight translate+scale; y flips about the page's top edge, and the
  // rect's *top* in canvas space is its `y + h` (top edge) in PDF space.
  return {
    x: (placement.x - x0) * scale,
    y: (y1 - (placement.y + placement.h)) * scale,
    w: placement.w * scale,
    h: placement.h * scale,
  };
}

/**
 * Do two axis-aligned rectangles share any area? Touching edges do not count.
 *
 * A degenerate rect (zero width or height) never intersects. Strict-inequality
 * overlap alone does *not* give that: a zero-area rect strictly inside another
 * satisfies all four comparisons, so a bare click would land on whatever sits
 * under the pointer. Selecting on a stray click is a footgun, so it is excluded
 * here rather than at each call site.
 */
export function rectsIntersect(a: CanvasRect, b: CanvasRect): boolean {
  if (a.w <= 0 || a.h <= 0 || b.w <= 0 || b.h <= 0) return false;
  return (
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
  );
}

/**
 * Normalise a drag into a rect with non-negative width/height, so a box dragged
 * up-and-left behaves like one dragged down-and-right.
 */
export function rectFromDrag(
  from: { x: number; y: number },
  to: { x: number; y: number },
): CanvasRect {
  return {
    x: Math.min(from.x, to.x),
    y: Math.min(from.y, to.y),
    w: Math.abs(to.x - from.x),
    h: Math.abs(to.y - from.y),
  };
}

/** One object a box resolved to, with enough context to explain the selection. */
export interface BoxHit {
  objId: number;
  /** The object's human label, e.g. `"Image 800×600 (DCTDecode)"`. */
  label: string;
  /** Classification tag — the UI warns differently for `content_stream`. */
  kind: string;
  /** True when selecting this hides the whole page, not a region of it. */
  wholePage: boolean;
}

/**
 * Objects whose placement on `page` intersects `box`.
 *
 * Returns them **smallest-area first**, so the most specific thing under the
 * pointer leads: a box over a signature sitting on a page resolves to the image
 * before the page-sized content stream that also covers that point. The caller
 * decides how much of the list to apply — this function does not choose for it.
 *
 * A zero-area box (a click, not a drag) selects nothing — see
 * [`rectsIntersect`], which excludes degenerate rects for exactly this case.
 */
export function objectsUnderBox(
  box: CanvasRect,
  page: number,
  descriptions: readonly RedactionObjectDescription[],
  pageBox: PageBox,
  scale: number,
): BoxHit[] {
  const hits: Array<BoxHit & { area: number }> = [];

  for (const d of descriptions) {
    for (const p of d.placements) {
      if (p.page !== page) continue;
      const rect = placementToCanvasRect(p, pageBox, scale);
      if (!rectsIntersect(box, rect)) continue;
      hits.push({
        objId: d.objId,
        label: d.label,
        kind: d.kind,
        // A content stream's placement IS its page box — redacting it blanks the
        // whole page. Surfacing that before the user commits is ADR-0029 §5's
        // over-redaction-is-surfaced rule.
        wholePage: d.kind === "content_stream",
        area: rect.w * rect.h,
      });
      break; // one hit per object, even if several of its placements overlap
    }
  }

  hits.sort((a, b) => a.area - b.area || a.objId - b.objId);
  return hits.map(({ objId, label, kind, wholePage }) => ({
    objId,
    label,
    kind,
    wholePage,
  }));
}
