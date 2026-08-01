// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  objectsUnderBox,
  placementToCanvasRect,
  rectFromDrag,
  rectsIntersect,
  type PageBox,
} from "./redactionHitTest";
import type { RedactionObjectDescription, RedactionPlacement } from "./api";

/** US Letter, origin at 0,0 — the common case. */
const LETTER: PageBox = [0, 0, 612, 792];

function obj(
  objId: number,
  kind: string,
  label: string,
  placements: RedactionPlacement[],
): RedactionObjectDescription {
  return {
    objId,
    byteLength: 100,
    kind: kind as RedactionObjectDescription["kind"],
    label,
    page: placements[0]?.page ?? null,
    preview: null,
    width: null,
    height: null,
    filter: null,
    baseFont: null,
    typeName: null,
    placements,
  };
}

describe("placementToCanvasRect", () => {
  it("flips y about the page's top edge", () => {
    // A 200×100 rect whose bottom sits 600pt up the page. In canvas space its
    // TOP edge is 792 - (600 + 100) = 92pt from the page top.
    const r = placementToCanvasRect({ page: 1, x: 50, y: 600, w: 200, h: 100 }, LETTER, 1);
    expect(r).toEqual({ x: 50, y: 92, w: 200, h: 100 });
  });

  it("maps a full-page placement onto the whole canvas", () => {
    const r = placementToCanvasRect({ page: 1, x: 0, y: 0, w: 612, h: 792 }, LETTER, 1);
    expect(r).toEqual({ x: 0, y: 0, w: 612, h: 792 });
  });

  it("honours a page box whose origin is not 0,0", () => {
    // A /MediaBox need not start at the origin; the offset must be subtracted or
    // every rect lands shifted by it.
    const offset: PageBox = [10, 20, 622, 812];
    const r = placementToCanvasRect({ page: 1, x: 10, y: 20, w: 100, h: 50 }, offset, 1);
    // Bottom-left of the box IS the page's bottom-left → canvas x 0, and its top
    // edge is 50pt above the page bottom, i.e. 812 - (20 + 50) = 742 from the top.
    expect(r).toEqual({ x: 0, y: 742, w: 100, h: 50 });
  });

  it("applies the render scale to position and size alike", () => {
    const r = placementToCanvasRect({ page: 1, x: 50, y: 600, w: 200, h: 100 }, LETTER, 2);
    expect(r).toEqual({ x: 100, y: 184, w: 400, h: 200 });
  });

  it("round-trips the page's bottom edge to the canvas bottom", () => {
    // Guards the flip's sign: a placement flush with the page bottom must land
    // flush with the canvas bottom, not the top.
    const r = placementToCanvasRect({ page: 1, x: 0, y: 0, w: 10, h: 10 }, LETTER, 1);
    expect(r.y + r.h).toBe(792);
  });
});

describe("rectsIntersect", () => {
  const a = { x: 10, y: 10, w: 20, h: 20 };

  it("detects overlap", () => {
    expect(rectsIntersect(a, { x: 20, y: 20, w: 20, h: 20 })).toBe(true);
  });

  it("rejects a disjoint rect", () => {
    expect(rectsIntersect(a, { x: 100, y: 100, w: 5, h: 5 })).toBe(false);
  });

  it("treats touching edges as no overlap", () => {
    expect(rectsIntersect(a, { x: 30, y: 10, w: 20, h: 20 })).toBe(false);
  });

  it("rejects a zero-area rect inside another", () => {
    expect(rectsIntersect(a, { x: 15, y: 15, w: 0, h: 0 })).toBe(false);
  });
});

describe("rectFromDrag", () => {
  it("normalises a drag made up and to the left", () => {
    expect(rectFromDrag({ x: 100, y: 100 }, { x: 40, y: 30 })).toEqual({
      x: 40,
      y: 30,
      w: 60,
      h: 70,
    });
  });

  it("gives a zero-area rect for a click", () => {
    expect(rectFromDrag({ x: 5, y: 5 }, { x: 5, y: 5 })).toEqual({
      x: 5,
      y: 5,
      w: 0,
      h: 0,
    });
  });
});

describe("objectsUnderBox", () => {
  // A signature image sitting on a page whose content stream covers everything.
  const image = obj(96, "image", "Image 200×100 (DCTDecode)", [
    { page: 1, x: 50, y: 600, w: 200, h: 100 },
  ]);
  const content = obj(2, "content_stream", "Page 1 — text", [
    { page: 1, x: 0, y: 0, w: 612, h: 792 },
  ]);
  const font = obj(5, "font", "Font: Helvetica", []);
  const all = [image, content, font];

  it("resolves a box over the signature to the image first", () => {
    // Both cover the point; the smaller, more specific object must lead.
    const hits = objectsUnderBox({ x: 60, y: 100, w: 40, h: 40 }, 1, all, LETTER, 1);
    expect(hits.map((h) => h.objId)).toEqual([96, 2]);
    expect(hits[0].wholePage).toBe(false);
  });

  it("flags a content stream as whole-page so the UI can warn", () => {
    // A box over bare text hits only the page-sized content stream — redacting
    // it blanks the entire page, and that must not be a surprise.
    const hits = objectsUnderBox({ x: 300, y: 700, w: 20, h: 20 }, 1, all, LETTER, 1);
    expect(hits.map((h) => h.objId)).toEqual([2]);
    expect(hits[0].wholePage).toBe(true);
    expect(hits[0].label).toBe("Page 1 — text");
  });

  it("ignores objects with no placement", () => {
    const hits = objectsUnderBox({ x: 0, y: 0, w: 612, h: 792 }, 1, all, LETTER, 1);
    expect(hits.map((h) => h.objId)).not.toContain(font.objId);
  });

  it("ignores placements on another page", () => {
    const onPage2 = obj(7, "image", "Image", [{ page: 2, x: 50, y: 600, w: 200, h: 100 }]);
    const hits = objectsUnderBox({ x: 60, y: 100, w: 40, h: 40 }, 1, [onPage2], LETTER, 1);
    expect(hits).toEqual([]);
  });

  it("selects nothing for a click", () => {
    const hits = objectsUnderBox({ x: 60, y: 100, w: 0, h: 0 }, 1, all, LETTER, 1);
    expect(hits).toEqual([]);
  });

  it("counts an object once even when several of its placements overlap the box", () => {
    const twice = obj(96, "image", "Image", [
      { page: 1, x: 50, y: 600, w: 200, h: 100 },
      { page: 1, x: 60, y: 610, w: 200, h: 100 },
    ]);
    const hits = objectsUnderBox({ x: 0, y: 0, w: 612, h: 792 }, 1, [twice], LETTER, 1);
    expect(hits).toHaveLength(1);
  });

  it("applies the same scale it was rendered at", () => {
    // At scale 2 the signature occupies canvas (100,184)-(500,384). A box that
    // would miss at scale 1 must hit here.
    const box = { x: 120, y: 200, w: 20, h: 20 };
    expect(objectsUnderBox(box, 1, [image], LETTER, 1)).toEqual([]);
    expect(objectsUnderBox(box, 1, [image], LETTER, 2).map((h) => h.objId)).toEqual([96]);
  });
});
