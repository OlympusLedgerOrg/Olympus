// SPDX-License-Identifier: Apache-2.0

/**
 * ADR-0029 A.5-4: render a committed PDF page and let the operator drag a box
 * over the region they want to hide.
 *
 * **pdf.js is display-only and is NOT a trust boundary** (ADR-0029 §5). It draws
 * pixels so a human can point; the box it produces is only a *suggestion* of
 * object ids. The cut, the leaf binding, and the re-validation against the
 * committed manifest all happen in Rust — a renderer that drew the wrong thing
 * costs the user a bad suggestion, never a bad commitment.
 *
 * Two environment constraints shape this file:
 *
 *  * The Tauri CSP is `script-src 'self' 'wasm-unsafe-eval'` — no `unsafe-eval`.
 *    pdf.js v6 removed its eval-based path entirely, so nothing extra is needed
 *    (v5 and earlier wanted `isEvalSupported: false`; that option no longer
 *    exists). Its worker loads from a same-origin bundled URL, which
 *    `default-src 'self'` permits — a `blob:` worker would not be.
 *  * pdf.js is imported **dynamically**, so it stays out of the main bundle and
 *    out of jsdom's way in tests.
 */

import { useCallback, useEffect, useRef, useState } from "react";

import {
  objectsUnderBox,
  rectFromDrag,
  type BoxHit,
  type CanvasRect,
  type PageBox,
} from "../lib/redactionHitTest";
import type { RedactionObjectDescription } from "../lib/api";

/** Render scale. 1.5 keeps a Letter page legible without a huge canvas. */
const RENDER_SCALE = 1.5;

export interface PdfBoxSelectProps {
  /** The committed document's bytes — for *display* only. */
  bytes: Uint8Array;
  /** 1-based page to render. */
  page: number;
  /** Descriptions from `POST /redaction/describe`, carrying `placements[]`. */
  descriptions: readonly RedactionObjectDescription[];
  /** Called when a drag resolves to one or more objects, smallest-area first. */
  onResolve: (hits: BoxHit[]) => void;
}

type LoadState =
  | { status: "loading" }
  | { status: "ready"; pageBox: PageBox }
  | { status: "error"; message: string };

export function PdfBoxSelect({ bytes, page, descriptions, onResolve }: PdfBoxSelectProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [load, setLoad] = useState<LoadState>({ status: "loading" });
  /**
   * A drag in flight, tracked in BOTH spaces: `box` is backing-store pixels for
   * the hit test, `boxCss` is displayed CSS pixels for positioning the overlay.
   * They diverge whenever the canvas is CSS-downscaled.
   */
  const [drag, setDrag] = useState<{
    from: { x: number; y: number };
    fromCss: { x: number; y: number };
    box: CanvasRect;
    boxCss: CanvasRect;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    let cleanup: (() => void) | undefined;

    (async () => {
      try {
        const pdfjs = await import("pdfjs-dist");
        // Same-origin worker URL; see the CSP note in the module docs.
        const workerUrl = await import("pdfjs-dist/build/pdf.worker.min.mjs?url");
        pdfjs.GlobalWorkerOptions.workerSrc = workerUrl.default;

        // `bytes` is passed to a worker that may transfer/detach it; hand over a
        // copy so the caller's buffer (also used for hashing and the describe
        // call) is never emptied underneath it.
        const loadingTask = pdfjs.getDocument({ data: new Uint8Array(bytes) });
        // `destroy()` lives on the loading task, not the document — it is what
        // tears the worker down.
        cleanup = () => void loadingTask.destroy();
        const doc = await loadingTask.promise;
        if (cancelled) return;

        const pdfPage = await doc.getPage(page);
        if (cancelled) return;

        const viewport = pdfPage.getViewport({ scale: RENDER_SCALE });
        const canvas = canvasRef.current;
        if (!canvas) {
          // Without a canvas there is nothing to draw on and no retry; failing
          // here beats sitting on "Rendering page N…" forever.
          setLoad({
            status: "error",
            message: "canvas element unavailable at render time",
          });
          return;
        }
        canvas.width = Math.ceil(viewport.width);
        canvas.height = Math.ceil(viewport.height);
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          setLoad({ status: "error", message: "canvas 2d context unavailable" });
          return;
        }
        await pdfPage.render({ canvas, canvasContext: ctx, viewport }).promise;
        if (cancelled) return;

        // `page.view` is the page box in PDF user space — the same space the
        // placements are in, including a non-zero origin.
        const view = pdfPage.view as number[];
        setLoad({
          status: "ready",
          pageBox: [view[0], view[1], view[2], view[3]] as PageBox,
        });
      } catch (e) {
        if (!cancelled) {
          setLoad({
            status: "error",
            message: e instanceof Error ? e.message : String(e),
          });
        }
      }
    })();

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, [bytes, page]);

  /**
   * Pointer position in **canvas backing-store pixels** — the space
   * `placementToCanvasRect` works in.
   *
   * The canvas carries `max-w-full`, so any container narrower than the rendered
   * width displays it downscaled. Reading the pointer in CSS pixels and treating
   * them as backing-store pixels would resolve the box to a different region
   * than the operator drew, silently — the same class of failure as getting the
   * y-flip wrong.
   */
  const pointAt = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    const canvas = canvasRef.current;
    const target = canvas ?? e.currentTarget;
    const r = target.getBoundingClientRect();
    const sx = canvas && r.width > 0 ? canvas.width / r.width : 1;
    const sy = canvas && r.height > 0 ? canvas.height / r.height : 1;
    return { x: (e.clientX - r.left) * sx, y: (e.clientY - r.top) * sy };
  }, []);

  /** The same point in displayed CSS pixels, for positioning the overlay. */
  const cssPointAt = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  }, []);

  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (load.status !== "ready") return;
      const p = pointAt(e);
      const pCss = cssPointAt(e);
      e.currentTarget.setPointerCapture?.(e.pointerId);
      setDrag({
        from: p,
        fromCss: pCss,
        box: { ...p, w: 0, h: 0 },
        boxCss: { ...pCss, w: 0, h: 0 },
      });
    },
    [load.status, pointAt, cssPointAt],
  );

  const onPointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!drag) return;
      setDrag({
        ...drag,
        box: rectFromDrag(drag.from, pointAt(e)),
        boxCss: rectFromDrag(drag.fromCss, cssPointAt(e)),
      });
    },
    [drag, pointAt, cssPointAt],
  );

  const onPointerUp = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!drag || load.status !== "ready") return;
      const box = rectFromDrag(drag.from, pointAt(e));
      setDrag(null);
      onResolve(objectsUnderBox(box, page, descriptions, load.pageBox, RENDER_SCALE));
    },
    [drag, load, onResolve, page, descriptions, pointAt],
  );

  if (load.status === "error") {
    return (
      <div role="alert" className="text-sm text-red-600">
        Could not render this page for box selection ({load.message}). The object checklist below
        still works.
      </div>
    );
  }

  return (
    <div
      data-testid="pdf-box-select"
      className="relative inline-block touch-none select-none"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
    >
      <canvas ref={canvasRef} className="block max-w-full" />
      {drag && drag.boxCss.w > 0 && drag.boxCss.h > 0 && (
        <div
          data-testid="pdf-box-select-rect"
          className="pointer-events-none absolute border-2 border-blue-500 bg-blue-500/20"
          style={{
            left: drag.boxCss.x,
            top: drag.boxCss.y,
            width: drag.boxCss.w,
            height: drag.boxCss.h,
          }}
        />
      )}
      {load.status === "loading" && (
        <div className="text-sm text-slate-500">Rendering page {page}…</div>
      )}
    </div>
  );
}
