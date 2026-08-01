import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

// pdf.js cannot render in jsdom, and it is display-only anyway — what matters
// here is that a drag resolves to the right object ids. Mock the renderer and
// assert the selection behaviour.
const getViewport = vi.fn(() => ({ width: 918, height: 1188 }));
const renderPage = vi.fn(() => ({ promise: Promise.resolve() }));
const destroy = vi.fn();

vi.mock("pdfjs-dist", () => ({
  GlobalWorkerOptions: { workerSrc: "" },
  getDocument: vi.fn(() => ({
    promise: Promise.resolve({
      destroy,
      getPage: vi.fn(async () => ({
        getViewport,
        render: renderPage,
        // US Letter, origin at 0,0 — matches the placements below.
        view: [0, 0, 612, 792],
      })),
    }),
  })),
}));
vi.mock("pdfjs-dist/build/pdf.worker.min.mjs?url", () => ({
  default: "/assets/pdf.worker.mjs",
}));

import { PdfBoxSelect } from "./PdfBoxSelect";
import type { RedactionObjectDescription } from "../lib/api";

function obj(
  objId: number,
  kind: string,
  label: string,
  placements: RedactionObjectDescription["placements"],
): RedactionObjectDescription {
  return {
    objId,
    byteLength: 100,
    kind: kind as RedactionObjectDescription["kind"],
    label,
    page: 1,
    preview: null,
    width: null,
    height: null,
    filter: null,
    baseFont: null,
    typeName: null,
    placements,
  };
}

// A signature image on a page whose content stream covers the whole sheet.
const DESCRIPTIONS = [
  obj(96, "image", "Image 200×100 (DCTDecode)", [
    { page: 1, x: 50, y: 600, w: 200, h: 100 },
  ]),
  obj(2, "content_stream", "Page 1 — text", [
    { page: 1, x: 0, y: 0, w: 612, h: 792 },
  ]),
];

beforeEach(() => {
  vi.clearAllMocks();
  // jsdom has no 2d context; the component treats a missing one as an error, so
  // give it a stub.
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({}) as never);
});

async function renderReady(onResolve = vi.fn()) {
  render(
    <PdfBoxSelect
      bytes={new Uint8Array([1, 2, 3])}
      page={1}
      descriptions={DESCRIPTIONS}
      onResolve={onResolve}
    />,
  );
  await waitFor(() => expect(renderPage).toHaveBeenCalled());
  return { onResolve, surface: screen.getByTestId("pdf-box-select") };
}

/** Drag from (x1,y1) to (x2,y2) in canvas pixels. */
function drag(
  surface: HTMLElement,
  x1: number,
  y1: number,
  x2: number,
  y2: number,
) {
  fireEvent.pointerDown(surface, { clientX: x1, clientY: y1, pointerId: 1 });
  fireEvent.pointerMove(surface, { clientX: x2, clientY: y2, pointerId: 1 });
  fireEvent.pointerUp(surface, { clientX: x2, clientY: y2, pointerId: 1 });
}

describe("PdfBoxSelect", () => {
  it("renders the requested page with eval disabled (CSP has no unsafe-eval)", async () => {
    const pdfjs = await import("pdfjs-dist");
    await renderReady();
    expect(vi.mocked(pdfjs.getDocument)).toHaveBeenCalledWith(
      expect.objectContaining({ isEvalSupported: false }),
    );
  });

  it("resolves a box over the signature to the image, most specific first", async () => {
    const { onResolve, surface } = await renderReady();
    // The image occupies canvas y 138..288 at scale 1.5 (792-700=92pt → 138px).
    drag(surface, 90, 150, 200, 250);
    expect(onResolve).toHaveBeenCalledTimes(1);
    const hits = onResolve.mock.calls[0][0];
    expect(hits.map((h: { objId: number }) => h.objId)).toEqual([96, 2]);
    expect(hits[0].wholePage).toBe(false);
  });

  it("flags a bare-text box as whole-page so the caller can warn", async () => {
    const { onResolve, surface } = await renderReady();
    // Well clear of the image: only the page-sized content stream is here.
    drag(surface, 400, 900, 500, 1000);
    const hits = onResolve.mock.calls[0][0];
    expect(hits.map((h: { objId: number }) => h.objId)).toEqual([2]);
    expect(hits[0].wholePage).toBe(true);
  });

  it("selects nothing on a click", async () => {
    const { onResolve, surface } = await renderReady();
    drag(surface, 100, 160, 100, 160);
    expect(onResolve).toHaveBeenCalledWith([]);
  });

  it("shows the selection rectangle only while dragging", async () => {
    const { surface } = await renderReady();
    expect(screen.queryByTestId("pdf-box-select-rect")).toBeNull();
    fireEvent.pointerDown(surface, { clientX: 90, clientY: 150, pointerId: 1 });
    fireEvent.pointerMove(surface, { clientX: 200, clientY: 250, pointerId: 1 });
    expect(screen.getByTestId("pdf-box-select-rect")).toBeInTheDocument();
    fireEvent.pointerUp(surface, { clientX: 200, clientY: 250, pointerId: 1 });
    expect(screen.queryByTestId("pdf-box-select-rect")).toBeNull();
  });

  it("copies the bytes so the caller's buffer is not detached by the worker", async () => {
    const pdfjs = await import("pdfjs-dist");
    const bytes = new Uint8Array([1, 2, 3]);
    render(
      <PdfBoxSelect
        bytes={bytes}
        page={1}
        descriptions={DESCRIPTIONS}
        onResolve={vi.fn()}
      />,
    );
    await waitFor(() => expect(renderPage).toHaveBeenCalled());
    const passed = vi.mocked(pdfjs.getDocument).mock.calls[0][0] as {
      data: Uint8Array;
    };
    expect(passed.data).not.toBe(bytes);
    expect(Array.from(passed.data)).toEqual([1, 2, 3]);
  });

  it("degrades to a message instead of blocking the checklist", async () => {
    const pdfjs = await import("pdfjs-dist");
    vi.mocked(pdfjs.getDocument).mockReturnValueOnce({
      promise: Promise.reject(new Error("bad pdf")),
    } as never);
    render(
      <PdfBoxSelect
        bytes={new Uint8Array([1])}
        page={1}
        descriptions={DESCRIPTIONS}
        onResolve={vi.fn()}
      />,
    );
    // The object checklist is the fallback; a render failure must not be fatal.
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("bad pdf"),
    );
  });
});
