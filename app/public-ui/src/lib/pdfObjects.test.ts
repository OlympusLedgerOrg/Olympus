/**
 * Unit tests for the browser-side traditional-xref PDF parser (ADR-0026).
 *
 * Mirrors the synthetic-PDF construction in
 * `src-tauri/src/zk/pdf_objects.rs`'s `build_pdf` test helper so the byte
 * offsets the xref table records are exact, and exercises the same happy /
 * error paths the Rust `object_span` + `parse_xref_section` tests cover.
 */
import { describe, it, expect } from "vitest";
import { extractObjectSpans, PdfParseError } from "./pdfObjects";

const ENC = new TextEncoder();
const DEC = new TextDecoder();

/** Byte-exact port of `pdf_objects.rs::build_pdf`: object `i+1`'s body is
 *  `bodies[i]`, with a correct traditional xref table + trailer + startxref. */
function buildPdf(bodies: string[]): Uint8Array {
  const parts: number[] = [];
  const push = (s: string | Uint8Array) => {
    const b = typeof s === "string" ? ENC.encode(s) : s;
    for (const x of b) parts.push(x);
  };
  push("%PDF-1.4\n");
  const offsets: number[] = [];
  bodies.forEach((body, i) => {
    offsets.push(parts.length);
    push(`${i + 1} 0 obj\n`);
    push(body);
    push("\nendobj\n");
  });
  const xrefOff = parts.length;
  const n = bodies.length + 1; // include free object 0
  push(`xref\n0 ${n}\n`);
  push("0000000000 65535 f \n");
  for (const off of offsets) push(`${String(off).padStart(10, "0")} 00000 n \n`);
  push(`trailer\n<< /Size ${n} /Root 1 0 R >>\n`);
  push(`startxref\n${xrefOff}\n%%EOF\n`);
  return new Uint8Array(parts);
}

const segText = (pdf: Uint8Array, s: { byteOffset: number; byteEnd: number }) =>
  DEC.decode(pdf.subarray(s.byteOffset, s.byteEnd));

describe("pdfObjects.extractObjectSpans", () => {
  it("returns one span per in-use object in ascending obj-id order", () => {
    const pdf = buildPdf([
      "<< /Type /Catalog /Pages 2 0 R >>",
      "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
      "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]);
    const spans = extractObjectSpans(pdf);
    expect(spans.map((s) => s.objId)).toEqual([1, 2, 3]);
    for (const s of spans) {
      const txt = segText(pdf, s);
      expect(txt.endsWith("endobj")).toBe(true);
      expect(txt).toContain(" obj");
      // Header offset points at the `N 0 obj` line.
      expect(txt.startsWith(`${s.objId} 0 obj`)).toBe(true);
    }
  });

  it("skips an `endobj` that appears inside a stream payload", () => {
    const pdf = buildPdf([
      "<< /Length 20 >>\nstream\nhi endobj here\nendstream",
      "<< /Type /Catalog >>",
    ]);
    const spans = extractObjectSpans(pdf);
    const o1 = spans.find((s) => s.objId === 1)!;
    const seg = segText(pdf, o1);
    // The span must extend past the in-stream `endobj` to the real trailer.
    expect(seg.endsWith("endobj")).toBe(true);
    expect(seg).toContain("endstream");
    expect(seg).toContain("hi endobj here");
  });

  it("throws not_traditional_xref for a PDF 1.5+ cross-reference stream", () => {
    // startxref points at an indirect object (an xref *stream*), not `xref`.
    const parts: number[] = [];
    const push = (s: string | Uint8Array) => {
      const b = typeof s === "string" ? ENC.encode(s) : s;
      for (const x of b) parts.push(x);
    };
    push("%PDF-1.5\n");
    const xrefOff = parts.length;
    push("7 0 obj\n<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R >>\nstream\n");
    push(new Uint8Array(16));
    push("\nendstream\nendobj\n");
    push(`startxref\n${xrefOff}\n%%EOF\n`);
    try {
      extractObjectSpans(new Uint8Array(parts));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(PdfParseError);
      expect((e as PdfParseError).kind).toBe("not_traditional_xref");
    }
  });

  it("throws malformed_xref when there is no startxref marker", () => {
    try {
      extractObjectSpans(ENC.encode("%PDF-1.4\nnot a pdf"));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(PdfParseError);
      expect((e as PdfParseError).kind).toBe("malformed_xref");
    }
  });

  it("follows the /Prev chain with newer (first-seen) entries winning", () => {
    // Hand-build a two-section file: an older xref (object 1 → bogus offset)
    // chained via /Prev under a newer xref (object 1 → real offset). The newer
    // section is parsed first, so its offset must win and parse cleanly.
    const parts: number[] = [];
    const push = (s: string) => {
      for (const x of ENC.encode(s)) parts.push(x);
    };
    push("%PDF-1.4\n");
    const obj1Off = parts.length;
    push("1 0 obj\n<< /Type /Catalog >>\nendobj\n");

    // Older section: claims object 1 lives at a wrong offset.
    const oldXref = parts.length;
    push("xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n");
    push("trailer\n<< /Size 2 /Root 1 0 R >>\n");

    // Newer section: correct offset for object 1, /Prev → older section.
    const newXref = parts.length;
    push("xref\n0 2\n0000000000 65535 f \n");
    push(`${String(obj1Off).padStart(10, "0")} 00000 n \n`);
    push(`trailer\n<< /Size 2 /Root 1 0 R /Prev ${oldXref} >>\n`);
    push(`startxref\n${newXref}\n%%EOF\n`);

    const spans = extractObjectSpans(new Uint8Array(parts));
    expect(spans.map((s) => s.objId)).toEqual([1]);
    expect(spans[0].byteOffset).toBe(obj1Off);
    expect(segText(new Uint8Array(parts), spans[0]).endsWith("endobj")).toBe(true);
  });

  it("throws object_out_of_bounds when an xref offset points past EOF", () => {
    const parts: number[] = [];
    const push = (s: string) => {
      for (const x of ENC.encode(s)) parts.push(x);
    };
    push("%PDF-1.4\n");
    push("1 0 obj\n<< >>\nendobj\n");
    const xrefOff = parts.length;
    // Object 1's entry claims an offset far past the end of the file.
    push("xref\n0 2\n0000000000 65535 f \n0000999999 00000 n \n");
    push("trailer\n<< /Size 2 /Root 1 0 R >>\n");
    push(`startxref\n${xrefOff}\n%%EOF\n`);
    try {
      extractObjectSpans(new Uint8Array(parts));
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(PdfParseError);
      expect((e as PdfParseError).kind).toBe("object_out_of_bounds");
      expect((e as PdfParseError).objId).toBe(1);
    }
  });
});

export { buildPdf };
