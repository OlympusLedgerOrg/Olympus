/**
 * Unit tests for the object-level redaction binding pipeline (ADR-0026).
 *
 * The cross-language byte-for-byte pin lives in
 * `redactionBinding.conformance.test.ts`; this file exercises the integration
 * paths that the conformance fixture doesn't — `recomputeRedactionCommitment`
 * over a real synthetic PDF (xref parse → revealed-leaf recompute → masked
 * depth-10 chain fold), the fail-closed guards, and the canonical-blinding
 * validation.
 */
import { describe, it, expect } from "vitest";
import { poseidon2 } from "poseidon-lite";

import { BJJ_L } from "./babyJubjub";
import { extractObjectSpans } from "./pdfObjects";
import {
  MAX_LEAVES,
  objectLeaf,
  recomputeRedactionCommitment,
  verifyRedactionBindingJs,
} from "./redactionBinding";

const ENC = new TextEncoder();

/** Byte-exact port of `pdf_objects.rs::build_pdf` (see pdfObjects.test.ts). */
function buildPdf(bodies: string[]): Uint8Array {
  const parts: number[] = [];
  const push = (s: string) => {
    for (const x of ENC.encode(s)) parts.push(x);
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
  const n = bodies.length + 1;
  push(`xref\n0 ${n}\n`);
  push("0000000000 65535 f \n");
  for (const off of offsets) push(`${String(off).padStart(10, "0")} 00000 n \n`);
  push(`trailer\n<< /Size ${n} /Root 1 0 R >>\n`);
  push(`startxref\n${xrefOff}\n%%EOF\n`);
  return new Uint8Array(parts);
}

/** Independent re-implementation of the masked chain fold, so the assertion
 *  isn't a tautology against the module's own fold loop. */
function foldCommitment(leaves: bigint[], mask: boolean[]): string {
  const revealedCount = BigInt(mask.filter(Boolean).length);
  let acc = revealedCount;
  for (let i = 0; i < MAX_LEAVES; i++) {
    const val = mask[i] ? leaves[i] : 0n;
    acc = poseidon2([poseidon2([3n, acc]), val]); // domain_node(3, acc, val)
  }
  return acc.toString();
}

const SAMPLE = [
  "<< /Type /Catalog /Pages 2 0 R >>",
  "<< /Length 30 >>\nstream\nBT (SECRET) Tj ET\nendstream",
];
const BLINDING = "123456789";

/** Expected commitment for the SAMPLE pdf when object 2 is redacted and
 *  object 1 is revealed under BLINDING — computed independently here. */
function expectedForSample(pdf: Uint8Array): string {
  const spans = extractObjectSpans(pdf);
  const o1 = spans.find((s) => s.objId === 1)!;
  const leaves = new Array<bigint>(MAX_LEAVES).fill(0n);
  const mask = new Array<boolean>(MAX_LEAVES).fill(false);
  leaves[0] = objectLeaf(1, pdf.subarray(o1.byteOffset, o1.byteEnd), BigInt(BLINDING));
  mask[0] = true; // object 1 revealed at position 0; object 2 redacted
  return foldCommitment(leaves, mask);
}

describe("redactionBinding.recomputeRedactionCommitment", () => {
  it("recomputes the commitment from a redacted PDF + bundle", async () => {
    const pdf = buildPdf(SAMPLE);
    const expected = expectedForSample(pdf);
    const got = await recomputeRedactionCommitment(
      pdf,
      [2],
      [{ segmentId: 1, blindingDecimal: BLINDING }],
    );
    expect(got).toBe(expected);
  });

  it("verifyRedactionBindingJs accepts the matching commitment, rejects others", async () => {
    const pdf = buildPdf(SAMPLE);
    const expected = expectedForSample(pdf);
    await expect(
      verifyRedactionBindingJs(pdf, [2], [{ segmentId: 1, blindingDecimal: BLINDING }], `  ${expected}  `),
    ).resolves.toBe(true);
    await expect(
      verifyRedactionBindingJs(pdf, [2], [{ segmentId: 1, blindingDecimal: BLINDING }], "999"),
    ).resolves.toBe(false);
  });

  it("throws when a revealed object has no blinding in the bundle", async () => {
    const pdf = buildPdf(SAMPLE);
    await expect(
      recomputeRedactionCommitment(pdf, [2], []),
    ).rejects.toThrow(/missing a blinding for revealed object 1/);
  });

  it("rejects empty input", async () => {
    await expect(
      recomputeRedactionCommitment(new Uint8Array(0), [], []),
    ).rejects.toThrow(/empty/);
  });

  it("rejects non-canonical blinding decimals", async () => {
    const pdf = buildPdf(SAMPLE);
    for (const bad of ["0x1f", "-5", "007", " 5 ", "", "1.0"]) {
      await expect(
        recomputeRedactionCommitment(pdf, [2], [{ segmentId: 1, blindingDecimal: bad }]),
        `blinding ${JSON.stringify(bad)} must be rejected`,
      ).rejects.toThrow(/canonical non-negative decimal integer/);
    }
  });

  it("rejects an out-of-range blinding (>= BJJ_L)", async () => {
    const pdf = buildPdf(SAMPLE);
    await expect(
      recomputeRedactionCommitment(pdf, [2], [
        { segmentId: 1, blindingDecimal: BJJ_L.toString() },
      ]),
    ).rejects.toThrow(/out of range \[0, BJJ_L\)/);
  });

  it("fails closed (does not truncate) when the PDF exceeds MAX_LEAVES objects", async () => {
    const bodies = Array.from({ length: MAX_LEAVES + 1 }, () => "<< >>");
    const pdf = buildPdf(bodies);
    await expect(
      recomputeRedactionCommitment(pdf, [], []),
    ).rejects.toThrow(/exceeding the 1024-object commitment capacity/);
  });
});
