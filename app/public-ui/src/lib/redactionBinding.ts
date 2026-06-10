/**
 * ⚠️ LEGACY — deprecated 16-chunk raw-byte redaction binding.
 *
 * This implements the OLD chunk-based `redaction_validity` scheme (16 leaves /
 * depth-4 fold, DOMAIN_LEAF=1, DOMAIN_REDACTION=3). Per ADR-0025/0026 the
 * production scheme is now PDF object-level commitment (1024 leaves / depth-10),
 * driven by object ids + the manifest endpoint (`issueRedaction` /
 * `getRedactionManifest` in api.ts) — NOT this module. It is retained ONLY to
 * verify pre-ADR-0025 sealed records.
 *
 * Do not feed object-scheme bundles here: the functions below hard-require a
 * `MAX_LEAVES` (16) entry `reveal_mask` and throw on any other shape, so an
 * object-scheme bundle (1024-wide mask) is rejected rather than silently
 * mis-bound — but new code should call the object-level path directly and
 * never reach this file.
 *
 * Browser-side file→commitment binding for `redaction_validity` audits.
 *
 * **ADR-0026 object-level redaction.** Mirrors
 * `src-tauri/src/zk/pdf_objects.rs::extract_objects` +
 * `src-tauri/src/zk/poseidon.rs::redaction_commitment` and the shared
 * `olympus_crypto::redaction::redaction_leaf` (hiding leaf: Pedersen
 * commitment on Baby Jubjub then Poseidon over its coords) byte-for-byte,
 * so a remote auditor reading the read-only Tor public_router (where Tauri
 * IPC isn't available) can still bind a dropped redacted file to the
 * verified ZK proof.
 *
 * If you change ANY constant or step here, you MUST also update
 * `src-tauri/src/zk/pdf_objects.rs::js_conformance_fixture_locked` and the
 * Vitest test `redactionBinding.conformance.test.ts` in the same commit.
 * Drift between desktop and web auditors would silently invalidate every
 * redaction audit.
 *
 * Pipeline (exact mirror of the Rust path):
 *
 *   1. extractObjectSpans(pdfBytes) — parse the trailing `startxref`-anchored
 *      traditional xref table + `/Prev` chain, slice each in-use indirect
 *      object span by its `obj`/`endobj` keywords. PDF 1.5+ cross-reference
 *      streams throw `PdfParseError("not_traditional_xref")`.
 *
 *   2. objectLeaf(objId, objBytes, blinding) — for revealed objects only:
 *        content = bytesBE(BLAKE3_XOF("OLY:REDACTION:OBJ:V1"
 *                  || lp(objId_be) || objBytes, 64 bytes)) mod BJJ_L
 *        C       = content·G + blinding·H        (Pedersen on Baby Jubjub)
 *        leaf    = Poseidon(C.x, C.y)            (hiding — ADR-0026)
 *      Redacted positions contribute 0 to the commitment chain (revealMask=0
 *      zeros them out) so the auditor does NOT need their blindings.
 *
 *   3. redactedCommitment over a padded 1024-leaf array:
 *        acc = revealedCount
 *        for i in 0..MAX_LEAVES:
 *          val = mask[i] ? leaves[i] : 0n
 *          acc = domainNode(3, acc, val)
 *      where domainNode(d, l, r) = Poseidon(Poseidon(d, l), r).
 *      Compare decimal string to publicSignals[2].
 */
import { blake3 } from "@noble/hashes/blake3.js";
import { poseidon2 } from "poseidon-lite";

import {
  BJJ_L,
  bytesBEToBigInt,
  pedersenCommit,
  type BjjPoint,
} from "./babyJubjub";
import { extractObjectSpans } from "./pdfObjects";

/** ADR-0026 object-level circuit geometry. */
export const MAX_LEAVES = 1024;

/** Domain tag for the commitment chain (matches Rust `domain_node(3, …)`). */
const DOMAIN_REDACTION = 3n;

/** Object-leaf hashing domain (`olympus_crypto::redaction::REDACTION_OBJ_PREFIX`). */
const OBJ_DOMAIN = new TextEncoder().encode("OLY:REDACTION:OBJ:V1");

/**
 * One entry of a bundle's `revealedSegments` array — `segmentId` is the
 * indirect object number, `blindingDecimal` is the canonical decimal scalar
 * the issuer used for `r` in `C = m·G + r·H`.
 */
export interface RevealedSegment {
  segmentId: number;
  blindingDecimal: string;
}

function lpU32(buf: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + buf.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, buf.length, false); // big-endian
  out.set(buf, 4);
  return out;
}

function objIdBE(id: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, id >>> 0, false);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Hiding object leaf (ADR-0026): `Poseidon(C.x, C.y)` where
 * `C = content·G + blinding·H` and `content` is a 64-byte BLAKE3-XOF over
 * `("OLY:REDACTION:OBJ:V1" || lp(objId_be) || objBytes)` reduced mod the
 * Baby Jubjub subgroup order `BJJ_L`.
 */
export function objectLeaf(
  objId: number,
  objBytes: Uint8Array,
  blinding: bigint,
): bigint {
  const input = concatBytes(OBJ_DOMAIN, lpU32(objIdBE(objId)), objBytes);
  const wide = blake3(input, { dkLen: 64 });
  const content = bytesBEToBigInt(wide) % BJJ_L;
  const C: BjjPoint = pedersenCommit(content, blinding);
  return poseidon2([C.x, C.y]);
}

/**
 * `domain_node(3, left, right)` = `poseidon2(poseidon2(3, left), right)`.
 * Same construction the Rust auditor + circuit use for the chain.
 */
function domainNode3(left: bigint, right: bigint): bigint {
  const inner = poseidon2([DOMAIN_REDACTION, left]);
  return poseidon2([inner, right]);
}

/**
 * Recompute `redactedCommitment` from the redacted PDF bytes + bundle, return
 * the decimal string of the BN254 field element ready for direct `===`
 * comparison with `publicSignals[2]` of a `redaction_validity` bundle.
 *
 * @param pdfBytes Raw bytes of the dropped redacted PDF file (post-redaction —
 *                 redacted objects' content bytes are NUL-filled but their
 *                 framing survives).
 * @param redactedObjIds Bundle's list of redacted object ids.
 * @param revealedSegments Bundle's per-revealed-object `{segmentId,
 *                         blindingDecimal}` entries.
 */
export async function recomputeRedactionCommitment(
  pdfBytes: Uint8Array,
  redactedObjIds: number[],
  revealedSegments: RevealedSegment[],
): Promise<string> {
  if (pdfBytes.length === 0) {
    throw new Error("PDF bytes are empty");
  }

  // 1. Parse the (post-redaction) PDF — its object framing is preserved by
  //    construction, so the obj-id-ascending span order matches the original
  //    file's, which is the order the witness folded over.
  const spans = extractObjectSpans(pdfBytes);
  if (spans.length === 0) {
    throw new Error("PDF has no in-use indirect objects");
  }
  if (spans.length > MAX_LEAVES) {
    // Rust silently truncates to MAX_OBJECTS with a tracing::warn, so the
    // bundle was minted over the first MAX_LEAVES objects. The auditor
    // mirrors that bound rather than failing outright.
    spans.length = MAX_LEAVES;
  }

  // 2. Build the position-aligned reveal mask. Redacted positions contribute 0
  //    to the chain regardless of their actual leaf, so we never need to
  //    recompute redacted leaves (and don't carry their blindings).
  const redactedSet = new Set<number>(redactedObjIds);
  const blindingById = new Map<number, bigint>();
  for (const s of revealedSegments) {
    blindingById.set(s.segmentId, BigInt(s.blindingDecimal));
  }

  const leaves: bigint[] = new Array(MAX_LEAVES).fill(0n);
  const mask: boolean[] = new Array(MAX_LEAVES).fill(false);
  for (let i = 0; i < spans.length; i++) {
    const s = spans[i];
    if (redactedSet.has(s.objId)) {
      // Redacted slot: mask = false, leaf = 0 (not folded in either way).
      continue;
    }
    const blinding = blindingById.get(s.objId);
    if (blinding === undefined) {
      throw new Error(
        `revealedSegments is missing a blinding for revealed object ${s.objId}`,
      );
    }
    const bytes = pdfBytes.subarray(s.byteOffset, s.byteEnd);
    leaves[i] = objectLeaf(s.objId, bytes, blinding);
    mask[i] = true;
  }

  // 3. Fold the chain over ALL MAX_LEAVES padded slots (zero-leaves at the
  //    tail, mask=0 at every padding slot).
  let revealedCount = 0n;
  for (let i = 0; i < MAX_LEAVES; i++) if (mask[i]) revealedCount++;

  let acc = revealedCount;
  for (let i = 0; i < MAX_LEAVES; i++) {
    const val = mask[i] ? leaves[i] : 0n;
    acc = domainNode3(acc, val);
  }
  return acc.toString();
}

/**
 * High-level: returns `true` iff re-deriving the commitment from the dropped
 * file matches the bundle's expected value. Equal-length decimal strings on
 * both sides (BN254 scalars), so `===` is fine.
 */
export async function verifyRedactionBindingJs(
  pdfBytes: Uint8Array,
  redactedObjIds: number[],
  revealedSegments: RevealedSegment[],
  expectedCommitmentDec: string,
): Promise<boolean> {
  const computed = await recomputeRedactionCommitment(
    pdfBytes,
    redactedObjIds,
    revealedSegments,
  );
  return computed === expectedCommitmentDec.trim();
}
