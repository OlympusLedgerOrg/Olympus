# Redaction frontend object-port — execution plan (ADR-0026)

**Status:** backend complete & merged; frontend pending (needs a working JS
toolchain — `pnpm install` + `tsc` + `vitest`, which did not install in the
web-session container).

## Context — what already shipped

The object-level redaction **producer backend** is fully merged (ADR-0026):

| PR | What |
|----|------|
| #1228 | ADR-0026 design + multi-format object scheme + ingest migration |
| #1229 | Phases 1–4b: hiding leaf (`olympus_crypto::redaction`), `zk/pdf_objects.rs` (extract/apply/witness_inputs), SSMF vectors, ingest object-commitment, `redaction_segment_manifests` (migration 0047) |
| #1230 | Producer API rewire (`/redaction/issue`+`/redaction/redact` → object ids), `GET /redaction/manifest/{content_hash}`, manifest-bounds hardening, producer-path prover regression test; **removed `/redaction/link`** |

The cryptographic feature is done and validated end-to-end in CI. What remains
is **frontend-only**: move the producer/auditor UI from the retired chunk/byte-
range model to the object scheme, and remove the dead `/redaction/link` UI.

This is a **from-scratch UI redesign**, not a mechanical port: selection changes
from *byte ranges in text* to *a checklist of PDF objects*, and the format
constraint **inverts** (chunk redaction was text-only; object redaction is for
PDFs).

## Validation (run in an environment where deps install)

```bash
cd app/public-ui
pnpm install
pnpm exec tsc -b --noEmit     # type-check (FE-1..FE-3 must all land for this to pass)
pnpm test:run                 # vitest
pnpm run build                # tsc -b && vite build (matches CI "frontend type-check + build")
```

CI jobs that gate this: **frontend type-check + build**, **frontend coverage
(vitest)**. The Rust side of FE-4 is gated by **tauri desktop unit tests** +
the JS↔Rust conformance test.

## The contract (FE-1 — `app/public-ui/src/lib/api.ts`)

Replace the chunk redaction section (was lines ~364–480) with the object
contract. Backend wire shape is `#[serde(rename_all = "camelCase")]`.

```ts
export interface RevealedSegment {
  segmentId: number;        // indirect-object id
  blindingDecimal: string;  // decimal BJJ subgroup scalar b
}

export interface RedactionIssueResponse {
  circuit: ZkCircuit;
  contentHash: string;
  originalRoot: string;
  proofJson: unknown;
  publicSignals: string[];
  redactedObjIds: number[];          // was revealMask
  revealedSegments: RevealedSegment[]; // was revealedChunkHashes
  signatureHex: string;
}

// POST /redaction/issue  — body { content_hash, redacted_obj_ids, recipient_id }
export function issueRedaction(contentHash, redactedObjIds: number[], recipientId, apiKey?)

// GET /redaction/manifest/{contentHash}  (NEW — already live on the backend)
export interface ManifestObject { segmentId: number; byteLength: number }
export interface RedactionManifestResponse {
  contentHash: string; originalRoot: string; objectCount: number; objects: ManifestObject[];
}
export function getRedactionManifest(contentHash, apiKey?)

// POST /redaction/redact  — body { original_base64, redacted_obj_ids, recipient_id }
//   (drop `ranges` + `fill`; response unchanged shape: { redactedBase64, bundle })
export function redactDocument(originalBase64, redactedObjIds: number[], recipientId, apiKey?)
```

Remove: `RedactByteRange`, `fill`, `revealMask`, `revealedChunkHashes`. There is
no `linkRedaction` in `api.ts` (the `/link` UI called `apiFetch` directly).

## UX model (FE-2 — producer)

Flow: **load committed PDF → fetch its object manifest → check the objects to
hide → redact → download redacted PDF + bundle.**

- `useRedactionCreate` (`hooks/useRedactionCreate.ts`): drop byte-range state
  (`ranges`/`addRange`/`removeRange`/`computeRevealMask`/`computeChunkStatus`/
  `populatedChunks`/`fill`) and `selectionToByteOffset` usage. New state:
  `manifest: RedactionManifestResponse | null`, `selectedIds: Set<number>`.
  - `onFile`: read bytes, BLAKE3 the bytes client-side **only to display** the
    content hash, then `getRedactionManifest(contentHash)` to populate the
    checklist. (The hash for the GET should match the server's BLAKE3 — confirm
    the existing `hashFile`/`blake3` lib matches `blake3::hash(bytes)`; the
    auditor already relies on this.)
  - `redact()`: validate `selectedIds` non-empty and not all objects, then
    `redactDocument(base64, [...selectedIds], recipientId)`.
  - **Verify-before-send:** the chunk path recomputed the commitment via
    `verifyRedactionBindingJs`. For the object scheme this needs the FE-4
    object-level recompute; until FE-4, **drop the client self-check** (set
    `bindingValid` unused / remove) — the server proof + `/zk/verify` are
    authoritative. Do NOT leave the chunk recompute wired (it would always fail
    for object docs).
- `RedactTab` (`tabs/RedactTab.tsx`): replace the text preview + select-to-range
  + manual range entry + 16-chunk strip with an **object checklist**
  (`manifest.objects` → row per object: `#id · N bytes` + checkbox). Replace the
  "text/CSV/JSON only; PDF unsupported" copy with PDF-oriented copy. Result panel:
  show `redactedObjIds.length` hidden / `objectCount` instead of `chunks_hidden /16`.
- `ProofResultPanel` (`components/ProofResultPanel.tsx`, ~lines 242–256): the
  hard-coded demo `revealMask = [1×15, 0]` + `reveal_mask`/`revealed_chunk_hashes`
  fields must move to `redactedObjIds` / `revealedSegments`. Re-check what this
  panel actually demonstrates and update to issue with `redacted_obj_ids`.

## Remove the `/link` UI (FE-3)

Delete `hooks/useRedactionLink.ts` (+ `.test.tsx`),
`components/RedactionLinkPanel.tsx` (+ `.test.tsx`), and unmount from
`pages/HomePage.tsx` (+ fix `HomePage.test.tsx`). `/redaction/link` no longer
exists on the backend.

Tests to update for the new types (they hard-code `revealMask`/
`revealedChunkHashes`): `useRedactionCreate.test.tsx`, `RedactTab.test.tsx`,
`ProofResultPanel.test.tsx`.

## Auditor object-port (FE-4 — conformance-sensitive)

The recipient/auditor verifies a redacted artifact binds to the proof's
`redactedCommitment` (publicSignals[2]) by recomputing revealed objects' hiding
leaves and folding. Two recompute paths:

1. **Rust Tauri command `verify_redaction_binding`** (desktop auditor) — currently
   re-chunks the file. Rework to: re-extract objects from the uploaded artifact
   (or use the bundle's `revealedSegments` blindings), recompute each revealed
   leaf `Poseidon((content·G + b·H).x, .y)` via `olympus_crypto::redaction`, fold
   with the reveal mask, compare to `publicSignals[2]`. This is sanctioned Rust
   crypto (BJJ permissive lib).
2. **`lib/redactionBinding.ts`** (Tor public-web auditor, no IPC) — the JS mirror.
   This is a **pinned JS↔Rust conformance fixture**: its header requires it to
   change in lockstep with `src-tauri/src/zk/chunk.rs::js_conformance_fixture_locked`
   and `redactionBinding.conformance.test.ts`. The object version needs TS Baby
   Jubjub Pedersen (mirror `verifiers/javascript`'s hiding-leaf code if #1229
   added it there; otherwise port from `crates/babyjubjub-permissive`). Emit a new
   Rust fixture (object-level) and pin both sides in the same commit.

`useRedactionAudit.ts`: its `parseRedactionBundle` reads `reveal_mask`; for object
bundles it should read `redactedObjIds` + `revealedSegments` and call the
object-level binding check. Until FE-4 lands, object bundles will fail to parse
(clean error, not a wrong result) — acceptable interim, but message it.

## Gotchas

- **axum 0.8 route syntax**: backend routes use `{param}`, not `:param` (caught
  in #1230 CI). N/A to frontend but noted for any new backend route in FE-4.
- **PDF-vs-text inversion**: all "text only / binary unsupported" copy is now
  backwards — object redaction is *for* PDFs.
- **Don't ship the chunk recompute against object bundles** — it always fails;
  drop or gate it rather than leave it mis-verifying.
- **Frontend does no security crypto** except the sanctioned auditor re-verify
  (`redactionBinding.ts`, analogous to `verifiers/javascript`). Keep signing/key
  handling server-side.
