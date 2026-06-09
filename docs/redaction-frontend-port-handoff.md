# Redaction frontend object-port — UI handoff for Claude Design (ADR-0026)

**Status:** the hooks / API / test layer is ported to the object-level contract
(this branch). The remaining work is the **UI component rewrite**, which is
Claude Design's. **The frontend type-check (`tsc -b`) and `pnpm run build` are
RED until the two components below are reworked** — this is expected and was
agreed; the hook/API/test layer is complete and its own tests pass.

See `docs/redaction-frontend-port-plan.md` for the full contract/UX rationale.

## What's already done (do not redo)

- `src/lib/api.ts` — object contract: `RedactionIssueResponse` now carries
  `redactedObjIds: number[]` + `revealedSegments: {segmentId, blindingDecimal}[]`
  (no more `revealMask` / `revealedChunkHashes`). New `getRedactionManifest()`
  and `ManifestObject` / `RedactionManifestResponse`. `issueRedaction(contentHash,
  redactedObjIds, recipientId, apiKey?)` and `redactDocument(originalBase64,
  redactedObjIds, recipientId, apiKey?)` (dropped `ranges` + `fill`). Removed
  `RedactByteRange`.
- `src/hooks/useRedactionCreate.ts` — rewritten to the object-checklist model.
  New surface:
  - State: `stage` (`idle | loading_manifest | redacting | done | error`),
    `fileName`, `fileSize`, `contentHash`, `manifest: RedactionManifestResponse | null`,
    `selectedIds: number[]`, `recipientId`, `result`, `error`.
  - Actions: `onFile(file)` (hashes bytes → `getRedactionManifest` → populates
    checklist), `toggleId(id)`, `clearSelection()`, `setRecipientId(s)`,
    `redact()`, `downloadRedacted()`, `downloadBundle()`, `reset()`.
  - The chunk-era client self-check (`verifyRedactionBindingJs`) is **dropped** —
    do NOT wire it against object bundles (it always fails). Server proof +
    `/zk/verify` are authoritative until FE-4.
- Deleted dead `/link` UI: `useRedactionLink(.test)`, `RedactionLinkPanel(.test)`
  (the backend route is gone). HomePage never mounted them, so no unmount needed.
- Deleted `src/lib/redactionGeometry.conformance.test.ts` — it pinned the
  removed `computeRevealMask` chunk geometry; the object producer has no
  client-side mask. The shared `redactionGeometry.vectors.json` + the Rust test
  `src-tauri/src/zk/redact.rs::geometry_golden_vectors` are left intact (legacy
  chunk geometry).
- Tests updated to the new contract: `useRedactionCreate.test.tsx` (rewritten,
  passes), `lib/api.test.ts` (object ids + manifest + redact), `HomePage.test.tsx`
  (hook stub shape).

## What Claude Design needs to do (the RED files)

### 1. `src/tabs/RedactTab.tsx`
Rework the producer UI from byte-ranges/text-preview/16-chunk-strip to an
**object checklist**:
- Drop `selectionToByteOffset`, the text `<textarea>` preview, the manual
  start/end range inputs, the FILL input, the 16-chunk strip, and the
  verify-before-send (`bindingValid`) indicator.
- Render `hook.manifest.objects` as a checklist — one row per object
  (`#${segmentId} · ${byteLength} bytes` + checkbox) wired to `hook.toggleId`.
  Show `hook.selectedIds.length` / `hook.manifest.objectCount` hidden.
- Replace the "text / CSV / JSON only; PDF unsupported" copy with PDF-oriented
  copy (object redaction is **for** PDFs; selected objects are zero-filled in
  place so the rest stay byte-identical).
- Result panel: show `result.bundle.redactedObjIds.length / objectCount`
  (was `chunks_hidden /16`).
- A `loading_manifest` stage exists — show a "loading manifest…" affordance.
- REDACT enabled when `hook.manifest && hook.selectedIds.length > 0`.

### 2. `src/components/ProofResultPanel.tsx` — `onGenerateRedactionProof`
The demo button hard-codes a 16-chunk `revealMask = [1×15,0]` and reads
`bundle.revealMask` / `bundle.revealedChunkHashes`. Rework to the object scheme:
- `import { getRedactionManifest } from "../lib/api"`.
- Fetch the manifest, require `objectCount >= 2`, hide one object (e.g. the last:
  `redactedObjIds = [manifest.objects.at(-1).segmentId]`), then
  `issueRedaction(contentHash, redactedObjIds, "1", apiKey)`.
- Export bundle with `redacted_obj_ids` + `revealed_segments` (not
  `reveal_mask` / `revealed_chunk_hashes`).

### 3. Update the two component tests
`RedactTab.test.tsx` and `ProofResultPanel.test.tsx` still build hook stubs /
mock responses with the old chunk fields (`fileText`, `addRange`, `previewMask`,
`revealMask`, …). Rewrite their fixtures to the new hook surface + object
response shape. (Reference fixtures: see `useRedactionCreate.test.tsx` and the
`bundleResponse` helper there.)

## Deferred — FE-4 (separate PR, conformance-sensitive)

The recipient/auditor object-port is **not** in this change:
`useRedactionAudit.ts` still parses `reveal_mask` (object bundles won't parse
yet — clean error, acceptable interim), the Rust `verify_redaction_binding`
Tauri command, and `lib/redactionBinding.ts` (the pinned JS↔Rust conformance
fixture — must change in lockstep with
`src-tauri/src/zk/chunk.rs::js_conformance_fixture_locked` +
`redactionBinding.conformance.test.ts`, emitting a new object-level fixture in
the same commit). Needs TS Baby Jubjub Pedersen.
