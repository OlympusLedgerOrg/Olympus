# Kickoff prompt — redaction frontend object-port

Paste the block below into a fresh Claude session **in an environment with a
working JS toolchain** (`pnpm install` + `tsc` + `vitest` must run). It executes
the plan in [`redaction-frontend-port-plan.md`](./redaction-frontend-port-plan.md).

---

```
You are working in the Olympus repo (OlympusLedgerOrg/Olympus), a Rust + Tauri 2
desktop app with a React/TypeScript frontend in app/public-ui/. Follow CLAUDE.md
and the olympus-dev-standards skill.

## Task
Execute the ADR-0026 redaction frontend object-level port. The producer BACKEND
is already complete and merged (PRs #1228/#1229/#1230); only the frontend remains.
A full execution plan is committed at docs/redaction-frontend-port-plan.md (branch
claude/redaction-frontend-objects, draft PR #1231) — READ IT FIRST; it is the
source of truth for the contract, file-by-file changes, UX, and conformance
constraints. This prompt summarizes; the doc has the detail.

## Why a fresh environment
This work was paused in a web-session container because the JS toolchain would not
install there (pnpm/npm stalled), so tsc/vitest couldn't run locally. You MUST be
able to run, locally and green, BEFORE every push:
    cd app/public-ui
    pnpm install
    pnpm exec tsc -b --noEmit      # type-check
    pnpm test:run                  # vitest
    pnpm run build                 # tsc -b && vite build  (mirrors CI)
If pnpm install does not complete in your environment, STOP and report — do not
build a large TS redesign blind.

## What changed on the backend (the contract you're targeting)
- /redaction/issue and /redaction/redact now select indirect PDF OBJECTS by id
  (redacted_obj_ids: number[]), not a 16-chunk reveal_mask.
- Response carries revealedSegments [{segmentId, blindingDecimal}] (was
  revealedChunkHashes) and redactedObjIds (was revealMask).
- NEW: GET /redaction/manifest/{content_hash} → {contentHash, originalRoot,
  objectCount, objects:[{segmentId, byteLength}]} — drives an object checklist.
- /redaction/link was REMOVED.
- Object redaction is FOR PDFs (binary). The old chunk path was text-only — that
  constraint inverts.

## Decomposition (land FE-1..FE-3 together so tsc passes; FE-4 may follow)
- FE-1  app/public-ui/src/lib/api.ts: replace the redaction section with the
        object contract (RedactionIssueResponse w/ redactedObjIds + revealedSegments;
        issueRedaction(contentHash, redactedObjIds, recipientId, apiKey?);
        getRedactionManifest(contentHash, apiKey?); redactDocument(originalBase64,
        redactedObjIds, recipientId, apiKey?)). Remove revealMask,
        revealedChunkHashes, RedactByteRange, fill. Exact shape is in the plan doc.
- FE-2  Producer UI redesign: useRedactionCreate + RedactTab + ProofResultPanel.
        Replace byte-range/text-selection/16-chunk-strip with an object checklist
        fetched via getRedactionManifest. Update copy from "text only" to
        PDF-oriented. DROP the chunk-era client self-check (verifyRedactionBindingJs)
        — do NOT leave it wired against object bundles (it would always fail);
        the server proof + /zk/verify are authoritative until FE-4.
- FE-3  Remove the /redaction/link UI: delete useRedactionLink(.test),
        RedactionLinkPanel(.test), unmount from pages/HomePage.tsx (fix its test).
        Update the chunk-field-referencing tests (useRedactionCreate.test,
        RedactTab.test, ProofResultPanel.test).
- FE-4  (conformance-sensitive; can be a separate PR) Auditor object-port:
        the Rust verify_redaction_binding Tauri command + lib/redactionBinding.ts.
        redactionBinding.ts is a PINNED JS<->Rust conformance fixture — it must change
        in lockstep with src-tauri/src/zk/chunk.rs::js_conformance_fixture_locked and
        redactionBinding.conformance.test.ts, emitting a new object-level fixture and
        pinning both sides in the SAME commit. Needs TS Baby Jubjub Pedersen (mirror
        verifiers/javascript / crates/babyjubjub-permissive). useRedactionAudit must
        parse object bundles (redactedObjIds/revealedSegments).

## Guardrails
- Frontend does NO security-sensitive crypto except the sanctioned auditor
  re-verify (redactionBinding.ts, analogous to verifiers/javascript). Signing/key
  handling stays server-side.
- New backend routes (FE-4) use axum 0.8 {param} syntax, not :param.
- Match surrounding code style (the components use inline styles + a skin context).

## Workflow
- Develop on branch claude/redaction-frontend-objects (continues PR #1231; the
  plan doc is already there). Commit FE-1..FE-3 as focused commits, each locally
  tsc+vitest+build green. Push, then keep PR #1231 and update its body to reflect
  the implemented work. Do FE-4 as a follow-up commit/PR.
- Commit messages: conventional, end with the session link line per CLAUDE.md.
- After pushing, ensure the draft PR is current; ask before merging.
```
