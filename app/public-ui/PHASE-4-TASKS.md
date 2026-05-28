# Phase 4 — visual-only excludes + coverage CI gate

Tracking file for the final phase of the frontend coverage push
(issue [#1079](https://github.com/OlympusLedgerOrg/Olympus/issues/1079)).
Depends on phases 1–3 landing first.

## What this phase does

1. Excludes pure-visual components from the coverage denominator —
   testing animation timing and framer-motion props for coverage % is
   busywork that buys no correctness signal.
2. Lifts the workspace coverage threshold to **85% line** in
   `vitest.config.ts`, mirroring the threshold the audit baseline
   tracks (issue #1079, quality gap).
3. Wires the threshold into CI so `pnpm coverage` fails the
   `frontend coverage (vitest)` job on regression rather than just
   uploading the artifact.

## Visual-only exclude list

These files render motion / chrome / skin theming only — no behaviour
that a unit test could meaningfully assert. Excluded from the
coverage denominator (NOT deleted, NOT excluded from the build):

| File | Why excluded |
|---|---|
| `components/GlyphRain.tsx` | matrix-rain skin chrome |
| `components/CrtOverlay.tsx` | CRT scanline overlay |
| `components/SkylineBackdrop.tsx` | skyline parallax |
| `components/TiltContainer.tsx` | mouse-tilt 3D wrapper |
| `components/LoadingSplash.tsx` | splash bitmap |
| `components/GlitchMentorPopups.tsx` | mascot popups |
| `skins/SkinProvider.tsx` | React-context provider plumbing |
| `skins/SkinContext.ts` | context type-only |
| `skins/registry.ts` | static skin manifest |
| `skins/types.ts` | type-only |
| `lib/audio.ts` | audio cue playback (Audio API mocking is unsound for assertion) |
| `App.tsx` | router root — exercised transitively by every page test |

## `vitest.config.ts` patch (sketch)

```ts
coverage: {
  // ... existing fields
  exclude: [
    // ... existing
    'src/components/{GlyphRain,CrtOverlay,SkylineBackdrop,TiltContainer,LoadingSplash,GlitchMentorPopups}.tsx',
    'src/skins/**',
    'src/lib/audio.ts',
    'src/App.tsx',
  ],
  thresholds: {
    lines: 85,
    functions: 85,
    branches: 80,
    statements: 85,
  },
},
```

## CI wiring

`.github/workflows/coverage.yml` `frontend-coverage` job already runs
`pnpm coverage`; the threshold above turns regression into a failed
job (vitest exits non-zero when thresholds aren't met). No new step
needed.

## Status

- [ ] Edit `vitest.config.ts` exclude list
- [ ] Edit `vitest.config.ts` thresholds
- [ ] Verify `pnpm coverage` exits 0 against current main+phases-1-3 tree
- [ ] Verify removing any phase-3 test makes the job fail (regression sentinel)
- [ ] Update issue #1079 quality-gap checkbox
