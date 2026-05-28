# Phase 3 — high-value components coverage

Tracking file for the third phase of the frontend coverage push
(issue [#1079](https://github.com/OlympusLedgerOrg/Olympus/issues/1079)).
Depends on phases 1 (libs+hooks) and 2 (pages+tabs) landing first.

## Coverage target

Bring overall workspace coverage from ~65% (phase-2 floor) → ~85%
(line) by exercising 21 behaviour-bearing components in
`src/components/`. The remaining ~15% gap (animation primitives,
provider plumbing) is closed by phase 4 via the coverage exclude list.

## Files to test

| File | Lines | Test scope |
|---|---|---|
| `InitialSecretsModal.tsx` | 353 | bootstrap one-shot flow + dismiss-gate logic (the manualAck checkbox path we added in #1087) |
| `RecentVerifications.tsx` | TBD | localStorage list render + clear button + cross-tab `storage` event |
| `Layout.tsx` | TBD | nav gating on `hasStoredAdminKey()`, scope chip mount |
| `WhoAmIChip.tsx` | 107 | current-user fetch + idle/error/loaded states |
| `VerdictCard.tsx` | 178 | verdict/status colour mapping, copyable rows |
| `CommitPrompt.tsx` | TBD | API-key paste → normalize → submit → success/error |
| `ScopeBanner.tsx` | TBD | scope label + colour by role |
| `ProofResultPanel.tsx` | TBD | render branches for verified/pending/invalid/unknown |
| `RedactionLinkPanel.tsx` | TBD | render + copy bundle |
| `StartupGate.tsx` | TBD | placeholder/loading/error → ready transitions |
| `DbErrorGate.tsx` | TBD | DB-error overlay render |
| `BootProgress.tsx` | TBD | progress steps render |
| `HashDisplay.tsx` | TBD | hash render + copyable |
| `HashReveal.tsx` | TBD | animation no-op smoke + reveal callback |
| `FileHasher.tsx` | TBD | file-drop → hash via `lib/blake3` (covered in phase 1b) |
| `StartupErrorScreen.tsx` | TBD | error message render + reload button |
| `CopyButton.tsx` | TBD | clipboard write + transient "Copied" state |
| `StatCards.tsx` | TBD | stat numbers render + null/loading states |
| `CommandDeck.tsx` | TBD | command palette render |
| `AnimatedNumber.tsx` | TBD | number-tween prop forwarding (no animation timing) |
| `SkinSelector.tsx` | TBD | skin context read + onChange |

## Mock surface

- `navigator.clipboard.writeText` — stub for `CopyButton`, `HashDisplay`
- `window.__TAURI__` — stub for `InitialSecretsModal`
- `fetch` — stub for `WhoAmIChip`, `StatCards`, `CommitPrompt`
- `localStorage` — direct read/write for `RecentVerifications`, `Layout`

## Threshold

This phase bumps the vitest coverage threshold to `85%` (line) on
`src/components/**` (excluding the phase-4 visual list below).

## Status

- [ ] All 21 components above
- [ ] Coverage threshold bump in `vitest.config.ts`
