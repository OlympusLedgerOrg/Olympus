# Phase 2 — pages + tabs coverage

Tracking file for the second phase of the frontend coverage push
(issue [#1079](https://github.com/OlympusLedgerOrg/Olympus/issues/1079)).
Depends on phase 1 (testing-library + jest-dom wiring) landing first —
this PR is a planning scaffold; the test files arrive in follow-up
commits on this same branch.

## Coverage target

Bring overall workspace coverage from ~25% (phase-1 floor) → ~65%
(line) by exercising the 8 routed pages + 3 tab components.

## Files to test

### Pages (`src/pages/`)

| File | Lines | Test scope |
|---|---|---|
| `HomePage.tsx` | 289 | landing flows, stat cards mount, route gating |
| `IngestPage.tsx` | 458 | the commit-prompt flow we tweaked in #1087 — paste → normalize → submit → result; CSP/Tauri-IPC mock paths |
| `OnboardPage.tsx` | 278 | first-launch + InitialSecretsModal integration |
| `AdminPage.tsx` | 254 | scope gating on `OLYMPUS_ADMIN_KEY` |
| `AdminUsersPage.tsx` | 411 | mint-key, edit-scope, promote-role; covered in backend by #1086 — frontend half here |
| `CredentialsPage.tsx` | 390 | SBT issue / list / revoke / verify UI |
| `DatasetPage.tsx` | 418 | dataset lookup |
| `RecordDetailPage.tsx` | 262 | proof-bundle render, anchor links |

### Tabs (`src/tabs/`)

| File | Lines | Test scope |
|---|---|---|
| `HashTab.tsx` | 146 | file → hash → display flow |
| `RedactionTab.tsx` | 378 | redaction binding UI (uses `lib/redactionBinding.ts`) |
| `AuditProofTab.tsx` | 340 | proof bundle paste + verify |

## Mock surface

All pages reach the Axum server via `lib/api.ts`'s `apiFetch<T>`
wrapper (`api.ts:110`), which calls the global `fetch` directly —
**not** `safeJsonFetch` (that helper is only used by the OnboardPage
auth-register path elsewhere in the tree). Tests should stub
`globalThis.fetch`, not the wrapper.

`InitialSecretsModal` reads Tauri IPC via the `window.__TAURI__`
runtime injection (`InitialSecretsModal.tsx:43-49`):

```ts
const tauri = (window as unknown as {
  __TAURI__?: { core?: { invoke: (cmd: string) => Promise<unknown> } };
}).__TAURI__;
if (!tauri?.core?.invoke) return;
```

Tests should stub `window.__TAURI__.core.invoke` to return the
`InitialSecrets` shape; the existing fallback path (`return` when the
injection is absent, line 46) exercises the plain-browser dev-server
case.

## Threshold

This phase bumps the vitest coverage threshold to `60%` (line) on
`src/pages/**` and `src/tabs/**`. Lower bars stay until phase 3.

## Status

- [ ] HomePage
- [ ] IngestPage
- [ ] OnboardPage
- [ ] AdminPage
- [ ] AdminUsersPage
- [ ] CredentialsPage
- [ ] DatasetPage
- [ ] RecordDetailPage
- [ ] HashTab
- [ ] RedactionTab
- [ ] AuditProofTab
- [ ] Coverage threshold bump in `vitest.config.ts`
