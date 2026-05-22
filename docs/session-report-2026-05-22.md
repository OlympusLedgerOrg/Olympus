# Olympus session report — 2026-05-22

## What landed (merged to main today)

| PR | Title | Notes |
|---|---|---|
| #934 | arkworks 0.5 → 0.6 + vendor light-poseidon | RUSTSEC-2025-0055 + 3 others cleared |
| #935 | `prove` scope mintable | one-line whitelist addition |
| #936 | v1 production-readiness — proofs_dir, placeholders, migrations, setup_circuits.sh wiring, bundle.resources, v0.9 version bump | `OLYMPUS_ENV=production` exit-2 gate |
| #937 | RFC 3161 + Sigstore Rekor + OpenTimestamps anchoring | `/anchors` routes; `docs/court-evidence.md` packet |
| #938 | `start.sh` + WSL perf workarounds + Matrix-rain kill switch | webkit2gtk env flags for WSLg |
| #939 | in-app admin Users page | mint keys, edit scopes, promote roles via `/admin/users/*` |
| #940 | one-shot bootstrap-keys modal | `take_initial_secrets` IPC; surfaces API key + BJJ key on first launch |
| #941 | UX perf batch 1 (design items 1-6) | SkylineBackdrop rAF + drop-shadow, GlitchMentor reduced-motion, typed `ApiError` + ScopeBanner, drag-drop hint, BootProgress overlay |
| #944 | TIMESTAMPTZ chrono fix | one-file admin_users.rs fix caught during verify |

## Still open / in flight at session end

| PR | Title | State |
|---|---|---|
| **#942** native Olympus SBTs | issue/list/revoke/verify routes + `CredentialsPage.tsx` + BJJ signature columns (migration 0027) | **frontend TS fix pushed; CI re-running** |
| **#943** UX batch 2 (design 7-12) | native file picker, modal copy-gate, prod startup screen, WhoAmI chip, Skyline cut, BootTicker reduced-motion | **frontend TS fix pushed; CI re-running** |
| **#945** unified BJJ ↔ API keys | derives `api_key = "oly_" + hex(BLAKE3("OLY:APIKEY:V1" || bjj_priv))`; migration 0028 adds `bjj_pubkey_x/y` to `api_keys` | CI was in progress when session ended |

All three need a check on CI status, then mark ready + merge.

## Bugs caught during this session's verify run

1. **TIMESTAMPTZ decode mismatch** in `admin_users.rs` `UserKeyRow` — `chrono::NaiveDateTime` vs schema's `TIMESTAMPTZ`. Fixed in #944.
2. **Frontend type errors on #942 + #943** — both referenced the `ApiError` class added in #941; branched before that merged. Fixed by inlining tiny helpers (`errMsg`, `errStatus`).
3. **External DB migrations runner skipped sqlx tracking** — verify showed "type agency_level already exists" when sqlx tried to replay migrations on a DB that had been seeded out-of-band. Workaround in the verify run: `DROP DATABASE / CREATE DATABASE`. Not yet patched in code; long-term fix is teaching the bootstrap to detect "schema already exists, populate `_sqlx_migrations`" or to use a transactional CREATE-IF-NOT-EXISTS shape in 0001.

## Design directions captured (Antman83 surfaced these during the session)

These are **not implemented** yet. They're the next major workstream.

### 1. SBT-driven scope resolution
Goal: scopes come from the SBTs a user holds, not from the static `api_keys.scopes` column.

Wire pieces now in place:
- `api_keys.bjj_pubkey_x/y` (PR #945) → tells the server which BJJ identity owns an api_key
- `key_credentials.holder_key` + `key_credentials.issued_signature_*` (PR #942) → signed list of capabilities a BJJ identity holds

Missing piece: a middleware that, given an authenticated `api_key`,
1. looks up its `bjj_pubkey`
2. queries `key_credentials WHERE holder_key = bjj:<x>:<y> AND revoked_at IS NULL`
3. maps credential_type → set of granted scopes (table-driven mapping)
4. returns the union as effective scopes
5. compares against the route's required scope

Suggested mapping (configurable):
```
press_credential   → read, verify, ingest, commit
foia_requester     → read, verify, ingest
court_observer     → read, verify
verifier_only      → read, verify
authority_sbt      → admin, prove, ingest, commit, write, read, verify
```

### 2. Burn-on-grant lifecycle
Goal: when an admin grants someone a capability, the *request SBT* that authorized the grant gets revoked atomically.

Workflow:
1. User holds `request:commit_access` SBT (or similar request-shaped credential).
2. Admin sees pending requests at `/credentials?type=request:*`.
3. Admin calls `POST /credentials/{request_id}/grant` which atomically:
   - Issues a new SBT for the requested capability (e.g. `press_credential`)
   - Revokes the request SBT (writes `revoked_at` + `revoked_signature_*`)
4. Resolver picks up the new SBT on the next request; old one is signed-revoked.

This is roughly one new endpoint + a transaction in `credentials.rs`. ~150 LOC.

### 3. "All can sign in & verify"
Implementation note: the current scope hierarchy already permits this — `/zk/verify` accepts `verify` / `read` / `admin`, `/credentials` GET routes accept the same set. What's missing is registering non-admin users *at all* (the only registered user today is `system-bootstrap`). Need a self-registration flow OR an admin-mints-then-shares pattern. The admin Users page (#939) already supports the latter.

## Verify-run state (not committed; lives in `/tmp/olympus-run/`)

- External postgres on `127.0.0.1:5434` (data dir `/tmp/pgdata`, run by `postgres` system user)
- DB name: `olympus_dev`
- Last bootstrap printed:
  - `system API key: oly_f6641e281527427f82a5da96f05b2365`
  - `OLYMPUS_BJJ_AUTHORITY_KEY=2de7e0fba1026a5d5fe740cc54d37e9f4fb9667cc5d0464ae472e391357f8eb1`
  - `OLYMPUS_ADMIN_KEY=olympus_admin_test_1779474888`
- Detached launcher at `/tmp/olympus-run/launch.sh`

Verify results captured:
- ✅ Steps 1-2: health + bootstrap
- ✅ Step 3: GET /admin/users 401 / 401-wrong-key (auth gate works)
- ❌ Step 3: GET /admin/users 500 with valid key — caught the chrono bug, now fixed in #944
- ✅ Step 4: mint key via `/admin/users/{id}/keys` (scopes: read, verify, prove)
- ✅ Step 4b: minted key successfully calls `/zk/verify` (scope dispatch correct)
- ✅ Step 8: GET /anchors returns `{anchors: []}`
- ✅ Step 9: `take_initial_secrets`, `get_startup_error`, `open_file_dialog` all in `generate_handler!`
- ⏭ Steps 5-7 skipped: `/credentials` routes are on #942, not yet merged

## OTF grant context (relevant to v1.0 planning)

User shared their OTF Internet Freedom Fund #22165 application (concept note, not yet reviewed):
- $25,000 / 3-5 months
- Focus: journalists, FOIA, civil society — verify document existence + non-existence + redaction validity
- Activities map cleanly to what's already shipped (especially the court-evidence packet in #937)
- User explicitly said "they haven't even looked at it yet" — don't over-invest in grant-aligned docs polish

## Suggested next session, in order

1. **Drain the open PRs** — check #942, #943, #945 CI; mark ready + merge.
2. **Schema cleanup migration** — `_sqlx_migrations` reconciliation or `CREATE IF NOT EXISTS` rewrite of migration 0001 so external DB bootstrap doesn't trip on pre-seeded schemas.
3. **SBT-driven scope resolver** — biggest open architectural piece. Concrete plan:
   - New table `credential_scope_grants` or hardcoded `match` in middleware
   - Modify `AuthenticatedKey` extractor to call a `resolve_effective_scopes(api_key) -> Vec<String>` that joins `api_keys` → `bjj_pubkey` → `key_credentials`
   - Cache per-request inside `AuthenticatedKey`
   - Keep the legacy `api_keys.scopes` column as a fallback for pre-resolver rows (system-bootstrap especially)
4. **Burn-on-grant** flow once the resolver is in.
5. **Self-registration** for non-admin users (or `/auth/whoami` route — the WhoAmIChip already calls it and degrades gracefully).
6. **CredentialsPage rebase onto main** to drop the `errMsg` shim in favor of typed `ApiError`.
7. **Verify-run integration test** — codify the curl-stepped smoke as a Rust integration test against a real Postgres in CI so the chrono bug class is caught next time.

## Files / paths worth remembering

- `src-tauri/src/api/credentials.rs` — SBT routes (#942)
- `src-tauri/src/api/admin_users.rs` — admin Users routes (#939); has the chrono fix from #944
- `src-tauri/src/api/middleware/auth.rs` — `derive_api_key_from_bjj` (#945); future home of scope resolver
- `src-tauri/src/anchoring/` — RFC 3161 + Rekor + OTS clients (#937)
- `src-tauri/src/bootstrap.rs` — now derives system API key from BJJ priv (#945)
- `migrations/0027_add_credential_signature.sql` — SBT signature columns
- `migrations/0028_api_keys_bjj_pubkey.sql` — `api_keys.bjj_pubkey_x/y`
- `docs/court-evidence.md` — expert-witness packet (#937)
- `docs/sbt-deployment.md` — rewritten on #942 branch; pre-#942 main still has the stale EVM-mirror version

## Operator state on the user's WSL Ubuntu machine

- Olympus runs at v0.9.0 from `~/Olympus/target/release/`
- They have ptau20 at `~/Olympus/proofs/keys/powersOfTau28_hez_final_20.ptau`
- They ran `proofs/setup_circuits.sh` end-to-end; all 4 circuits + .ark.zkey files in place
- Webkit2gtk perf flags + Matrix-rain kill switch in `start.sh`
- They built deb/rpm/AppImage bundles
- WSL admin user is Antman83 (the only admin); registration of other users is the gap
