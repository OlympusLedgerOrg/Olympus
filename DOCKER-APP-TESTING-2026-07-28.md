# Docker Full-App Testing — 2026-07-28/29

**Branch:** `claude/docker-app-testing-892b9c`, rebased onto `origin/main` @ `992afb1a`
**Host:** Windows 11, Docker Desktop 4.64.0 / engine 29.2.1, `desktop-linux` context, 8 CPU / 8 GB
**Scope:** stand the whole app up in a container and exercise it end-to-end, then use Linux
containers to reach the surfaces Windows cannot test at all.

---

## 1. What this delivers

| Result | Detail |
|---|---|
| **Containerised full-app harness, working** | Forward-ported from a stranded branch; `main` referenced it but did not contain it |
| **44 / 44** endpoint checks | E2E sweep against the real server in a container |
| **695 + 8** federation tests | `--features federation,quorum-circuit` — cannot even *link* on Windows |
| **655** zkvm-prover tests + a **real receipt** | Proved in 38s, verified against the pinned guest image id |
| **External PostgreSQL contract verified** | Real `postgres:15`, production two-role shape, ingest round-trip, lifecycle lock |

### Not delivered by this branch (important)

The two `db::process_identity` defects from `#1486` that this work independently rediscovered were
**fixed upstream in `#1505` (`e9b7926d`, 2026-07-29 09:28)** while this session was running, together
with `src-tauri/tests/db_init_embedded.rs` covering the gap. This branch's own attempt at those fixes
was **discarded** in favour of upstream's, which is the better fix — see §4.

---

## 2. The harness was stranded, not missing

`tests/e2e_http.rs` on `main` is dual-mode and documents a container mode pointing at
`docker/compose.audit.yml` — a file `main` did not have. It lived on the unmerged
`audit/full-stack-2026-06-20`, commit `6326d0a3`, **211 commits stale**. Forward-ported:

- `src-tauri/src/bin/olympus-server.rs` — headless Axum + pg_embed boot, no GTK window
- `docker/Dockerfile.audit` (+ its `.dockerignore`) — builder → slim non-root runtime
- `docker/compose.audit.yml` — server + E2E runner sharing its network namespace

The netns detail matters: `server::start` binds `127.0.0.1` only and exits if it ever resolves to a
non-loopback address — a fail-closed invariant the per-IP rate limiter depends on. A published
`ports:` mapping therefore cannot reach it; the runner joins via
`network_mode: "service:olympus-server"` rather than weakening the bind.

### Drift and harness defects fixed to make it run

| # | Defect | Cause |
|---|---|---|
| 1 | `anchoring::upgrade_cron::spawn` missing 4th arg | Gained `ots_bitcoin_headers_path` since the branch was cut |
| 2 | Headless bin missing the ADR-0036 signed-request nonce reaper | `main.rs` gained it; the bin documents itself as "kept in sync with main.rs" |
| 3 | Build failed: `couldn't read olympus_canonicalization_guest.elf` | `zk/canonicalization.rs` `include_bytes!`s the RISC Zero guest ELF; the dockerignore dropped all of `proofs/` bar vkeys + manifests |
| 4 | E2E runner OOM-killed (SIGKILL) | `cargo test` builds *all* bin targets including the LTO'd `olympus-desktop`, which the builder stage never compiles; will not fit in 8 GB at `codegen-units=1` |

For #3 I swept every `include_bytes!`/`include_str!` in the lib, `build.rs` and workspace crates
rather than chasing one file at a time — the zkVM guest was the only gap.

For #4 the fix is profile relaxation **for the runner only** (`CARGO_PROFILE_RELEASE_LTO=false`,
`CODEGEN_UNITS=16`, bounded `CARGO_BUILD_JOBS`); LTO buys a test runner nothing. A second latent
problem was fixed alongside: the runner is `--rm` with no persistent target dir, so every invocation
would have recompiled the whole tree. It now uses a named cache volume.

---

## 3. Results

### 3.1 Containerised E2E sweep — 44/44

Server boots clean on a fresh volume: migrations applied, bootstrap minted the system API key + BJJ
authority, self-signed authority SBT minted, anchor cron and nonce reaper running, health `db: ok`,
`/public/stats` reporting `sbts_issued: 1`.

Coverage spans public routes, auth, admin, ingest, ZK, credentials, redaction and anchors, and
re-checks the load-bearing invariants: Host-guard `403`, CORS preflight, `413` body limit, ZK
`treeSize=0` (H-2) `400`, shard `authorize_write` `403`, insert-only `409`, and the credential/anchor
auth matrix.

```
=== 44 ok / 0 FAIL ===
```

### 3.2 Federation on Linux — 695 lib + 8 integration

`--features federation,quorum-circuit`. This feature **cannot link on Windows** (LNK1181 on
`sqlite3.lib` via `arti → rusqlite`), so on the host `cargo check` passes but `cargo test` cannot.
In the container: **695 lib tests passed, 0 failed**.

The equivocation suite was also run **with federation enabled**, against the real `postgres:15` (the
test accepts `OLYMPUS_TEST_PG_URL` instead of pg_embed): **8 passed, 0 failed**.

That combination is **not covered by CI** — the embedded-Postgres job builds these binaries
`--no-default-features`, so `federation_equivocation` normally runs with the feature *off*. The audit
A1-03 TOCTOU and narrow-detection fixes had therefore never run in a federation-enabled build.

### 3.3 zkvm-prover on Linux — real receipt produced and verified

`zkvm-prover` is deliberately absent from Windows builds ("the upstream proving toolchain does not
support Windows"). In the container: **655 passed, 0 failed**.

Compiling is necessary but not sufficient — that suite finishes in ~2s, so it generates no proof, and
`prove_source_base64` has **no test coverage anywhere in the repo**. A throwaway smoke test was
mounted into the container (**not committed**) to exercise it for real:

```
proved in 38.079087176s, receipt is 777412 base64 chars
canonical_hash = 11372485855650552949894324196872520549549884452388200021000527697898207308191
receipt verified against the pinned guest image id
```

A first attempt fed the guest arbitrary bytes and it panicked *inside the zkVM* with `source must be
valid bounded Olympus canonical JSON` — incidental confirmation that the guest really executes and
enforces its input contract. Corrected to canonical JSON (JCS/RFC 8785).

### 3.4 External PostgreSQL role contract — against a real `postgres:15`

Provisioned the production two-role shape from `docs/external-postgresql-roles.md`, mirroring the DDL
in `tests/api_db/external_pg_roles.rs`: neutral `NOLOGIN` owner, migrator owning the sole application
schema, runtime role with no DDL rights.

This is genuinely new coverage — the in-repo test provisions its roles *inside the pg_embed fixture*,
so the contract had never run against a real PostgreSQL server.

| Check | Result |
|---|---|
| Migrations applied | **55** |
| Schema owner | `olympus_app` → `olympus_migrator` |
| Table owner | all tables → `olympus_migrator` |
| Runtime `CONNECT` | `t` — restored last, as documented |
| Runtime `CREATE` on schema | `f` — no DDL |
| Runtime `SELECT` / `INSERT` | `t` / `t` |
| Runtime `DELETE` | **`f`** |
| Ingest round-trip | `HTTP 201`, real content hash |
| Rows written via runtime role | 1 ingest record, 1 SMT leaf, 2 users |

`DELETE = f` is worth calling out: the ADR-0031 insert-only ledger invariant is enforced at the
**database privilege layer**, not merely in application code.

**Exclusive lifecycle lock.** A second server against the same database was refused —
`external database maintenance lock is unavailable — DB-backed routes return 503` — while the first
stayed healthy. Fail-closed, exactly as `CLAUDE.md` describes.

---

## 4. The `#1486` regression — rediscovered here, fixed upstream

Standing the app up in a container immediately surfaced that `arm_verified_postgres` could never
succeed. Two defects, both from `#1486` (`bcc564c9`, 2026-07-27):

1. **Start time compared with exact equality.** sysinfo derives `btime + starttime_jiffies / HZ`
   (truncating, measuring process *start*); `postmaster.pid` line 3 is PostgreSQL's own `time(NULL)`,
   taken strictly later. Measured in-container, 6/6 consecutive starts showed sysinfo exactly **1
   second behind** → `ReusedPid`.
2. **An unsatisfiable argv allowlist.** It *required* `-F`, but `PgEmbed::start_db` spawns exactly
   `postgres -D <dir> -p <port>`; `-F` appears nowhere in `pg-embed-local`. So `observed.data_dir`
   was always `None` → `UnverifiableProcess`.

**Upstream `#1505` fixed both while this session ran**, and did so better:

- it introduced a symmetric `start_times_agree` helper, where this branch had used a one-directional
  window;
- it made `-F` **fail closed** (`"-F must fail closed, not be tolerated or required"`) rather than
  merely optional. That is the correct call: `-F` disables fsync while `patch_pg_conf` pins
  `fsync = on`, and command-line options override the config file — so tolerating `-F` tolerates a
  postmaster running against the ledger's own durability policy. This branch had left it tolerated
  and flagged the question; upstream answered it correctly.

`#1505` also added `src-tauri/tests/db_init_embedded.rs` and wired it into
`scripts/embedded-postgres-tests.sh`, closing the coverage gap that let the regression ship: the
shared harness in `tests/common/mod.rs` drives `PgEmbed` directly and never calls `db::init_embedded`.

This branch's duplicate fixes and its own `embedded_startup.rs` were therefore **discarded**, and the
branch rebased onto `992afb1a`. The independent rediscovery is still useful as corroboration — in
particular the 6/6 measured 1-second skew, which is runtime evidence for a defect that had previously
only been identified by static reading.

---

## 5. Corrections to earlier statements in this session

Recorded because they were stated confidently and were wrong:

- **"`smt_pg_backend` passes green on this host while the app path is dead."** It did not pass — it
  failed to *compile*, and a `| tail -25` pipeline masked the non-zero exit. That run never started
  PostgreSQL and proved nothing. The claim that `tests/common/mod.rs` bypasses `db::init_embedded`
  remains true, but it rests on reading the harness, not on that run.
- **"Windows is broken at two further points by `#1486`."** Not supported. Every pg_embed integration
  test fails on this Windows host at `PgEmbed::setup()`/initdb with `retained utility exited
  unsuccessfully with code Some(1)`, and this is a known pre-existing host-local condition:
  `pg-embed-local/src/process.rs::spawn_windows` routes child stdio to `NUL`, so initdb's real error
  is unrecoverable, and the same `initdb.exe` with the same argv succeeds when run by hand. Local
  embedded-Postgres reds on this host are not evidence about the code under test — verify in CI or
  the container.

---

## 6. Coverage gaps still open

1. **`prove_source_base64` has no test coverage.** The Linux-only proving path is never exercised.
   The ~30-line smoke test used here would close it, ideally in a nightly job given ~38s per proof.
2. **Federation-enabled integration tests never run in CI.** The embedded-Postgres job builds
   `--no-default-features`.
3. **The external-PG contract is only tested against pg_embed.** The production shape against a real
   server — and anything requiring TLS, e.g. `sslmode=verify-full` — is uncovered. A `postgres:15`
   service in CI would close it.
4. **Windows CI runs no embedded-Postgres tests at all** (an explicit DB-free allowlist), so the
   platform where local pg_embed is broken also has no CI signal for it.

---

## 7. Changes on this branch

Nothing is committed.

```
docker/Dockerfile.audit               (new)
docker/Dockerfile.audit.dockerignore  (new, + zkvm guest re-include)
docker/compose.audit.yml              (new, + proofs override, profile relaxation, cache volume)
src-tauri/Cargo.toml                  (tokio "signal", for the headless bin's graceful shutdown)
src-tauri/src/bin/olympus-server.rs   (new, + 2 drift fixes)
```

## 8. Running it

```bash
OLYMPUS_PROOFS_KEYS_HOST=/c/Users/you/Olympus/proofs/keys \
  docker compose -f docker/compose.audit.yml up -d --build
```

```bash
OLYMPUS_PROOFS_KEYS_HOST=/c/Users/you/Olympus/proofs/keys \
  docker compose -f docker/compose.audit.yml --profile e2e run --rm e2e
```

`OLYMPUS_PROOFS_KEYS_HOST` matters from a git worktree: `build.rs` drops 60-byte `PLACEHOLDER` stubs
into the worktree's own `proofs/keys`, while the real `.wasm`/`.r1cs`/`.ark.zkey` live in the primary
checkout. Mounting placeholders fails silently — the server starts fine and only `/zk/prove` 503s.
