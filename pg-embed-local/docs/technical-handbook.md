# pg-embed Technical Handbook

Internal reference covering architecture, data flow, global state, platform support, and error taxonomy.

---

## Module overview

```
src/
├── lib.rs               — public re-exports + compile_error! feature guard
├── pg_errors.rs         — Error enum (thiserror) + Result alias
├── pg_enums.rs          — PgAuthMethod, PgServerStatus, OperationSystem, Architecture, …
├── pg_fetch.rs          — HTTP download (reqwest) → raw JAR bytes
├── pg_unpack.rs         — JAR → XZ tarball → binary files on disk
├── pg_access.rs         — atomic immutable cache + retained executable handles
├── pg_commands.rs       — builds AsyncCommandExecutor for initdb
├── command_executor.rs  — generic async process runner with timeout
├── process.rs           — exact parent-tied process-tree capability and termination
└── postgres.rs          — PgEmbed public API + PgSettings + Drop
```

### Dependency graph

```
postgres.rs
  ├── pg_access.rs
  │     └── pg_fetch.rs → (network)
  │     └── pg_unpack.rs → (disk)
  ├── pg_commands.rs
  │     └── command_executor.rs → (child processes)
  └── pg_enums.rs
        └── command_executor.rs (ProcessStatus trait)
```

All error types flow upward into `pg_errors::Error`; all async code runs on a tokio runtime.

---

## Data flow

### `PgEmbed::new()`

1. Accepts `PgSettings` and `PgFetchSettings`.
2. Constructs a `PgAccess` which computes:
   - **cache dir** (`{OS cache}/pg-embed/{os}/{arch}/{version}/`) — where binaries live.
   - **database dir** — user-supplied path for the cluster data files.
   - **password file path** — a `.pgpass`-style temp file written alongside the database dir.
3. Returns an uninitialised `PgEmbed` with `server_status = Uninitialized`.

### `pg.setup()`

```
PgEmbed::setup()
  └─ PgAccess::maybe_acquire_postgres()
       ├─ require a repository-pinned SHA-256 for version + target
       ├─ acquire the versioned cross-process cache lease
       ├─ verify the archive, marker, complete executable set, and tree permissions
       ├─ (if invalid/missing) create an owner-only sibling staging directory
       ├─ stream and verify the archive before extraction
       ├─ pg_unpack::unpack_postgres(snapshot, staging_dir)
       │     ├─ tokio::task::spawn_blocking(...)
       │     ├─ ZipArchive::new(zip_file)
       │     ├─ find entry ending in ".txz" or ".xz"
       │     ├─ lzma_rs::xz_decompress(xz_bytes) → tar_bytes
       │     └─ Archive::new(tar_bytes).unpack(staging_dir)
       ├─ compare extracted initdb, pg_ctl, and postgres with the snapshot
       ├─ write marker, harden the entire staging tree, then atomically rename
       └─ mark ACQUIRED_PG_BINS[cache_dir] = Finished
  └─ retain verified executable handles/inodes plus a shared cache lease
  └─ write password file
  └─ (if no PG_VERSION file) run initdb
       └─ AsyncCommandExecutor { initdb, --auth, --username, --pwfile, … }
```

### `pg.install_extension(dir)`

```
PgEmbed::install_extension(extension_dir)
  ├─ reject mutation while a server is running
  └─ PgAccess::install_extension(extension_dir) under an exclusive cache lease
       ├─ revalidate archive pin, marker, executables, and immutable tree
       ├─ copy the complete live cache to a private sibling staging tree
       ├─ locate/create the extension directories only inside staging
       ├─ for each no-follow regular file in extension_dir:
            ├─ .so / .dylib / .dll  → copy to {cache}/lib/
            ├─ .control / .sql      → copy to {cache}/share/postgresql/extension/
            └─ anything else        → skip
       ├─ make and revalidate the complete staged cache as immutable
       └─ publish by directory rename, rolling back the authenticated original
          on failure; the blocking transaction continues if its async waiter is cancelled
  └─ reacquire verified executable handles from the published cache
```

Must be called after `setup()` (cache dir exists) and before `start_db()` (PostgreSQL reads the extension directory at startup).

### `pg.start_db()`

```
PgEmbed::start_db()
  ├─ recheck retained executable pathname identity
  ├─ spawn authenticated postgres inside a parent-tied private tree
  ├─ immediately seal the tree as PostgresProcess
  │    ├─ Linux: handle-bound image + retained pidfd/private session/watchdog
  │    ├─ Windows: retained process/thread handles; assign suspended process
  │    │           to kill-on-close Job before ResumeThread
  │    └─ macOS: retained unreaped leader/private session/parent-watch supervisor
  ├─ poll a bounded, no-follow postmaster.pid until PID/data-dir/port/status match
  └─ on cancellation/error/timeout, exact-terminate and wait
  └─ server_status = Started
```

### `pg.stop_db()`

Signals the exact postmaster retained by `start_db()` and waits for the entire
tree. Linux uses the pidfd and private session, Windows authenticates
PostgreSQL's signal pipe against the retained process HANDLE and observes the
Job, and macOS signals the retained supervisor. The Windows signal-pipe
connect, write, and acknowledgement share a one-second deadline; pending I/O
is cancelled before falling back to the Job. After the grace interval every
platform force-terminates and confirms the whole private tree.
`stop_db_sync()` performs the same operation without an async runtime.

### `Drop` implementation

```rust
impl Drop for PgEmbed {
    fn drop(&mut self) {
        if let Some(exact_process) = self.process.take() {
            exact_process.terminate_and_wait();
        }
        if exit_is_confirmed() && !self.pg_settings.persistent {
            let _ = self.pg_access.clean();
        }
    }
}
```

**Constraint:** Complete tree authority is stored before the first post-spawn
await. A failure to establish it kills and waits the just-created tree before
returning. A mutable pidfile, executable pathname, or numeric PID never becomes
shutdown authority. A stale live pidfile from a legacy launch fails closed
because a later leader handle cannot reconstruct descendant-tree authority.

---

## Global state

```rust
// src/pg_access.rs
static ACQUIRED_PG_BINS: LazyLock<Arc<Mutex<HashMap<PathBuf, PgAcquisitionStatus>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::with_capacity(5))));
```

**Purpose:** Prevents duplicate work within one process. A sibling lock file
adds shared/exclusive coordination across processes and remains held for the
whole server lifetime.

**Lifecycle:**
1. `maybe_acquire_postgres()` locks the mutex for the cache path.
2. A cache is reusable only when all executables, the retained archive, and
   marker exist; archive and executable bytes match; no symlink/reparse or
   special node exists; and every tree entry has the required owner and
   immutable mode/protected owner-only ACL.
3. Otherwise the versioned binary cache (never the separate database cluster)
   is rebuilt in a private staging tree and atomically published.
4. Shared leases and retained executable handles bind validation through
   launch and prevent cooperative cache replacement while PostgreSQL runs.

**`purge()`** fails closed. Whole-cache removal cannot be synchronized safely
with capabilities held by an unknown external process and is an offline
maintenance operation.

---

## Binary package format

Binaries are distributed as Maven JAR files (ZIP archives) from `repo1.maven.org`.
URL template:
```
{host}/maven2/io/zonky/test/postgres/
  embedded-postgres-binaries-{platform}/{version}/
  embedded-postgres-binaries-{platform}-{version}.jar
```

The JAR contains exactly one entry with a `.txz` extension (e.g. `postgres-darwin-arm_64.txz`).
That entry is an XZ-compressed tarball (`tar.xz`) containing the full PostgreSQL binary tree.

Before the unpacker runs, SHA-256 is streamed while downloading and compared
with the repository pin. This proves equality with the repository-pinned digest
only; it does not independently authenticate the upstream publisher. A mismatch
deletes the partial archive and fails closed.
The unpacker then:

1. Opens the verified JAR with the `zip` crate.
2. Finds the entry ending in `.txz` or `.xz`.
3. Decompresses XZ with `lzma-rs` (pure Rust).
4. Extracts the tar with the `tar` crate into the cache directory.

This is run inside `tokio::task::spawn_blocking` to avoid blocking the async executor.

### Integrity boundary and threat model

The pinned SHA-256 establishes that an archive is byte-for-byte equal to the
digest reviewed in this repository. It does not independently establish
publisher identity. Cache validation compares `initdb`, `pg_ctl`, and
`postgres` with that exact in-memory archive snapshot. A retained shared lease,
opened executable handle/inode, immediate path-identity recheck, and enforced
tree permissions bind that validation through launch. On Unix the operating
system account owning the cache remains inside the trust boundary; on Windows
open handles deny write/delete sharing even to a racing process.

---

## Filesystem layout

```
{cache}/pg-embed/{os}/{arch}/{version}/
  ├── bin/
  │    ├── initdb
  │    ├── pg_ctl
  │    └── postgres (and other PG tools)
  ├── lib/                             ← .so/.dylib/.dll from install_extension()
  ├── share/postgresql/extension/      ← .control/.sql from install_extension()
  ├── {platform}-{version}.zip        ← retained, re-hashed JAR
  └── .olympus-verified-package.sha256

{database_dir}/
  ├── PG_VERSION        ← created by initdb; used as existence check
  ├── pg_hba.conf
  └── … (standard cluster data files)

{database_dir}/../.pgpass   ← password file written by setup()
```

Cache base path (OS-specific, from `dirs` crate):

| OS      | Path |
|---------|------|
| macOS   | `$HOME/Library/Caches/pg-embed` |
| Linux   | `$XDG_CACHE_HOME/pg-embed` or `$HOME/.cache/pg-embed` |
| Windows | `{FOLDERID_LocalAppData}\pg-embed` |

---

## Platform support matrix

| OS            | `OperationSystem` variant | `Display` string |
|---------------|--------------------------|-----------------|
| macOS         | `Darwin`                 | `darwin`        |
| Linux (glibc) | `Linux`                  | `linux`         |
| Alpine Linux  | `AlpineLinux`            | `linux`         |
| Windows       | `Windows`                | `windows`       |

| CPU           | `Architecture` variant | `Display` string |
|---------------|------------------------|-----------------|
| x86-64        | `Amd64`                | `amd64`         |
| 32-bit x86    | `I386`                 | `i386`          |
| ARMv6 32-bit  | `Arm32v6`              | `arm32v6`       |
| ARMv7 32-bit  | `Arm32v7`              | `arm32v7`       |
| AArch64       | `Arm64v8`              | `arm64v8`       |
| POWER LE 64   | `Ppc64le`              | `ppc64le`       |

For Alpine Linux the Maven classifier appends `-alpine` to the architecture:
`linux-amd64-alpine`, `linux-arm64v8-alpine`, etc.

`OperationSystem::default()` and `Architecture::default()` are set at compile time via `#[cfg(target_os)]` / `#[cfg(target_arch)]`.

---

## Feature flags

| Feature              | Enables                    | Gates                                                      |
|----------------------|----------------------------|------------------------------------------------------------|
| `rt_tokio`           | tokio + reqwest            | fetch, unpack, init, start/stop, `install_extension`       |
| `rt_tokio_migrate`   | + sqlx                     | everything above + `create_database`, `drop_database`, `database_exists`, `migrate` |

At least one feature is required; `lib.rs` emits `compile_error!` otherwise.
The default features are `rt_tokio_migrate`.

sqlx-dependent code is guarded with `#[cfg(feature = "rt_tokio_migrate")]`.

---

## `command_executor.rs` internals

`AsyncCommandExecutor` implements the `AsyncCommand` trait using AFIT (async fn
in traits, stable since Rust 1.75). It uses the same retained process-tree
runner as the server, including for `initdb`; no auxiliary launch bypasses the
tree capability.

```
execute(timeout)
  ├─ launch retained executable image as a private process tree
  ├─ poll whole-tree exit (leader exit alone is insufficient)
  └─ at timeout
       ├─ gracefully signal the retained payload
       ├─ force the complete tree after the grace interval
       └─ confirm tree exit before returning PgTimedOutError
```

`server_status` is a `Arc<Mutex<PgServerStatus>>` shared between the executor and the `PgEmbed` struct, updated at entry (`Initializing` / `Starting` / `Stopping`) and exit (`Initialized` / `Started` / `Stopped` or `Failure`).

---

## Error taxonomy

| Variant              | When raised |
|----------------------|-------------|
| `InvalidPgUrl`       | Cache directory unavailable or unsupported platform |
| `InvalidPgPackage`   | Downloaded ZIP cannot be opened or has no `.txz`/`.xz` entry |
| `UnpinnedPgPackage`  | No repository-pinned SHA-256 exists for the requested version/target |
| `PgPackageDigestMismatch` | Downloaded or cached JAR differs from its source pin |
| `WriteFileError`     | Password file or zip file write fails |
| `ReadFileError`      | File read or existence check fails |
| `DirCreationError`   | `fs::create_dir_all` fails |
| `UnpackFailure`      | XZ decompress or tar extract fails |
| `PgStartFailure`     | Direct PostgreSQL child exits before publishing readiness |
| `PgInitFailure`      | `initdb` exits non-zero |
| `PgCleanUpFailure`   | Removal of database dir or password file fails |
| `PgPurgeFailure`     | Removal of cache directory fails |
| `PgBufferReadError`  | BufReader line read fails inside I/O task |
| `PgLockError`        | Mutex acquire fails |
| `PgProcessError`     | `child.wait()` or spawn fails |
| `PgTimedOutError`    | `tokio::time::timeout` elapsed |
| `PgTaskJoinError`    | `spawn_blocking` task panicked |
| `PgError`            | Internal context wrapper (message + context string) |
| `DownloadFailure`    | `reqwest::get` fails |
| `ConversionFailure`  | `.bytes().await` fails on HTTP response |
| `SendFailure`        | MPSC channel send fails (receiver dropped) |
| `SqlQueryError`      | sqlx connection or query fails (`rt_tokio_migrate`) |
| `MigrationError`     | sqlx migrator fails (`rt_tokio_migrate`) |

---

## MSRV and dependency notes

- **MSRV:** Rust 1.88 — set by `zip` 8.x (1.88); Rust edition 2024 requires 1.85; `std::sync::LazyLock` requires 1.80
- **`lzma-rs`:** pure-Rust XZ decompression; replaces former C-based `xz2`
- **`std::sync::LazyLock`:** replaces former `lazy_static` crate for `ACQUIRED_PG_BINS`
- **AFIT:** replaces former `async-trait` crate in `AsyncCommand`
- **`zip` 8.x:** binding MSRV constraint at 1.88
- **`reqwest` 0.13:** TLS backend is `rustls` (no OpenSSL dependency)

---

## Testing

Integration tests are split into thematic files:

| File | Requires | Content |
|:---|:---|:---|
| `tests/lifecycle.rs` | `rt_tokio` + `rt_tokio_migrate` | start/stop, drop, timeout, persistence, concurrent |
| `tests/auth.rs` | `rt_tokio` + `rt_tokio_migrate` | authentication methods |
| `tests/database.rs` | `rt_tokio_migrate` | create/drop/exists, URI format |
| `tests/migration.rs` | `rt_tokio_migrate` | sqlx migrations |
| `tests/extension.rs` | `rt_tokio_migrate` | extension install and use |

`lifecycle.rs` and `auth.rs` are each registered twice in `Cargo.toml` (once per feature flag) so the same source is compiled under both `rt_tokio` and `rt_tokio_migrate`.

`#[file_serial(pg_port_5432)]` is used on tests that start a server to serialise across process boundaries (file locks work between separate test binaries).

Test isolation uses `tempfile::TempDir` via the `tests/common::setup_with_tempdir` helper. Return type is `(TempDir, PgEmbed)` — `TempDir` first so it is dropped _last_, after `PgEmbed` has stopped the server and removed the database directory.
