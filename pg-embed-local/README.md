<p align="center">
  <img src="assets/logo.jpg" alt="pg-embed logo" width="320">
</p>
<h1 align="center">pg-embed</h1>

<p align="center">
  <a href="https://crates.io/crates/pg-embed"><img src="https://img.shields.io/crates/v/pg-embed" alt="crates.io"></a>
  <a href="https://docs.rs/pg-embed"><img src="https://docs.rs/pg-embed/badge.svg" alt="docs.rs"></a>
  <a href="https://crates.io/crates/pg-embed"><img src="https://img.shields.io/crates/d/pg-embed" alt="downloads"></a>
  <img src="https://img.shields.io/badge/rustc-1.88%2B-orange" alt="MSRV 1.88">
  <a href="LICENSE"><img src="https://img.shields.io/crates/l/pg-embed" alt="license"></a>
</p>

<p align="center">
  Run a PostgreSQL server locally as part of a Rust application or test suite — no system installation required.
</p>

<p align="center">
  <img src="assets/banner.png" alt="pg-embed banner">
</p>

---

pg-embed uses precompiled PostgreSQL binaries published by [zonkyio/embedded-postgres-binaries](https://github.com/zonkyio/embedded-postgres-binaries). It downloads artifacts from the configured host (Maven Central by default), verifies retained archives against repository-pinned SHA-256 digests, caches them on first use, and manages the full server lifecycle (`initdb` → direct `postgres` child → exact-process shutdown). Built on [tokio](https://crates.io/crates/tokio).

## Contents

- [Quick start](#quick-start)
- [Extensions](#extensions)
- [Features](#features)
- [Platform support](#platform-support)
- [Binary cache](#binary-cache)
- [Documentation](#documentation)

---

## Quick start

```toml
[dependencies]
pg-embed = "1.0"
```

```rust,no_run
use std::path::PathBuf;
use std::time::Duration;

use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_errors::Result;
use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
use pg_embed::postgres::{PgEmbed, PgSettings};

#[tokio::main]
async fn main() -> Result<()> {
    let mut pg = PgEmbed::new(
        PgSettings {
            database_dir:  PathBuf::from("data/db"),
            port:          5432,
            user:          "postgres".to_string(),
            password:      "password".to_string(),
            auth_method:   PgAuthMethod::MD5,
            persistent:    false,
            timeout:       Some(Duration::from_secs(30)),
            migration_dir: None,
        },
        PgFetchSettings { version: PG_V15, ..Default::default() },
    ).await?;

    pg.setup().await?;    // download + unpack + initdb (cached after first run)
    pg.start_db().await?;

    pg.create_database("mydb").await?;

    // postgres://postgres:password@localhost:5432/mydb
    let uri = pg.full_db_uri("mydb");
    println!("Connect at: {uri}");

    pg.stop_db().await?;
    Ok(())
}
```

---

## Extensions

Third-party extensions (pgvector, PostGIS, etc.) are not included in the precompiled binaries. To install one, point `install_extension()` at a directory containing the pre-built files for your platform. Call it **after** `setup()` and **before** `start_db()`.

```rust,no_run
use std::path::Path;

// After pg.setup() and before pg.start_db():
pg.install_extension(Path::new("extensions/pgvector")).await?;
pg.start_db().await?;

// Then activate it inside a database:
// CREATE EXTENSION IF NOT EXISTS vector;
```

Files are routed by extension:

| File type               | Destination                           |
| :---------------------- | :------------------------------------ |
| `.so`, `.dylib`, `.dll` | `{cache}/lib/`                        |
| `.control`, `.sql`      | `{cache}/share/postgresql/extension/` |
| Anything else           | Skipped                               |

Pure-SQL extensions (no shared library) work the same way — simply omit the binary.

---

## Features

| Capability               | API                                                         | Feature flag       |
| :----------------------- | :---------------------------------------------------------- | :----------------- |
| 🔄 Server lifecycle       | `setup()`, `start_db()`, `stop_db()`                        | `rt_tokio`         |
| 🧩 Extension installation | `install_extension()`                                       | `rt_tokio`         |
| 🗄️ Database management    | `create_database()`, `drop_database()`, `database_exists()` | `rt_tokio_migrate` |
| 🚀 Migrations             | `migrate()`                                                 | `rt_tokio_migrate` |

The default feature is `rt_tokio_migrate` (includes sqlx). For a smaller build without sqlx:

```toml
pg-embed = { version = "1.0", default-features = false, features = ["rt_tokio"] }
```

Additional behaviours included in all builds:

- **Verified, atomic archive caching** — downloads are extracted into a private staging tree, checked against the pinned archive, made owner-only and immutable, then published by atomic rename.
- **Exact process-tree lifecycle** — `start_db()` launches PostgreSQL in a parent-tied private tree. Linux retains a pidfd plus a private session and watchdog; Windows retains the original process/thread handles and assigns the still-suspended process to a kill-on-close Job before resuming it; macOS retains the unreaped leader plus a parent-watch supervisor. Graceful shutdown signals only the retained postmaster, then force-falls back to the complete tree. Windows authenticates PostgreSQL's signal-pipe server against the retained process handle and bounds the connect/write/acknowledgement exchange before that fallback. `postmaster.pid` never grants shutdown authority.
- **Launch-bound executable integrity** — verified executable handles/inodes and a shared cross-process cache lease remain live from authentication through the server lifetime. The whole cache tree, including dynamically loaded libraries and extensions, is owner/permission checked before launch.
- **Transactional extension installation** — extension files are copied into a complete authenticated sibling cache, revalidated, and atomically published under an exclusive cross-process lease. Cancellation cannot expose a partial live cache.
- **Concurrent safety** — process-local serialization plus a cross-process file lease prevents partial-cache observation and mutation while a server is using the cache.

---

## Platform support

| OS                                                                                                | Verified architectures |
| :------------------------------------------------------------------------------------------------ | :--------------------- |
| ![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)         | amd64, arm64v8         |
| ![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)         | amd64                  |
| ![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)   | amd64                  |

The verified acquisition path is pinned to **PostgreSQL 15.16.0** (`PG_V15`).
Other legacy version constants fail closed until their exact target archives
are reviewed and pinned in source.

---

## Binary cache

The retained archive is stored at an OS-specific location and reused only while
the archive, marker, complete executable comparison, owner/ACL or mode checks,
and immutable tree checks all remain valid:

| OS      | Cache path                                          |
| :------ | :-------------------------------------------------- |
| macOS   | `~/Library/Caches/pg-embed/`                        |
| Linux   | `$XDG_CACHE_HOME/pg-embed/` or `~/.cache/pg-embed/` |
| Windows | `%LOCALAPPDATA%\pg-embed\`                          |

---

## Documentation

- [User Handbook](docs/user-handbook.md) — configuration reference, auth methods, migrations, FAQ
- [Technical Handbook](docs/technical-handbook.md) — architecture, data flow, module graph, internals
- [API reference on docs.rs](https://docs.rs/pg-embed)

---

## License

pg-embed is dual-licensed under [MIT](LICENSE) / [Apache 2.0](LICENSE).

---

## Credits

Precompiled binaries provided by [zonkyio/embedded-postgres-binaries](https://github.com/zonkyio/embedded-postgres-binaries), hosted on [Maven Central](https://mvnrepository.com/artifact/io.zonky.test.postgres/embedded-postgres-binaries-bom).
