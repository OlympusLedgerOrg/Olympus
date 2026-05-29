//! Storage backends for the persistent Sparse Merkle Tree.
//!
//! A backend only moves bytes between memory and durable storage; every piece
//! of hashing / path / proof logic lives in [`super::tree`] and in the pure
//! `olympus-crypto` crate. Two implementations:
//!
//!  - [`PgBackend`] — the production path-addressed `smt_nodes` / `smt_leaves`
//!    tables (migration 0032). Lookups are direct primary-key probes by
//!    bit-path; writes are batched multi-row upserts via `UNNEST`.
//!  - [`MemBackend`] — an in-memory map used to exercise the tree algorithm
//!    (and its byte-for-byte parity with the reference in-memory tree) without
//!    a live database.

use std::collections::HashMap;
use std::sync::Mutex;

use sqlx::{PgPool, Row};

/// A node's address: its bit-path (one byte per bit, MSB first). Its length is
/// the node's depth; the global root has the empty path.
pub type NodePath = Vec<u8>;

/// Leaf preimage stored in `smt_leaves`. The leaf hash is recomputed on demand
/// from these fields via the canonical `leaf_hash` domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRecord {
    pub value_hash: [u8; 32],
    /// Shard identifier, bound into the leaf domain prefix (ADR-0005).
    pub shard_id: String,
    pub parser_id: String,
    pub canonical_parser_version: String,
    /// Parser model-artifact hash, bound into the leaf domain (ADR-0004).
    pub model_hash: String,
}

/// Durable storage for SMT nodes and leaves. Methods are batch-oriented so the
/// tree layer can amortise round-trips across a whole insert/proof batch.
#[allow(async_fn_in_trait)]
pub trait NodeBackend: Send + Sync {
    /// Fetch internal-node hashes for `paths`. Absent paths are simply omitted
    /// from the result (the caller fills them with the empty-subtree hash).
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;

    /// Fetch leaf records for the given 32-byte tree keys.
    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>>;

    /// Upsert internal nodes (`path → hash`).
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()>;

    /// Upsert leaves.
    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()>;

    /// Every node with depth (== path length) `<= max_depth`, for the hot
    /// write-behind cache that keeps the upper levels resident.
    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;

    /// Audit H-4: acquire a cross-process exclusive lock for the duration
    /// of an `update_batch`. The returned guard MUST be held across the
    /// read-modify-write sequence (`build_working_set` → recompute →
    /// `put_nodes`/`put_leaves`). Releasing it on drop is sufficient.
    ///
    /// Without this lock, two concurrent writers — e.g. a federation
    /// gossip thread + a /ingest handler — can each read a stale working
    /// set, compute disjoint dirty sets in memory, and racingly `put_nodes`.
    /// The second writer's upserts silently overwrite overlapping internal
    /// paths from the first, producing a root that reflects only the
    /// second writer's leaves while the first writer's leaves are still
    /// in `smt_leaves` — i.e. the tree's invariant (`root reconstructs
    /// from leaves`) is broken until the next full recompute.
    ///
    /// The Postgres impl uses `pg_advisory_lock` on a dedicated keyspace;
    /// the in-memory impl uses an async `Mutex`. The single-process
    /// `&mut self` borrow on `update_batch` already prevents intra-process
    /// races; the lock closes the inter-process / federation gap.
    async fn acquire_write_lock(&self) -> anyhow::Result<WriteLockGuard>;
}

/// RAII guard returned by [`NodeBackend::acquire_write_lock`]. Holds whatever
/// resource (Postgres advisory lock, in-memory mutex permit) the backend
/// uses to serialise writers, and releases it on drop. The guard is
/// `Send` so it can cross `.await` points.
pub struct WriteLockGuard {
    _inner: WriteLockKind,
}

impl WriteLockGuard {
    /// Construct from a Postgres advisory-lock holder. Crate-private so
    /// only the backend impls in this module produce guards.
    pub(crate) fn pg(holder: PgAdvisoryLockHolder) -> Self {
        Self {
            _inner: WriteLockKind::Pg(holder),
        }
    }

    /// Construct from an in-memory mutex permit (used by `MemBackend`).
    pub(crate) fn mem(permit: tokio::sync::OwnedMutexGuard<()>) -> Self {
        Self {
            _inner: WriteLockKind::Mem(permit),
        }
    }
}

enum WriteLockKind {
    Pg(PgAdvisoryLockHolder),
    Mem(tokio::sync::OwnedMutexGuard<()>),
}

/// Holds a Postgres advisory lock and releases it on drop. The
/// associated connection is **detached** from the pool
/// (`PoolConnection::detach`) so dropping the guard *closes* the
/// underlying session rather than returning the connection to the pool
/// with the lock still held.
///
/// Why detach rather than spawn a `pg_advisory_unlock` on Drop:
/// `pg_advisory_lock` is session-scoped (not transaction-scoped). If
/// the connection were returned to the pool while still leased to a
/// held lock, a future checkout by an unrelated request would inherit
/// the lock — permanently blocking every other `update_batch` caller
/// until that session is closed. A best-effort `tokio::spawn` unlock
/// has its own problems: the spawned task may never run if the
/// runtime is shutting down, and even if it does, there is a window
/// between conn return and unlock during which the lock leaks.
/// Closing the session on Drop is the only release path that survives
/// runtime shutdown.
pub struct PgAdvisoryLockHolder {
    // `Option` so Drop can take the connection. Detached from the
    // pool at acquisition time so dropping it closes the TCP session
    // and ends the Postgres session, which auto-releases every
    // advisory lock held by that session.
    conn: Option<sqlx::PgConnection>,
    key: i64,
}

impl Drop for PgAdvisoryLockHolder {
    fn drop(&mut self) {
        // The session-close on conn-drop is the authoritative release.
        // We still fire a best-effort `pg_advisory_unlock` so the lock
        // is released *immediately* rather than waiting for the
        // backend to notice the TCP close — but correctness no longer
        // depends on that spawn completing.
        if let Some(mut conn) = self.conn.take() {
            let key = self.key;
            tokio::spawn(async move {
                use sqlx::Executor;
                let _ = conn
                    .execute(sqlx::query("SELECT pg_advisory_unlock($1)").bind(key))
                    .await;
                // `conn` (PgConnection) drops here, closing the session.
            });
            // If the spawn above never runs (runtime shutdown), `conn`
            // was moved into the future and is dropped along with the
            // future — still closing the session, still releasing the
            // lock. The connection is detached, so there is no path
            // by which it could leak back into the pool while still
            // holding the lock.
        }
    }
}

/// Stable advisory-lock key for the SMT writer lock. Chosen from a
/// distinctive range so it doesn't collide with other Olympus advisory
/// locks the operator might add later.
pub(crate) const SMT_WRITE_LOCK_KEY: i64 = 0x4F4C594D_50555330_u64 as i64; // 'OLYMPUS\0' truncated

fn to_hash(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes.len() != 32 {
        anyhow::bail!("smt: expected 32-byte hash, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

// ── PostgreSQL backend ──────────────────────────────────────────────────────

/// Path-addressed Postgres storage over `smt_nodes` / `smt_leaves`.
pub struct PgBackend {
    pool: PgPool,
}

impl PgBackend {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl NodeBackend for PgBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let owned: Vec<Vec<u8>> = paths.to_vec();
        let rows = sqlx::query("SELECT path, hash FROM smt_nodes WHERE path = ANY($1)")
            .bind(owned)
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let path: Vec<u8> = row.try_get("path")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(path, to_hash(&hash)?);
        }
        Ok(out)
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let owned: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key = ANY($1)",
        )
        .bind(owned)
        .fetch_all(&self.pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let key: Vec<u8> = row.try_get("key")?;
            let value_hash: Vec<u8> = row.try_get("value_hash")?;
            let shard_id: String = row.try_get("shard_id")?;
            let parser_id: String = row.try_get("parser_id")?;
            let canonical_parser_version: String = row.try_get("canonical_parser_version")?;
            let model_hash: String = row.try_get("model_hash")?;
            out.insert(
                to_hash(&key)?,
                LeafRecord {
                    value_hash: to_hash(&value_hash)?,
                    shard_id,
                    parser_id,
                    canonical_parser_version,
                    model_hash,
                },
            );
        }
        Ok(out)
    }

    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let paths: Vec<Vec<u8>> = nodes.iter().map(|(p, _)| p.clone()).collect();
        let hashes: Vec<Vec<u8>> = nodes.iter().map(|(_, h)| h.to_vec()).collect();
        sqlx::query(
            "INSERT INTO smt_nodes (path, hash) \
             SELECT * FROM UNNEST($1::bytea[], $2::bytea[]) \
             ON CONFLICT (path) DO UPDATE SET hash = EXCLUDED.hash",
        )
        .bind(paths)
        .bind(hashes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
        if leaves.is_empty() {
            return Ok(());
        }
        let keys: Vec<Vec<u8>> = leaves.iter().map(|(k, _)| k.to_vec()).collect();
        let value_hashes: Vec<Vec<u8>> =
            leaves.iter().map(|(_, r)| r.value_hash.to_vec()).collect();
        let shard_ids: Vec<String> = leaves.iter().map(|(_, r)| r.shard_id.clone()).collect();
        let parser_ids: Vec<String> = leaves.iter().map(|(_, r)| r.parser_id.clone()).collect();
        let versions: Vec<String> = leaves
            .iter()
            .map(|(_, r)| r.canonical_parser_version.clone())
            .collect();
        let model_hashes: Vec<String> = leaves.iter().map(|(_, r)| r.model_hash.clone()).collect();
        sqlx::query(
            "INSERT INTO smt_leaves \
                 (key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash) \
             SELECT * FROM UNNEST($1::bytea[], $2::bytea[], $3::text[], $4::text[], $5::text[], $6::text[]) \
             ON CONFLICT (key) DO UPDATE SET \
                 value_hash = EXCLUDED.value_hash, \
                 shard_id = EXCLUDED.shard_id, \
                 parser_id = EXCLUDED.parser_id, \
                 canonical_parser_version = EXCLUDED.canonical_parser_version, \
                 model_hash = EXCLUDED.model_hash",
        )
        .bind(keys)
        .bind(value_hashes)
        .bind(shard_ids)
        .bind(parser_ids)
        .bind(versions)
        .bind(model_hashes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let rows = sqlx::query("SELECT path, hash FROM smt_nodes WHERE length(path) <= $1")
            .bind(max_depth as i64)
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let path: Vec<u8> = row.try_get("path")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(path, to_hash(&hash)?);
        }
        Ok(out)
    }

    async fn acquire_write_lock(&self) -> anyhow::Result<WriteLockGuard> {
        use sqlx::Executor;
        // Take a dedicated connection out of the pool and pin the lock to
        // it for the lifetime of the guard. `pg_advisory_lock` is
        // session-scoped, so the connection MUST stay checked-out for
        // the lock to remain held — using the pool directly would not
        // give us that guarantee.
        // Detach so dropping the guard closes the TCP session and
        // releases the (session-scoped) advisory lock — see
        // `PgAdvisoryLockHolder` doc comment.
        let mut conn = self.pool.acquire().await?.detach();
        conn.execute(sqlx::query("SELECT pg_advisory_lock($1)").bind(SMT_WRITE_LOCK_KEY))
            .await?;
        Ok(WriteLockGuard::pg(PgAdvisoryLockHolder {
            conn: Some(conn),
            key: SMT_WRITE_LOCK_KEY,
        }))
    }
}

// ── In-memory backend (tests / parity) ────────────────────────────────────────

/// In-memory `NodeBackend` backed by two maps behind a `Mutex`. Used by the
/// tree's parity tests so the algorithm can be exercised without a database.
pub struct MemBackend {
    nodes: Mutex<HashMap<NodePath, [u8; 32]>>,
    leaves: Mutex<HashMap<[u8; 32], LeafRecord>>,
    /// Audit H-4: in-memory writer lock. `tokio::sync::Mutex` lets the
    /// guard cross `.await`, matching the lifetime of `update_batch`.
    /// `Arc` so `acquire_write_lock` can hand back an `OwnedMutexGuard`.
    write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl Default for MemBackend {
    fn default() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
            leaves: Mutex::new(HashMap::new()),
            write_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

impl MemBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeBackend for MemBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let g = self.nodes.lock().unwrap();
        Ok(paths
            .iter()
            .filter_map(|p| g.get(p).map(|h| (p.clone(), *h)))
            .collect())
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let g = self.leaves.lock().unwrap();
        Ok(keys
            .iter()
            .filter_map(|k| g.get(k).map(|r| (*k, r.clone())))
            .collect())
    }

    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        let mut g = self.nodes.lock().unwrap();
        for (p, h) in nodes {
            g.insert(p.clone(), *h);
        }
        Ok(())
    }

    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
        let mut g = self.leaves.lock().unwrap();
        for (k, r) in leaves {
            g.insert(*k, r.clone());
        }
        Ok(())
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let g = self.nodes.lock().unwrap();
        Ok(g.iter()
            .filter(|(p, _)| p.len() <= max_depth)
            .map(|(p, h)| (p.clone(), *h))
            .collect())
    }

    async fn acquire_write_lock(&self) -> anyhow::Result<WriteLockGuard> {
        let permit = self.write_lock.clone().lock_owned().await;
        Ok(WriteLockGuard::mem(permit))
    }
}
