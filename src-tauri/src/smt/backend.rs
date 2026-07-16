//! Storage backends for the persistent Sparse Merkle Tree.
//!
//! A backend only moves bytes between memory and durable storage; every piece
//! of hashing / path / proof logic lives in [`super::tree`] and in the pure
//! `olympus-crypto` crate. Three implementations:
//!
//!  - [`PgBackend`] — the production path-addressed `smt_nodes` / `smt_leaves`
//!    tables. Nodes are keyed by `(depth, packed bit-path)` (migration 0043;
//!    see [`pack_bits`]); lookups are primary-key probes and writes are batched
//!    multi-row upserts via `UNNEST`.
//!  - [`SqliteBackend`] — an optional local-file backend with the same physical
//!    keys. Writers use `BEGIN IMMEDIATE`, so SQLite's database writer lock and
//!    the atomic SMT transaction are the same correctness boundary.
//!  - [`MemBackend`] — an in-memory map used to exercise the tree algorithm
//!    (and its byte-for-byte parity with the reference in-memory tree) without
//!    a live database.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sqlx::postgres::PgPool;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::{Postgres, QueryBuilder, Row, Sqlite, SqliteConnection, Transaction};

use super::tree::WriteOnceViolation;

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

fn ensure_write_once_leaves(
    existing: &HashMap<[u8; 32], LeafRecord>,
    leaves: &[([u8; 32], LeafRecord)],
) -> anyhow::Result<()> {
    let mut incoming = HashMap::<[u8; 32], &LeafRecord>::with_capacity(leaves.len());
    for (key, record) in leaves {
        let prior = incoming.get(key).copied().or_else(|| existing.get(key));
        if prior.is_some_and(|prior| prior != record) {
            return Err(anyhow::Error::new(WriteOnceViolation { key: *key }));
        }
        incoming.insert(*key, record);
    }
    Ok(())
}

/// Read view over SMT nodes and leaves. Both a durable backend and the write
/// transaction it creates implement this contract, allowing the tree algorithm
/// to issue the same reads inside the transaction that eventually commits the
/// corresponding leaves and internal nodes.
#[allow(async_fn_in_trait)]
pub trait NodeRead: Send + Sync {
    /// Fetch internal-node hashes for `paths`. Absent paths are simply omitted
    /// from the result (the caller fills them with the empty-subtree hash).
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;

    /// Fetch leaf records for the given 32-byte tree keys.
    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>>;

    /// Fetch up to `limit` leaf records whose 32-byte key lies in the
    /// **inclusive** range `[lo, hi]`. Used to recompute deep nodes
    /// (`depth > LAZY_DEPTH`) from the canopy of leaves sharing a tree-key
    /// prefix — see ADR-0022. Keys are `shard_prefix ‖ suffix`, so a depth-`d`
    /// prefix maps to a contiguous key range (`[prefix‖0…, prefix‖1…]`), making
    /// this a single ordered scan. `limit` bounds the work: callers pass
    /// `cap + 1` so a return of more than `cap` rows signals an over-cap ("hot")
    /// canopy without scanning it in full.
    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>>;

    /// Every node with depth (== path length) `<= max_depth`, for the hot
    /// write-behind cache that keeps the upper levels resident.
    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;
}

/// Stable read snapshot returned by [`NodeBackend::begin_read`]. Multi-query
/// operations such as proof generation use this view so leaves, siblings, and
/// the root cannot come from different commits.
#[allow(async_fn_in_trait)]
pub trait NodeReadTransaction: NodeRead + Send {
    /// Release the snapshot after all reads complete.
    async fn finish(self) -> anyhow::Result<()>
    where
        Self: Sized;
}

/// Atomic write unit returned by [`NodeBackend::begin_write`]. All reads used
/// to construct an SMT batch and both sets of writes MUST go through this
/// value. Dropping it without `commit` rolls back durable implementations and
/// discards the staged in-memory state.
#[allow(async_fn_in_trait)]
pub trait NodeWriteTransaction: NodeRead + Send {
    /// Stage internal-node upserts (`path → hash`).
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()>;

    /// Stage new leaves. Existing identical records are harmless no-ops;
    /// differing records fail with [`WriteOnceViolation`].
    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()>;

    /// Atomically publish every staged read-modify-write effect.
    async fn commit(self) -> anyhow::Result<()>
    where
        Self: Sized;

    /// Explicitly discard staged changes and release writer ownership. Drop is
    /// still a panic/cancellation safety net, but ordinary error paths call this
    /// so neither an advisory lock nor SQLite's writer reservation lingers.
    async fn rollback(self) -> anyhow::Result<()>
    where
        Self: Sized;
}

/// Durable storage for SMT nodes and leaves. Reads are batch-oriented so the
/// tree layer can amortise round-trips. Writes are deliberately available only
/// through the associated transaction type: the API makes it impossible for
/// `PersistentSmt` to persist leaves and nodes on unrelated pool connections.
#[allow(async_fn_in_trait)]
pub trait NodeBackend: NodeRead + Send + Sync {
    type ReadTransaction: NodeReadTransaction;
    type WriteTransaction: NodeWriteTransaction;

    /// Begin a snapshot-consistent read unit. PostgreSQL uses a read-only
    /// repeatable-read transaction; SQLite uses a deferred read transaction.
    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction>;

    /// Audit H-4 / ADR-0039: begin an atomic, cross-process-serialised write
    /// transaction for the duration of an `update_batch`. It MUST own the
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
    /// PostgreSQL uses `pg_advisory_xact_lock`; SQLite uses `BEGIN IMMEDIATE`;
    /// the in-memory backend uses an async mutex plus a staged snapshot.
    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction>;
}

impl<B: NodeRead + ?Sized> NodeRead for Arc<B> {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        (**self).get_nodes(paths).await
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        (**self).get_leaves(keys).await
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        (**self).get_leaves_in_range(lo, hi, limit).await
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        (**self).load_hot(max_depth).await
    }
}

impl<B: NodeBackend> NodeBackend for Arc<B> {
    type ReadTransaction = B::ReadTransaction;
    type WriteTransaction = B::WriteTransaction;

    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction> {
        (**self).begin_read().await
    }

    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction> {
        (**self).begin_write().await
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

// ── packed bit-path codec (migration 0043) ──────────────────────────────────
//
// A [`NodePath`] is one byte per bit (each 0/1) in memory. On disk we store it
// as an explicit `depth` (the path length) plus `path_bits`: the bits packed
// MSB-first into `ceil(depth/8)` bytes, the final partial byte left-aligned.
// This shrinks the ≤255-byte node key to ≤32 bytes. The depth is carried
// separately (a `smallint` column) so the low bits of the last byte are
// unambiguous and `load_hot`'s `WHERE depth <= N` rides the PK index. The codec
// is purely physical — the path is never hashed — so node hashes, the root, and
// every proof are unchanged.

/// Pack a one-byte-per-bit path into `ceil(len/8)` MSB-first bytes (final byte
/// left-aligned, low bits zero). The path's `len()` (its depth) is stored
/// separately, so the caller must keep it to round-trip via [`unpack_bits`].
///
/// Errors if any byte is not exactly `0` or `1`: a [`NodePath`] is a bit-vector,
/// and masking a stray byte (e.g. `2` → `0`) would silently alias distinct paths
/// onto the same `path_bits` key — a persistence-boundary hazard for a ledger.
fn pack_bits(path: &NodePath) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(path.len().div_ceil(8));
    let mut byte = 0u8;
    let mut nbits = 0u8;
    for &b in path {
        anyhow::ensure!(b <= 1, "smt: NodePath byte must be a 0/1 bit, got {b}");
        byte = (byte << 1) | b;
        nbits += 1;
        if nbits == 8 {
            out.push(byte);
            byte = 0;
            nbits = 0;
        }
    }
    if nbits > 0 {
        out.push(byte << (8 - nbits));
    }
    Ok(out)
}

/// Inverse of [`pack_bits`]: expand `depth` MSB-first bits back to one byte per
/// bit. Reads only `depth` bits, so the final byte's padding is ignored.
fn unpack_bits(depth: usize, bits: &[u8]) -> NodePath {
    let mut out = Vec::with_capacity(depth);
    for i in 0..depth {
        out.push((bits[i / 8] >> (7 - (i % 8))) & 1);
    }
    out
}

// ── PostgreSQL backend ──────────────────────────────────────────────────────

/// Path-addressed Postgres storage over `smt_nodes` / `smt_leaves`.
#[derive(Clone)]
pub struct PgBackend {
    pool: PgPool,
}

impl PgBackend {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl NodeRead for PgBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        // Address each requested node by (depth, packed bits) and join those
        // pairs against the table — the multi-column form of `path = ANY(...)`.
        let depths: Vec<i16> = paths.iter().map(|p| p.len() as i16).collect();
        let bits: Vec<Vec<u8>> = paths.iter().map(pack_bits).collect::<anyhow::Result<_>>()?;
        let rows = sqlx::query(
            "SELECT n.depth, n.path_bits, n.hash FROM smt_nodes n \
             JOIN UNNEST($1::int2[], $2::bytea[]) AS q(depth, path_bits) \
               ON n.depth = q.depth AND n.path_bits = q.path_bits",
        )
        .bind(&depths)
        .bind(&bits)
        .fetch_all(&self.pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
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

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key >= $1 AND key <= $2 ORDER BY key LIMIT $3",
        )
        .bind(lo.to_vec())
        .bind(hi.to_vec())
        .bind(limit as i64)
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

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let rows = sqlx::query("SELECT depth, path_bits, hash FROM smt_nodes WHERE depth <= $1")
            .bind(max_depth as i16)
            .fetch_all(&self.pool)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
        Ok(out)
    }
}

/// PostgreSQL repeatable-read, read-only snapshot.
pub struct PgReadTransaction {
    tx: tokio::sync::Mutex<Transaction<'static, Postgres>>,
}

impl NodeRead for PgReadTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let depths: Vec<i16> = paths.iter().map(|p| p.len() as i16).collect();
        let bits: Vec<Vec<u8>> = paths.iter().map(pack_bits).collect::<anyhow::Result<_>>()?;
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT n.depth, n.path_bits, n.hash FROM smt_nodes n \
             JOIN UNNEST($1::int2[], $2::bytea[]) AS q(depth, path_bits) \
               ON n.depth = q.depth AND n.path_bits = q.path_bits",
        )
        .bind(&depths)
        .bind(&bits)
        .fetch_all(&mut **tx)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
        Ok(out)
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let owned: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key = ANY($1)",
        )
        .bind(owned)
        .fetch_all(&mut **tx)
        .await?;
        decode_pg_leaves(rows)
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key >= $1 AND key <= $2 ORDER BY key LIMIT $3",
        )
        .bind(lo.to_vec())
        .bind(hi.to_vec())
        .bind(limit as i64)
        .fetch_all(&mut **tx)
        .await?;
        decode_pg_leaves(rows)
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query("SELECT depth, path_bits, hash FROM smt_nodes WHERE depth <= $1")
            .bind(max_depth as i16)
            .fetch_all(&mut **tx)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
        Ok(out)
    }
}

impl NodeReadTransaction for PgReadTransaction {
    async fn finish(self) -> anyhow::Result<()> {
        self.tx.into_inner().commit().await?;
        Ok(())
    }
}

/// PostgreSQL write transaction. The SQLx transaction is behind an async
/// mutex solely because [`NodeRead`] uses `&self`; `PersistentSmt` drives it
/// sequentially. Every query still runs on the one transaction connection.
pub struct PgWriteTransaction {
    tx: tokio::sync::Mutex<Transaction<'static, Postgres>>,
}

impl NodeRead for PgWriteTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let depths: Vec<i16> = paths.iter().map(|p| p.len() as i16).collect();
        let bits: Vec<Vec<u8>> = paths.iter().map(pack_bits).collect::<anyhow::Result<_>>()?;
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT n.depth, n.path_bits, n.hash FROM smt_nodes n \
             JOIN UNNEST($1::int2[], $2::bytea[]) AS q(depth, path_bits) \
               ON n.depth = q.depth AND n.path_bits = q.path_bits",
        )
        .bind(&depths)
        .bind(&bits)
        .fetch_all(&mut **tx)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
        Ok(out)
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let owned: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key = ANY($1)",
        )
        .bind(owned)
        .fetch_all(&mut **tx)
        .await?;
        decode_pg_leaves(rows)
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key >= $1 AND key <= $2 ORDER BY key LIMIT $3",
        )
        .bind(lo.to_vec())
        .bind(hi.to_vec())
        .bind(limit as i64)
        .fetch_all(&mut **tx)
        .await?;
        decode_pg_leaves(rows)
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let mut tx = self.tx.lock().await;
        let rows = sqlx::query("SELECT depth, path_bits, hash FROM smt_nodes WHERE depth <= $1")
            .bind(max_depth as i16)
            .fetch_all(&mut **tx)
            .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let depth: i16 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
        Ok(out)
    }
}

impl NodeWriteTransaction for PgWriteTransaction {
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let depths: Vec<i16> = nodes.iter().map(|(p, _)| p.len() as i16).collect();
        let bits: Vec<Vec<u8>> = nodes
            .iter()
            .map(|(p, _)| pack_bits(p))
            .collect::<anyhow::Result<_>>()?;
        let hashes: Vec<Vec<u8>> = nodes.iter().map(|(_, h)| h.to_vec()).collect();
        let mut tx = self.tx.lock().await;
        sqlx::query(
            "INSERT INTO smt_nodes (depth, path_bits, hash) \
             SELECT * FROM UNNEST($1::int2[], $2::bytea[], $3::bytea[]) \
             ON CONFLICT (depth, path_bits) DO UPDATE SET hash = EXCLUDED.hash",
        )
        .bind(depths)
        .bind(bits)
        .bind(hashes)
        .execute(&mut **tx)
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
        let mut tx = self.tx.lock().await;
        let existing = decode_pg_leaves(
            sqlx::query(
                "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
                 FROM smt_leaves WHERE key = ANY($1)",
            )
            .bind(&keys)
            .fetch_all(&mut **tx)
            .await?,
        )?;
        ensure_write_once_leaves(&existing, leaves)?;
        sqlx::query(
            "INSERT INTO smt_leaves \
                 (key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash) \
             SELECT * FROM UNNEST($1::bytea[], $2::bytea[], $3::text[], $4::text[], $5::text[], $6::text[]) \
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(keys)
        .bind(value_hashes)
        .bind(shard_ids)
        .bind(parser_ids)
        .bind(versions)
        .bind(model_hashes)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn commit(self) -> anyhow::Result<()> {
        self.tx.into_inner().commit().await?;
        Ok(())
    }

    async fn rollback(self) -> anyhow::Result<()> {
        self.tx.into_inner().rollback().await?;
        Ok(())
    }
}

impl NodeBackend for PgBackend {
    type ReadTransaction = PgReadTransaction;
    type WriteTransaction = PgWriteTransaction;

    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction> {
        let tx = self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await?;
        Ok(PgReadTransaction {
            tx: tokio::sync::Mutex::new(tx),
        })
    }

    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction> {
        // Pin READ COMMITTED instead of inheriting an operator/session default.
        // Under REPEATABLE READ the advisory-lock statement could establish a
        // snapshot before it finishes waiting, and the subsequent SMT reads
        // could then miss the writer whose commit released the lock.
        let mut tx = self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        // Transaction-scoped lock: commit, rollback, cancellation, and process
        // death all release it. The following reads run under READ COMMITTED
        // after this statement, so a waiter observes the prior writer's commit.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SMT_WRITE_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        Ok(PgWriteTransaction {
            tx: tokio::sync::Mutex::new(tx),
        })
    }
}

fn decode_pg_leaves(
    rows: Vec<sqlx::postgres::PgRow>,
) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        let key: Vec<u8> = row.try_get("key")?;
        let value_hash: Vec<u8> = row.try_get("value_hash")?;
        out.insert(
            to_hash(&key)?,
            LeafRecord {
                value_hash: to_hash(&value_hash)?,
                shard_id: row.try_get("shard_id")?,
                parser_id: row.try_get("parser_id")?,
                canonical_parser_version: row.try_get("canonical_parser_version")?,
                model_hash: row.try_get("model_hash")?,
            },
        );
    }
    Ok(out)
}

// ── SQLite backend ──────────────────────────────────────────────────────────

/// Keep well below SQLite's host-parameter ceiling while retaining batched
/// probes and upserts. The exact engine ceiling varies by build.
const SQLITE_BATCH_ROWS: usize = 100;
const SQLITE_MIGRATIONS_TABLE: &str = "_olympus_smt_migrations";

fn validate_plain_sqlite_filename(path: &Path) -> anyhow::Result<()> {
    let rendered = path.as_os_str().to_string_lossy();
    let lower = rendered.to_ascii_lowercase();
    anyhow::ensure!(
        !rendered.is_empty()
            && rendered != ":memory:"
            && !lower.starts_with("file:")
            && !rendered.contains('?'),
        "smt sqlite: a plain durable file path is required; SQLite URI filenames are forbidden"
    );
    Ok(())
}

/// Optional SQLite storage for the SMT tables only. Olympus's broader
/// application schema remains PostgreSQL-specific; this backend is a narrow
/// portability boundary around `smt_nodes` and `smt_leaves`.
#[derive(Clone)]
pub struct SqliteBackend {
    pool: SqlitePool,
}

impl SqliteBackend {
    /// Open or create a SQLite database, apply the SMT-only migrations, and
    /// configure durable rollback-journal semantics. WAL is intentionally not
    /// enabled here: the currently resolved SQLite library is not a release on
    /// which Olympus has qualified multi-connection WAL recovery.
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            database_url.starts_with("sqlite:"),
            "smt sqlite: URL must use the sqlite: scheme"
        );
        anyhow::ensure!(
            !database_url.contains('?'),
            "smt sqlite: URI options are forbidden; use a plain sqlite: URL or connect_path"
        );
        anyhow::ensure!(
            !database_url.contains(":memory:"),
            "smt sqlite: a durable file-backed database is required"
        );
        let options = SqliteConnectOptions::from_str(database_url)?;
        // Validate again after SQLx percent-decodes the database component;
        // otherwise `%3Fvfs%3Dunix-none` can bypass the raw URL check.
        validate_plain_sqlite_filename(options.get_filename())?;
        Self::connect_options(options).await
    }

    /// Path-based counterpart to [`connect`](Self::connect), convenient for
    /// desktop app-data directories without URL escaping concerns.
    pub async fn connect_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        validate_plain_sqlite_filename(path)?;
        Self::connect_options(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
    }

    async fn connect_options(options: SqliteConnectOptions) -> anyhow::Result<Self> {
        let options = options
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Delete)
            .locking_mode(SqliteLockingMode::Normal)
            .synchronous(SqliteSynchronous::Extra)
            .pragma("trusted_schema", "OFF")
            .pragma("read_uncommitted", "OFF")
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    /// Finish opening the internally configured pool and apply the versioned
    /// SMT schema. This deliberately stays private: SQLite durability PRAGMAs
    /// such as `synchronous` are connection-local, so accepting an arbitrary
    /// caller pool could validate one connection while later checking out a
    /// differently configured one.
    async fn from_pool(pool: SqlitePool) -> anyhow::Result<Self> {
        validate_sqlite_configuration(&pool).await?;
        let mut migrator = sqlx::migrate!("../migrations-sqlite");
        migrator.dangerous_set_table_name(SQLITE_MIGRATIONS_TABLE);
        migrator.run(&pool).await?;
        Ok(Self { pool })
    }

    #[cfg(test)]
    fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

async fn validate_sqlite_configuration(pool: &SqlitePool) -> anyhow::Result<()> {
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        journal_mode.eq_ignore_ascii_case("delete"),
        "smt sqlite: journal_mode must be DELETE, got {journal_mode}"
    );
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        synchronous == 3,
        "smt sqlite: synchronous must be EXTRA (3), got {synchronous}"
    );
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(foreign_keys == 1, "smt sqlite: foreign_keys must be ON");
    let trusted_schema: i64 = sqlx::query_scalar("PRAGMA trusted_schema")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        trusted_schema == 0,
        "smt sqlite: trusted_schema must be OFF"
    );
    let read_uncommitted: i64 = sqlx::query_scalar("PRAGMA read_uncommitted")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        read_uncommitted == 0,
        "smt sqlite: read_uncommitted must be OFF"
    );
    let locking_mode: String = sqlx::query_scalar("PRAGMA locking_mode")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        locking_mode.eq_ignore_ascii_case("normal"),
        "smt sqlite: locking_mode must be NORMAL, got {locking_mode}"
    );
    let busy_timeout_ms: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        (1..=60_000).contains(&busy_timeout_ms),
        "smt sqlite: busy_timeout must be 1..=60000 ms, got {busy_timeout_ms}"
    );
    Ok(())
}

async fn sqlite_get_nodes(
    conn: &mut SqliteConnection,
    paths: &[NodePath],
) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
    let packed: Vec<(i64, Vec<u8>)> = paths
        .iter()
        .map(|p| Ok((p.len() as i64, pack_bits(p)?)))
        .collect::<anyhow::Result<_>>()?;
    let mut out = HashMap::new();
    for chunk in packed.chunks(SQLITE_BATCH_ROWS) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT depth, path_bits, hash FROM smt_nodes \
             WHERE (depth, path_bits) IN",
        );
        query.push_tuples(chunk, |mut row, (depth, bits)| {
            row.push_bind(*depth).push_bind(bits.clone());
        });
        let rows = query.build().fetch_all(&mut *conn).await?;
        out.reserve(rows.len());
        for row in rows {
            let depth: i64 = row.try_get("depth")?;
            let path_bits: Vec<u8> = row.try_get("path_bits")?;
            let hash: Vec<u8> = row.try_get("hash")?;
            out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
        }
    }
    Ok(out)
}

async fn sqlite_get_leaves(
    conn: &mut SqliteConnection,
    keys: &[[u8; 32]],
) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
    let mut out = HashMap::new();
    for chunk in keys.chunks(SQLITE_BATCH_ROWS) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
             FROM smt_leaves WHERE key IN (",
        );
        {
            let mut values = query.separated(", ");
            for key in chunk {
                values.push_bind(key.to_vec());
            }
        }
        query.push(")");
        let rows = query.build().fetch_all(&mut *conn).await?;
        out.extend(decode_sqlite_leaves(rows)?);
    }
    Ok(out)
}

async fn sqlite_get_leaves_in_range(
    conn: &mut SqliteConnection,
    lo: [u8; 32],
    hi: [u8; 32],
    limit: usize,
) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
    let rows = sqlx::query(
        "SELECT key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash \
         FROM smt_leaves WHERE key >= ?1 AND key <= ?2 ORDER BY key LIMIT ?3",
    )
    .bind(lo.to_vec())
    .bind(hi.to_vec())
    .bind(limit as i64)
    .fetch_all(&mut *conn)
    .await?;
    decode_sqlite_leaves(rows)
}

async fn sqlite_load_hot(
    conn: &mut SqliteConnection,
    max_depth: usize,
) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
    let rows = sqlx::query("SELECT depth, path_bits, hash FROM smt_nodes WHERE depth <= ?1")
        .bind(max_depth as i64)
        .fetch_all(&mut *conn)
        .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        let depth: i64 = row.try_get("depth")?;
        let path_bits: Vec<u8> = row.try_get("path_bits")?;
        let hash: Vec<u8> = row.try_get("hash")?;
        out.insert(unpack_bits(depth as usize, &path_bits), to_hash(&hash)?);
    }
    Ok(out)
}

async fn sqlite_put_nodes(
    conn: &mut SqliteConnection,
    nodes: &[(NodePath, [u8; 32])],
) -> anyhow::Result<()> {
    let packed: Vec<(i64, Vec<u8>, Vec<u8>)> = nodes
        .iter()
        .map(|(path, hash)| Ok((path.len() as i64, pack_bits(path)?, hash.to_vec())))
        .collect::<anyhow::Result<_>>()?;
    for chunk in packed.chunks(SQLITE_BATCH_ROWS) {
        let mut query =
            QueryBuilder::<Sqlite>::new("INSERT INTO smt_nodes (depth, path_bits, hash) ");
        query.push_values(chunk, |mut row, (depth, bits, hash)| {
            row.push_bind(*depth)
                .push_bind(bits.clone())
                .push_bind(hash.clone());
        });
        query.push(" ON CONFLICT (depth, path_bits) DO UPDATE SET hash = excluded.hash");
        query.build().execute(&mut *conn).await?;
    }
    Ok(())
}

async fn sqlite_put_leaves(
    conn: &mut SqliteConnection,
    leaves: &[([u8; 32], LeafRecord)],
) -> anyhow::Result<()> {
    let keys: Vec<[u8; 32]> = leaves.iter().map(|(key, _)| *key).collect();
    let existing = sqlite_get_leaves(conn, &keys).await?;
    ensure_write_once_leaves(&existing, leaves)?;
    for chunk in leaves.chunks(SQLITE_BATCH_ROWS) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "INSERT INTO smt_leaves \
             (key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash) ",
        );
        query.push_values(chunk, |mut row, (key, record)| {
            row.push_bind(key.to_vec())
                .push_bind(record.value_hash.to_vec())
                .push_bind(record.shard_id.clone())
                .push_bind(record.parser_id.clone())
                .push_bind(record.canonical_parser_version.clone())
                .push_bind(record.model_hash.clone());
        });
        query.push(" ON CONFLICT (key) DO NOTHING");
        query.build().execute(&mut *conn).await?;
    }
    Ok(())
}

fn decode_sqlite_leaves(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        let key: Vec<u8> = row.try_get("key")?;
        let value_hash: Vec<u8> = row.try_get("value_hash")?;
        out.insert(
            to_hash(&key)?,
            LeafRecord {
                value_hash: to_hash(&value_hash)?,
                shard_id: row.try_get("shard_id")?,
                parser_id: row.try_get("parser_id")?,
                canonical_parser_version: row.try_get("canonical_parser_version")?,
                model_hash: row.try_get("model_hash")?,
            },
        );
    }
    Ok(out)
}

impl NodeRead for SqliteBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let mut conn = self.pool.acquire().await?;
        sqlite_get_nodes(&mut conn, paths).await
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let mut conn = self.pool.acquire().await?;
        sqlite_get_leaves(&mut conn, keys).await
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut conn = self.pool.acquire().await?;
        sqlite_get_leaves_in_range(&mut conn, lo, hi, limit).await
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let mut conn = self.pool.acquire().await?;
        sqlite_load_hot(&mut conn, max_depth).await
    }
}

/// SQLite deferred read transaction. Its first query establishes the snapshot;
/// subsequent proof reads stay on the same connection until `finish`.
pub struct SqliteReadTransaction {
    tx: tokio::sync::Mutex<Transaction<'static, Sqlite>>,
}

impl NodeRead for SqliteReadTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let mut tx = self.tx.lock().await;
        sqlite_get_nodes(&mut tx, paths).await
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let mut tx = self.tx.lock().await;
        sqlite_get_leaves(&mut tx, keys).await
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut tx = self.tx.lock().await;
        sqlite_get_leaves_in_range(&mut tx, lo, hi, limit).await
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let mut tx = self.tx.lock().await;
        sqlite_load_hot(&mut tx, max_depth).await
    }
}

impl NodeReadTransaction for SqliteReadTransaction {
    async fn finish(self) -> anyhow::Result<()> {
        self.tx.into_inner().commit().await?;
        Ok(())
    }
}

/// SQLite transaction begun with `BEGIN IMMEDIATE` so the first SMT read is
/// already protected by cross-process writer ownership.
pub struct SqliteWriteTransaction {
    tx: tokio::sync::Mutex<Transaction<'static, Sqlite>>,
}

impl NodeRead for SqliteWriteTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let mut tx = self.tx.lock().await;
        sqlite_get_nodes(&mut tx, paths).await
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let mut tx = self.tx.lock().await;
        sqlite_get_leaves(&mut tx, keys).await
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut tx = self.tx.lock().await;
        sqlite_get_leaves_in_range(&mut tx, lo, hi, limit).await
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let mut tx = self.tx.lock().await;
        sqlite_load_hot(&mut tx, max_depth).await
    }
}

impl NodeWriteTransaction for SqliteWriteTransaction {
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        let mut tx = self.tx.lock().await;
        sqlite_put_nodes(&mut tx, nodes).await
    }

    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
        let mut tx = self.tx.lock().await;
        sqlite_put_leaves(&mut tx, leaves).await
    }

    async fn commit(self) -> anyhow::Result<()> {
        self.tx.into_inner().commit().await?;
        Ok(())
    }

    async fn rollback(self) -> anyhow::Result<()> {
        self.tx.into_inner().rollback().await?;
        Ok(())
    }
}

impl NodeBackend for SqliteBackend {
    type ReadTransaction = SqliteReadTransaction;
    type WriteTransaction = SqliteWriteTransaction;

    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction> {
        let tx = self.pool.begin_with("BEGIN").await?;
        Ok(SqliteReadTransaction {
            tx: tokio::sync::Mutex::new(tx),
        })
    }

    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction> {
        let tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Ok(SqliteWriteTransaction {
            tx: tokio::sync::Mutex::new(tx),
        })
    }
}

/// Runtime-selectable SMT storage without erasing the concrete SQLx database
/// types. Each variant retains its native SQL and indexing strategy while
/// presenting one semantic backend type to `PersistentSmt`.
#[derive(Clone)]
pub enum SmtStorageBackend {
    /// PostgreSQL with native array batching and transaction advisory locking.
    Postgres(PgBackend),
    /// SQLite with chunked statements and `BEGIN IMMEDIATE` serialization.
    Sqlite(SqliteBackend),
}

/// Read-snapshot counterpart to [`SmtStorageBackend`].
pub enum SmtReadTransaction {
    /// PostgreSQL read-only repeatable-read transaction.
    Postgres(PgReadTransaction),
    /// SQLite deferred read transaction.
    Sqlite(SqliteReadTransaction),
}

/// Write-transaction counterpart to [`SmtStorageBackend`].
pub enum SmtWriteTransaction {
    /// PostgreSQL transaction.
    Postgres(PgWriteTransaction),
    /// SQLite transaction.
    Sqlite(SqliteWriteTransaction),
}

impl From<PgBackend> for SmtStorageBackend {
    fn from(value: PgBackend) -> Self {
        Self::Postgres(value)
    }
}

impl From<SqliteBackend> for SmtStorageBackend {
    fn from(value: SqliteBackend) -> Self {
        Self::Sqlite(value)
    }
}

impl NodeRead for SmtStorageBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(backend) => backend.get_nodes(paths).await,
            Self::Sqlite(backend) => backend.get_nodes(paths).await,
        }
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(backend) => backend.get_leaves(keys).await,
            Self::Sqlite(backend) => backend.get_leaves(keys).await,
        }
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(backend) => backend.get_leaves_in_range(lo, hi, limit).await,
            Self::Sqlite(backend) => backend.get_leaves_in_range(lo, hi, limit).await,
        }
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(backend) => backend.load_hot(max_depth).await,
            Self::Sqlite(backend) => backend.load_hot(max_depth).await,
        }
    }
}

impl NodeRead for SmtReadTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(tx) => tx.get_nodes(paths).await,
            Self::Sqlite(tx) => tx.get_nodes(paths).await,
        }
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(tx) => tx.get_leaves(keys).await,
            Self::Sqlite(tx) => tx.get_leaves(keys).await,
        }
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(tx) => tx.get_leaves_in_range(lo, hi, limit).await,
            Self::Sqlite(tx) => tx.get_leaves_in_range(lo, hi, limit).await,
        }
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(tx) => tx.load_hot(max_depth).await,
            Self::Sqlite(tx) => tx.load_hot(max_depth).await,
        }
    }
}

impl NodeReadTransaction for SmtReadTransaction {
    async fn finish(self) -> anyhow::Result<()> {
        match self {
            Self::Postgres(tx) => tx.finish().await,
            Self::Sqlite(tx) => tx.finish().await,
        }
    }
}

impl NodeRead for SmtWriteTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(tx) => tx.get_nodes(paths).await,
            Self::Sqlite(tx) => tx.get_nodes(paths).await,
        }
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(tx) => tx.get_leaves(keys).await,
            Self::Sqlite(tx) => tx.get_leaves(keys).await,
        }
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        match self {
            Self::Postgres(tx) => tx.get_leaves_in_range(lo, hi, limit).await,
            Self::Sqlite(tx) => tx.get_leaves_in_range(lo, hi, limit).await,
        }
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        match self {
            Self::Postgres(tx) => tx.load_hot(max_depth).await,
            Self::Sqlite(tx) => tx.load_hot(max_depth).await,
        }
    }
}

impl NodeWriteTransaction for SmtWriteTransaction {
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        match self {
            Self::Postgres(tx) => tx.put_nodes(nodes).await,
            Self::Sqlite(tx) => tx.put_nodes(nodes).await,
        }
    }

    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
        match self {
            Self::Postgres(tx) => tx.put_leaves(leaves).await,
            Self::Sqlite(tx) => tx.put_leaves(leaves).await,
        }
    }

    async fn commit(self) -> anyhow::Result<()> {
        match self {
            Self::Postgres(tx) => tx.commit().await,
            Self::Sqlite(tx) => tx.commit().await,
        }
    }

    async fn rollback(self) -> anyhow::Result<()> {
        match self {
            Self::Postgres(tx) => tx.rollback().await,
            Self::Sqlite(tx) => tx.rollback().await,
        }
    }
}

impl NodeBackend for SmtStorageBackend {
    type ReadTransaction = SmtReadTransaction;
    type WriteTransaction = SmtWriteTransaction;

    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction> {
        match self {
            Self::Postgres(backend) => backend.begin_read().await.map(SmtReadTransaction::Postgres),
            Self::Sqlite(backend) => backend.begin_read().await.map(SmtReadTransaction::Sqlite),
        }
    }

    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction> {
        match self {
            Self::Postgres(backend) => backend
                .begin_write()
                .await
                .map(SmtWriteTransaction::Postgres),
            Self::Sqlite(backend) => backend.begin_write().await.map(SmtWriteTransaction::Sqlite),
        }
    }
}

// ── In-memory backend (tests / parity) ────────────────────────────────────────

/// In-memory `NodeBackend` used by parity tests. A write transaction clones the
/// committed state after acquiring the writer permit and publishes the staged
/// maps together under one `RwLock` only on commit.
#[derive(Debug, Clone, Default)]
struct MemState {
    nodes: HashMap<NodePath, [u8; 32]>,
    leaves: HashMap<[u8; 32], LeafRecord>,
}

struct MemInner {
    state: RwLock<MemState>,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
pub struct MemBackend {
    inner: Arc<MemInner>,
}

impl Default for MemBackend {
    fn default() -> Self {
        Self {
            inner: Arc::new(MemInner {
                state: RwLock::new(MemState::default()),
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
            }),
        }
    }
}

impl MemBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of internal-node entries currently held. Read-only
    /// introspection aid for benchmarks / storage sizing (the production
    /// `PgBackend` exposes the same figure as `SELECT count(*) FROM smt_nodes`).
    pub fn node_count(&self) -> usize {
        self.inner.state.read().unwrap().nodes.len()
    }

    /// Number of leaf records currently held — the persistent analogue of
    /// `SELECT count(*) FROM smt_leaves`.
    pub fn leaf_count(&self) -> usize {
        self.inner.state.read().unwrap().leaves.len()
    }

    /// Number of materialised internal nodes strictly deeper than `depth`
    /// (path length `> depth`). Introspection aid for the lazy deep-node tests
    /// (ADR-0022): the persistent analogue of
    /// `SELECT count(*) FROM smt_nodes WHERE depth > $1`.
    pub fn node_count_deeper_than(&self, depth: usize) -> usize {
        self.inner
            .state
            .read()
            .unwrap()
            .nodes
            .keys()
            .filter(|p| p.len() > depth)
            .count()
    }
}

impl NodeRead for MemBackend {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let g = self.inner.state.read().unwrap();
        Ok(paths
            .iter()
            .filter_map(|p| g.nodes.get(p).map(|h| (p.clone(), *h)))
            .collect())
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let g = self.inner.state.read().unwrap();
        Ok(keys
            .iter()
            .filter_map(|k| g.leaves.get(k).map(|r| (*k, r.clone())))
            .collect())
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let g = self.inner.state.read().unwrap();
        // Match the Pg `ORDER BY key LIMIT n` so the capped subset is
        // deterministic (the over-cap check only needs the count, but a stable
        // subset keeps Mem/Pg parity for any future use).
        let mut keys: Vec<&[u8; 32]> = g.leaves.keys().filter(|k| **k >= lo && **k <= hi).collect();
        keys.sort_unstable();
        Ok(keys
            .into_iter()
            .take(limit)
            .map(|k| (*k, g.leaves[k].clone()))
            .collect())
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let g = self.inner.state.read().unwrap();
        Ok(g.nodes
            .iter()
            .filter(|(p, _)| p.len() <= max_depth)
            .map(|(p, h)| (p.clone(), *h))
            .collect())
    }
}

/// Immutable in-memory snapshot used by proof tests.
pub struct MemReadTransaction {
    state: MemState,
}

impl NodeRead for MemReadTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        Ok(paths
            .iter()
            .filter_map(|path| self.state.nodes.get(path).map(|hash| (path.clone(), *hash)))
            .collect())
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        Ok(keys
            .iter()
            .filter_map(|key| {
                self.state
                    .leaves
                    .get(key)
                    .map(|record| (*key, record.clone()))
            })
            .collect())
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let mut keys: Vec<&[u8; 32]> = self
            .state
            .leaves
            .keys()
            .filter(|key| **key >= lo && **key <= hi)
            .collect();
        keys.sort_unstable();
        Ok(keys
            .into_iter()
            .take(limit)
            .map(|key| (*key, self.state.leaves[key].clone()))
            .collect())
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        Ok(self
            .state
            .nodes
            .iter()
            .filter(|(path, _)| path.len() <= max_depth)
            .map(|(path, hash)| (path.clone(), *hash))
            .collect())
    }
}

impl NodeReadTransaction for MemReadTransaction {
    async fn finish(self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Staged in-memory transaction used by deterministic parity tests.
pub struct MemWriteTransaction {
    inner: Arc<MemInner>,
    staged: RwLock<MemState>,
    _permit: tokio::sync::OwnedMutexGuard<()>,
}

impl NodeRead for MemWriteTransaction {
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let state = self.staged.read().unwrap();
        Ok(paths
            .iter()
            .filter_map(|path| state.nodes.get(path).map(|hash| (path.clone(), *hash)))
            .collect())
    }

    async fn get_leaves(&self, keys: &[[u8; 32]]) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let state = self.staged.read().unwrap();
        Ok(keys
            .iter()
            .filter_map(|key| state.leaves.get(key).map(|record| (*key, record.clone())))
            .collect())
    }

    async fn get_leaves_in_range(
        &self,
        lo: [u8; 32],
        hi: [u8; 32],
        limit: usize,
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        let state = self.staged.read().unwrap();
        let mut keys: Vec<&[u8; 32]> = state
            .leaves
            .keys()
            .filter(|key| **key >= lo && **key <= hi)
            .collect();
        keys.sort_unstable();
        Ok(keys
            .into_iter()
            .take(limit)
            .map(|key| (*key, state.leaves[key].clone()))
            .collect())
    }

    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>> {
        let state = self.staged.read().unwrap();
        Ok(state
            .nodes
            .iter()
            .filter(|(path, _)| path.len() <= max_depth)
            .map(|(path, hash)| (path.clone(), *hash))
            .collect())
    }
}

impl NodeWriteTransaction for MemWriteTransaction {
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()> {
        let mut state = self.staged.write().unwrap();
        for (path, hash) in nodes {
            state.nodes.insert(path.clone(), *hash);
        }
        Ok(())
    }

    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()> {
        let mut state = self.staged.write().unwrap();
        ensure_write_once_leaves(&state.leaves, leaves)?;
        for (key, record) in leaves {
            state.leaves.entry(*key).or_insert_with(|| record.clone());
        }
        Ok(())
    }

    async fn commit(self) -> anyhow::Result<()> {
        let staged = self
            .staged
            .into_inner()
            .map_err(|_| anyhow::anyhow!("smt: poisoned in-memory transaction"))?;
        *self.inner.state.write().unwrap() = staged;
        Ok(())
    }

    async fn rollback(self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl NodeBackend for MemBackend {
    type ReadTransaction = MemReadTransaction;
    type WriteTransaction = MemWriteTransaction;

    async fn begin_read(&self) -> anyhow::Result<Self::ReadTransaction> {
        Ok(MemReadTransaction {
            state: self.inner.state.read().unwrap().clone(),
        })
    }

    async fn begin_write(&self) -> anyhow::Result<Self::WriteTransaction> {
        let permit = self.inner.write_lock.clone().lock_owned().await;
        let staged = self.inner.state.read().unwrap().clone();
        Ok(MemWriteTransaction {
            inner: self.inner.clone(),
            staged: RwLock::new(staged),
            _permit: permit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mem_backend_counts_reflect_puts() {
        let b = MemBackend::new();
        // Empty backend counts nothing.
        assert_eq!(b.node_count(), 0);
        assert_eq!(b.leaf_count(), 0);

        // One atomic transaction publishes both the node and leaf.
        let tx = b.begin_write().await.unwrap();
        tx.put_nodes(&[(vec![0u8, 1, 0], [7u8; 32])]).await.unwrap();
        tx.put_leaves(&[(
            [9u8; 32],
            LeafRecord {
                value_hash: [1u8; 32],
                shard_id: "s".into(),
                parser_id: "p".into(),
                canonical_parser_version: "v1".into(),
                model_hash: "m".into(),
            },
        )])
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(b.node_count(), 1);
        assert_eq!(b.leaf_count(), 1);

        // Re-putting the same paths/keys upserts in place — no double-count.
        let tx = b.begin_write().await.unwrap();
        tx.put_nodes(&[(vec![0u8, 1, 0], [8u8; 32])]).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(b.node_count(), 1);
    }

    #[tokio::test]
    async fn mem_backend_rollback_discards_all_staged_rows() {
        let backend = MemBackend::new();
        let tx = backend.begin_write().await.unwrap();
        tx.put_nodes(&[(vec![1], [3u8; 32])]).await.unwrap();
        tx.put_leaves(&[(
            [4u8; 32],
            LeafRecord {
                value_hash: [5u8; 32],
                shard_id: "s".into(),
                parser_id: "p".into(),
                canonical_parser_version: "v1".into(),
                model_hash: "m".into(),
            },
        )])
        .await
        .unwrap();
        tx.rollback().await.unwrap();

        assert_eq!(backend.node_count(), 0);
        assert_eq!(backend.leaf_count(), 0);
    }

    #[tokio::test]
    async fn mem_backend_leaf_records_are_write_once() {
        let backend = MemBackend::new();
        let key = [8u8; 32];
        let original = LeafRecord {
            value_hash: [9u8; 32],
            shard_id: "s".into(),
            parser_id: "p".into(),
            canonical_parser_version: "v1".into(),
            model_hash: "m".into(),
        };

        let tx = backend.begin_write().await.unwrap();
        tx.put_leaves(&[(key, original.clone())]).await.unwrap();
        tx.commit().await.unwrap();

        let tx = backend.begin_write().await.unwrap();
        tx.put_leaves(&[(key, original.clone())]).await.unwrap();
        tx.commit().await.unwrap();

        let mut conflict = original.clone();
        conflict.model_hash = "different".into();
        let tx = backend.begin_write().await.unwrap();
        let error = tx.put_leaves(&[(key, conflict)]).await.unwrap_err();
        assert!(error.downcast_ref::<WriteOnceViolation>().is_some());
        tx.rollback().await.unwrap();
        assert_eq!(backend.get_leaves(&[key]).await.unwrap()[&key], original);
    }

    #[tokio::test]
    async fn sqlite_factory_pins_durability_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SqliteBackend::connect_path(dir.path().join("pragmas.sqlite"))
            .await
            .unwrap();
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(backend.pool())
            .await
            .unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(backend.pool())
            .await
            .unwrap();
        let trusted_schema: i64 = sqlx::query_scalar("PRAGMA trusted_schema")
            .fetch_one(backend.pool())
            .await
            .unwrap();
        let migration_tables: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_schema \
             WHERE type = 'table' AND name = ?1",
        )
        .bind(SQLITE_MIGRATIONS_TABLE)
        .fetch_one(backend.pool())
        .await
        .unwrap();
        assert_eq!(journal_mode, "delete");
        assert_eq!(synchronous, 3, "SQLite EXTRA synchronous must stay enabled");
        assert_eq!(trusted_schema, 0);
        assert_eq!(migration_tables, 1);
    }

    #[tokio::test]
    async fn sqlite_from_pool_rejects_insecure_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let options = SqliteConnectOptions::new()
            .filename(dir.path().join("insecure.sqlite"))
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Delete)
            .synchronous(SqliteSynchronous::Extra);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        let error = match SqliteBackend::from_pool(pool.clone()).await {
            Ok(_) => panic!("insecure caller-configured pool must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("trusted_schema"));
        pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_schema_rejects_noncanonical_values() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SqliteBackend::connect_path(dir.path().join("constraints.sqlite"))
            .await
            .unwrap();

        // depth=3 permits only the top three bits; A1 has a non-zero padding bit.
        let bad_path =
            sqlx::query("INSERT INTO smt_nodes (depth, path_bits, hash) VALUES (?1, ?2, ?3)")
                .bind(3_i64)
                .bind(vec![0xA1_u8])
                .bind(vec![0_u8; 32])
                .execute(backend.pool())
                .await;
        assert!(bad_path.is_err());

        let bad_provenance = sqlx::query(
            "INSERT INTO smt_leaves \
             (key, value_hash, shard_id, parser_id, canonical_parser_version, model_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .bind("contains\0nul")
        .bind("p")
        .bind("v1")
        .bind("m")
        .execute(backend.pool())
        .await;
        assert!(bad_provenance.is_err());
    }

    // ── packed bit-path codec (migration 0043) ──────────────────────────────

    /// Build a `depth`-bit one-byte-per-bit path with a chosen bit pattern.
    fn path_pattern(depth: usize, pat: u8) -> NodePath {
        (0..depth)
            .map(|i| match pat {
                0 => 0u8,                       // all zeros
                1 => 1u8,                       // all ones
                2 => (i % 2) as u8,             // alternating 0101…
                3 => ((i + 1) % 2) as u8,       // alternating 1010…
                _ => (((i / 8) + i) % 2) as u8, // mixed across byte boundaries
            })
            .collect()
    }

    #[test]
    fn pack_unpack_is_a_bijection_over_all_depths() {
        // Nodes live at depths 0..=255; include 256 for headroom. For every
        // depth and bit pattern, packing then unpacking must reproduce the path
        // exactly, and the packed form must be ceil(depth/8) bytes (≤ 32).
        for depth in 0..=256usize {
            for pat in 0..5u8 {
                let path = path_pattern(depth, pat);
                let packed = pack_bits(&path).expect("valid 0/1 path packs");
                assert_eq!(
                    packed.len(),
                    depth.div_ceil(8),
                    "packed length wrong at depth {depth}"
                );
                assert!(packed.len() <= 32, "packed key exceeds 32 bytes");
                assert_eq!(
                    unpack_bits(depth, &packed),
                    path,
                    "round-trip mismatch at depth {depth}, pattern {pat}"
                );
            }
        }
    }

    #[test]
    fn pack_handles_empty_root_path_and_partial_final_byte() {
        // The global root is the empty path → empty packed bits.
        assert!(pack_bits(&Vec::new()).unwrap().is_empty());
        assert!(unpack_bits(0, &[]).is_empty());

        // A 3-bit path `1,0,1` packs MSB-first, left-aligned: 0b1010_0000.
        let packed = pack_bits(&vec![1, 0, 1]).unwrap();
        assert_eq!(packed, vec![0b1010_0000]);
        // Unpacking reads only the first 3 bits, ignoring the zero padding.
        assert_eq!(unpack_bits(3, &packed), vec![1, 0, 1]);
    }

    #[test]
    fn pack_rejects_non_binary_path_bytes() {
        // A NodePath is a bit-vector: any byte other than 0/1 is rejected rather
        // than masked, so distinct paths can't silently alias on disk.
        assert!(pack_bits(&vec![0, 1, 2]).is_err());
        assert!(pack_bits(&vec![255]).is_err());
        assert!(pack_bits(&vec![0, 1, 0, 1]).is_ok());
    }
}
