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
    pub parser_id: String,
    pub canonical_parser_version: String,
}

/// Durable storage for SMT nodes and leaves. Methods are batch-oriented so the
/// tree layer can amortise round-trips across a whole insert/proof batch.
#[allow(async_fn_in_trait)]
pub trait NodeBackend: Send + Sync {
    /// Fetch internal-node hashes for `paths`. Absent paths are simply omitted
    /// from the result (the caller fills them with the empty-subtree hash).
    async fn get_nodes(&self, paths: &[NodePath]) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;

    /// Fetch leaf records for the given 32-byte tree keys.
    async fn get_leaves(
        &self,
        keys: &[[u8; 32]],
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>>;

    /// Upsert internal nodes (`path → hash`).
    async fn put_nodes(&self, nodes: &[(NodePath, [u8; 32])]) -> anyhow::Result<()>;

    /// Upsert leaves.
    async fn put_leaves(&self, leaves: &[([u8; 32], LeafRecord)]) -> anyhow::Result<()>;

    /// Every node with depth (== path length) `<= max_depth`, for the hot
    /// write-behind cache that keeps the upper levels resident.
    async fn load_hot(&self, max_depth: usize) -> anyhow::Result<HashMap<NodePath, [u8; 32]>>;
}

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

    async fn get_leaves(
        &self,
        keys: &[[u8; 32]],
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let owned: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
        let rows = sqlx::query(
            "SELECT key, value_hash, parser_id, canonical_parser_version \
             FROM smt_leaves WHERE key = ANY($1)",
        )
        .bind(owned)
        .fetch_all(&self.pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let key: Vec<u8> = row.try_get("key")?;
            let value_hash: Vec<u8> = row.try_get("value_hash")?;
            let parser_id: String = row.try_get("parser_id")?;
            let canonical_parser_version: String = row.try_get("canonical_parser_version")?;
            out.insert(
                to_hash(&key)?,
                LeafRecord {
                    value_hash: to_hash(&value_hash)?,
                    parser_id,
                    canonical_parser_version,
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
        let value_hashes: Vec<Vec<u8>> = leaves.iter().map(|(_, r)| r.value_hash.to_vec()).collect();
        let parser_ids: Vec<String> = leaves.iter().map(|(_, r)| r.parser_id.clone()).collect();
        let versions: Vec<String> = leaves
            .iter()
            .map(|(_, r)| r.canonical_parser_version.clone())
            .collect();
        sqlx::query(
            "INSERT INTO smt_leaves (key, value_hash, parser_id, canonical_parser_version) \
             SELECT * FROM UNNEST($1::bytea[], $2::bytea[], $3::text[], $4::text[]) \
             ON CONFLICT (key) DO UPDATE SET \
                 value_hash = EXCLUDED.value_hash, \
                 parser_id = EXCLUDED.parser_id, \
                 canonical_parser_version = EXCLUDED.canonical_parser_version",
        )
        .bind(keys)
        .bind(value_hashes)
        .bind(parser_ids)
        .bind(versions)
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
}

// ── In-memory backend (tests / parity) ────────────────────────────────────────

/// In-memory `NodeBackend` backed by two maps behind a `Mutex`. Used by the
/// tree's parity tests so the algorithm can be exercised without a database.
#[derive(Default)]
pub struct MemBackend {
    nodes: Mutex<HashMap<NodePath, [u8; 32]>>,
    leaves: Mutex<HashMap<[u8; 32], LeafRecord>>,
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

    async fn get_leaves(
        &self,
        keys: &[[u8; 32]],
    ) -> anyhow::Result<HashMap<[u8; 32], LeafRecord>> {
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
}
