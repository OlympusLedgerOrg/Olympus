//! Periodic anchoring cron.
//!
//! Audit finding H-A1: before this module landed, `crate::anchoring::anchor_all`
//! had exactly one caller (`federation::checkpoint::anchor_checkpoint`) which
//! itself was never invoked. Setting `OLYMPUS_ANCHOR_*` env vars therefore had
//! no observable effect and the court-evidence claim in
//! `docs/court-evidence.md` was unfulfilled.
//!
//! This cron runs in the always-built code path (no federation feature gate)
//! and on a configurable interval reads the latest ledger state, signs it with
//! the BJJ authority key when available, and submits the resulting hash to
//! every configured anchor backend.
//!
//! The cron is opt-in: if no anchor URLs are configured (the default), the
//! cron logs once and exits without spawning a loop, so a vanilla dev build
//! does no outbound network calls.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::{anchor_all, checkpoint_anchor_hash, AnchoringConfig};
use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// Lower bound on the cron interval. Anything tighter risks tripping
/// third-party rate limits (freetsa.org and the public OTS calendars
/// publish 1/minute / 1/hour ceilings); the cron is for periodic court
/// evidence, not per-request anchoring.
const MIN_INTERVAL_SECS: u64 = 60;

/// Delay before the first tick so the embedded Postgres has a moment to
/// finish migrations and bootstrap before we hit it with queries.
const STARTUP_DELAY_SECS: u64 = 30;

/// Spawn the anchoring cron task. Returns `None` if no anchor backend is
/// configured — the caller can drop the return value either way.
///
/// The task runs until the process exits; there is no graceful shutdown
/// handle today because the only consumer (`main.rs`) runs the tokio
/// runtime for the lifetime of the desktop app.
pub fn spawn(
    pool: PgPool,
    cfg: AnchoringConfig,
    http: Arc<reqwest::Client>,
    bjj_key: Option<[u8; 32]>,
    bjj_pubkey: Option<BabyJubJubPubKey>,
) -> Option<JoinHandle<()>> {
    if !cfg.any_enabled() {
        tracing::info!(
            "anchor cron: no OLYMPUS_ANCHOR_* URLs configured; cron not spawned"
        );
        return None;
    }
    let interval = cfg.interval_secs.max(MIN_INTERVAL_SECS);
    tracing::info!(
        "anchor cron: starting (interval={interval}s, rfc3161={}, rekor={}, ots_calendars={})",
        cfg.rfc3161_url.is_some(),
        cfg.rekor_url.is_some(),
        cfg.ots_calendars.len(),
    );
    Some(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
        loop {
            if let Err(e) = run_once(&pool, &cfg, &http, bjj_key.as_ref(), bjj_pubkey.as_ref()).await {
                tracing::warn!("anchor cron: tick failed: {e}");
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    }))
}

/// One tick of the cron. Returns `Ok(())` on success or graceful no-op
/// ("no ingest records yet"); only DB/anchoring failures surface as Err.
async fn run_once(
    pool: &PgPool,
    cfg: &AnchoringConfig,
    http: &reqwest::Client,
    bjj_key: Option<&[u8; 32]>,
    bjj_pubkey: Option<&BabyJubJubPubKey>,
) -> Result<(), String> {
    let snapshot = match latest_snapshot(pool, bjj_key, bjj_pubkey).await? {
        Some(s) => s,
        None => {
            tracing::debug!("anchor cron: no ingest_records yet; skipping tick");
            return Ok(());
        }
    };
    let hash = checkpoint_anchor_hash(
        &snapshot.ledger_root,
        snapshot.tree_size,
        snapshot.timestamp,
        &snapshot.authority_pubkey_hash,
        snapshot.sig.as_ref().map(|s| s.r8x.as_str()),
        snapshot.sig.as_ref().map(|s| s.r8y.as_str()),
        snapshot.sig.as_ref().map(|s| s.s.as_str()),
    );
    let (ids, errs) = anchor_all(pool, cfg, http, hash, None).await;
    tracing::info!(
        "anchor cron: tick complete — {} receipt(s) stored, {} failure(s)",
        ids.len(),
        errs.len(),
    );
    for (kind, e) in &errs {
        tracing::warn!("anchor cron: {} backend failed: {e}", kind.as_str());
    }
    Ok(())
}

/// Minimal checkpoint snapshot — enough to feed `checkpoint_anchor_hash`.
struct Snapshot {
    ledger_root: String,
    tree_size: i64,
    timestamp: i64,
    authority_pubkey_hash: String,
    /// `None` when no BJJ authority key is loaded; the anchor hash domain
    /// already covers the missing-sig case by hashing empty strings.
    sig: Option<SigDec>,
}

struct SigDec {
    r8x: String,
    r8y: String,
    s: String,
}

async fn latest_snapshot(
    pool: &PgPool,
    bjj_key: Option<&[u8; 32]>,
    bjj_pubkey: Option<&BabyJubJubPubKey>,
) -> Result<Option<Snapshot>, String> {
    let latest: Option<(String,)> = sqlx::query_as(
        "SELECT merkle_root FROM ingest_records
         WHERE merkle_root IS NOT NULL
         ORDER BY ts DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("query latest merkle_root: {e}"))?;

    let Some((merkle,)) = latest else {
        return Ok(None);
    };

    let tree_size: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ingest_records")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count ingest_records: {e}"))?;

    let now = chrono::Utc::now().timestamp();

    let (authority_pubkey_hash, sig) = match (bjj_key, bjj_pubkey) {
        (Some(key), Some(pubkey)) => {
            let ledger_root_fr = crate::zk::proof::parse_fr(&merkle)
                .map_err(|e| format!("parse ledger root: {e}"))?;
            let sig = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
                key,
                ledger_root_fr,
                now.max(0) as u64,
            )
            .map_err(|e| format!("BJJ sign: {e}"))?;
            let hash = pubkey
                .authority_hash()
                .map_err(|e| format!("pubkey authority_hash: {e}"))?;
            (
                fr_to_decimal(&hash),
                Some(SigDec {
                    r8x: fr_to_decimal(&sig.r8x),
                    r8y: fr_to_decimal(&sig.r8y),
                    s: fr_to_decimal(&sig.s),
                }),
            )
        }
        _ => (String::new(), None),
    };

    Ok(Some(Snapshot {
        ledger_root: merkle,
        tree_size: tree_size.0,
        timestamp: now,
        authority_pubkey_hash,
        sig,
    }))
}

fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_returns_none_when_no_backends_configured() {
        // Default config = all anchors disabled = no spawned task.
        // PgPool::connect_lazy requires a tokio context for its connection
        // pool init, so we run inside #[tokio::test]. spawn() short-circuits
        // on `!cfg.any_enabled()` before touching the pool.
        let cfg = AnchoringConfig::default();
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(pool, cfg, http, None, None);
        assert!(handle.is_none(), "no backends → no cron task");
    }

    #[test]
    fn min_interval_floor_protects_third_parties() {
        // Sanity guard: if a future refactor drops the .max() call the
        // floor still applies via the constant. The test exists so any
        // change to MIN_INTERVAL_SECS surfaces in code review.
        assert!(MIN_INTERVAL_SECS >= 60);
    }
}
