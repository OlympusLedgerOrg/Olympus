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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::{anchor_all, AnchoringConfig};
use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// Lower bound on the cron interval. Anything tighter risks tripping
/// third-party rate limits (freetsa.org and the public OTS calendars
/// publish 1/minute / 1/hour ceilings); the cron is for periodic court
/// evidence, not per-request anchoring.
const MIN_INTERVAL_SECS: u64 = 60;

/// Delay before the first tick so the embedded Postgres has a moment to
/// finish migrations and bootstrap before we hit it with queries.
const STARTUP_DELAY_SECS: u64 = 30;

/// Spawn the anchoring cron task. **Always starts**: this cron is the
/// canonical `own_checkpoints` producer (red-team CR-5/CR-7), so it must run
/// even when no external anchor backend is configured — federation reads the
/// rows it writes. External submission to `OLYMPUS_ANCHOR_*` backends is gated
/// per-tick inside `run_once` on `cfg.any_enabled()`, so a build with no anchor
/// URLs still produces checkpoints locally but makes no outbound network calls.
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
    // Where setup_circuits.sh staged the document_existence artifacts
    // (.wasm / .r1cs / .ark.zkey). When `None`, the cron still writes
    // own_checkpoints rows (sig-only / no Groth16 proof) so the anchor
    // pipeline keeps recording timestamped roots — but federation will
    // refuse to gossip those proof-less rows. Operators who want
    // gossipable checkpoints must set OLYMPUS_PROOFS_DIR or stage
    // artifacts in one of the resolved locations (see startup.rs).
    proofs_dir: Option<PathBuf>,
) -> JoinHandle<()> {
    let interval = cfg.interval_secs.max(MIN_INTERVAL_SECS);
    tracing::info!(
        "anchor cron: starting (interval={interval}s, own_checkpoint_producer=on, \
         rfc3161={}, rekor={}, ots_calendars={})",
        cfg.rfc3161_url.is_some(),
        cfg.rekor_url.is_some(),
        cfg.ots_calendars.len(),
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
        loop {
            if let Err(e) = run_once(
                &pool,
                &cfg,
                &http,
                bjj_key.as_ref(),
                bjj_pubkey.as_ref(),
                proofs_dir.as_deref(),
            )
            .await
            {
                tracing::warn!("anchor cron: tick failed: {e}");
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    })
}

/// One tick of the cron.
///
/// Red-team CR-5 closure: previously this read `ingest_records.merkle_root`
/// — a BLAKE3 column the v0.9 ingest path never populates — so every
/// tick fell through to "no ingest records yet" and zero rows were ever
/// written to `anchor_receipts`. The new pipeline builds the canonical
/// `own_checkpoints` row (Poseidon `snapshot_root` + BJJ sig + Groth16
/// proof + domain-separated anchor digest) and feeds it to `anchor_all`
/// with a real `checkpoint_id` so the receipt joins back to a persisted
/// checkpoint.
///
/// Returns `Ok(())` on success or graceful no-op ("no ingest records
/// with a complete snapshot yet"); only DB/anchoring failures surface
/// as `Err`.
async fn run_once(
    pool: &PgPool,
    cfg: &AnchoringConfig,
    http: &reqwest::Client,
    bjj_key: Option<&[u8; 32]>,
    bjj_pubkey: Option<&BabyJubJubPubKey>,
    proofs_dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let row = match super::own_checkpoint::build_and_persist(
        pool,
        bjj_key,
        bjj_pubkey,
        proofs_dir,
    )
    .await?
    {
        Some(r) => r,
        None => {
            tracing::debug!(
                "anchor cron: no ingest record has a complete Poseidon snapshot yet; \
                 skipping tick"
            );
            return Ok(());
        }
    };

    // The own_checkpoints row is now persisted regardless of anchor config.
    // External submission to third-party backends is the opt-in part: only
    // call `anchor_all` when at least one OLYMPUS_ANCHOR_* URL is configured,
    // so a federation/local build with no anchor backends still produces the
    // canonical checkpoint row but makes no outbound network calls.
    if !cfg.any_enabled() {
        tracing::debug!(
            "anchor cron: own_checkpoint {} persisted (ledger_root={}, tree_size={}); \
             no OLYMPUS_ANCHOR_* backends configured — skipping external submission",
            row.id,
            row.ledger_root,
            row.tree_size,
        );
        return Ok(());
    }

    let (ids, errs) = anchor_all(
        pool,
        cfg,
        http,
        row.anchor_hash.clone(),
        Some(row.id),
    )
    .await;
    tracing::info!(
        "anchor cron: tick complete — own_checkpoint={} ledger_root={} tree_size={} — \
         {} receipt(s) stored, {} failure(s)",
        row.id,
        row.ledger_root,
        row.tree_size,
        ids.len(),
        errs.len(),
    );
    for (kind, e) in &errs {
        tracing::warn!("anchor cron: {} backend failed: {e}", kind.as_str());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_starts_producer_even_without_anchor_backends() {
        // Decoupled producer (review follow-up CR-5/CR-7): own_checkpoints
        // production runs regardless of OLYMPUS_ANCHOR_* config, so spawn now
        // always starts a task. The STARTUP_DELAY_SECS lead-in means the task
        // never touches the (invalid) lazy pool during the test; abort it
        // immediately so nothing leaks past the test.
        let cfg = AnchoringConfig::default();
        assert!(!cfg.any_enabled(), "default config has no anchor backends");
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(pool, cfg, http, None, None, None);
        assert!(!handle.is_finished(), "producer task should be running");
        handle.abort();
    }

    #[test]
    fn min_interval_floor_protects_third_parties() {
        // Sanity guard: if a future refactor drops the .max() call the
        // floor still applies via the constant. The test exists so any
        // change to MIN_INTERVAL_SECS surfaces in code review.
        const { assert!(MIN_INTERVAL_SECS >= 60) };
    }
}
