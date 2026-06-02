//! Periodic OTS receipt-upgrade cron.
//!
//! Audit M-A3: `crate::anchoring::ots::try_upgrade` exists but was
//! never invoked. v0.9 only ever shipped *pending* OTS receipts, and
//! `docs/court-evidence.md` told courts to run `ots verify <receipt>`
//! against them — which fails on pending receipts because no Bitcoin
//! commitment exists yet. This cron walks pending receipts every
//! `interval_secs` and asks each receipt's originating calendar to
//! upgrade it (typically within ~6h of submission, once the calendar
//! has folded the commitment into a Bitcoin block).
//!
//! Tunable via `OLYMPUS_ANCHOR_OTS_UPGRADE_INTERVAL_SECS`
//! (default 21600 = 6h, floored at 300s to avoid hammering the
//! calendar).

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::{ots, store};

/// Default cron tick: 6h. OTS commits to Bitcoin every hour or so and
/// the upgraded proof requires ~6 confirmations on top, so a 6h cadence
/// catches most receipts on the first or second tick without burning
/// calendar bandwidth.
pub const DEFAULT_UPGRADE_INTERVAL_SECS: u64 = 21600;

/// Floor on the cron interval. OTS calendars publish rate limits in the
/// ~1/hour range per submitter; 300s = 5min is below typical limits but
/// well above the lower bound where the cron would consume meaningful
/// calendar bandwidth on a single-node install.
const MIN_UPGRADE_INTERVAL_SECS: u64 = 300;

/// Number of pending receipts to attempt per tick. Bound so a backlog
/// of thousands of receipts doesn't get fan-out into thousands of
/// concurrent HTTP calls.
const PER_TICK_LIMIT: i64 = 50;

/// Spawn the OTS upgrade cron. Returns `None` if no OTS calendars are
/// configured — without calendars there's nothing to upgrade against.
pub fn spawn(
    pool: PgPool,
    http: Arc<reqwest::Client>,
    ots_calendars_configured: bool,
) -> Option<JoinHandle<()>> {
    if !ots_calendars_configured {
        tracing::info!("ots upgrade cron: no OTS calendars configured; cron not spawned");
        return None;
    }
    let interval_secs = std::env::var("OLYMPUS_ANCHOR_OTS_UPGRADE_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_UPGRADE_INTERVAL_SECS)
        .max(MIN_UPGRADE_INTERVAL_SECS);
    tracing::info!(
        "ots upgrade cron: starting (interval={interval_secs}s, per_tick_limit={PER_TICK_LIMIT})"
    );
    Some(tokio::spawn(async move {
        // Sleep one tick before the first attempt so newly-submitted
        // receipts have a chance to enter Bitcoin before we ask.
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        loop {
            if let Err(e) = run_once(&pool, &http).await {
                tracing::warn!("ots upgrade cron: tick failed: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }))
}

/// One tick: list pending receipts, try to upgrade each, persist
/// successes. Failures are logged but don't abort the tick — a single
/// flaky calendar shouldn't lock the upgrade pipeline.
async fn run_once(pool: &PgPool, http: &reqwest::Client) -> Result<(), String> {
    let pending = store::list_pending_ots(pool, PER_TICK_LIMIT)
        .await
        .map_err(|e| format!("list pending: {}", e))?;
    if pending.is_empty() {
        tracing::debug!("ots upgrade cron: no pending receipts");
        return Ok(());
    }
    let total = pending.len();
    let mut upgraded = 0usize;
    let mut still_pending = 0usize;
    let mut errored = 0usize;
    for row in pending {
        // Re-canonicalise the stored anchored_hash to the [u8; 32] shape
        // the walker expects. Rows committed before migration 0040 still
        // have a 32-byte hash here (the column was always BYTEA NOT NULL
        // with a 32-byte invariant for OTS rows); reject anything else
        // loudly rather than silently misroute.
        let original: [u8; 32] = match row.anchored_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!(
                    "ots upgrade cron: row {} has anchored_hash of {} bytes (expected 32) — \
                     refusing to upgrade",
                    row.id,
                    row.anchored_hash.len()
                );
                errored += 1;
                continue;
            }
        };
        match ots::try_upgrade(http, &row.target, &row.receipt_blob, &original).await {
            Ok(Some(new_blob)) => match store::mark_ots_upgraded(pool, row.id, &new_blob).await {
                Ok(()) => upgraded += 1,
                Err(e) => {
                    tracing::warn!(
                        "ots upgrade cron: persist upgraded blob for {} failed: {}",
                        row.id,
                        e
                    );
                    errored += 1;
                }
            },
            Ok(None) => still_pending += 1,
            Err(e) => {
                tracing::debug!(
                    "ots upgrade cron: calendar {} did not upgrade {}: {}",
                    row.target,
                    row.id,
                    e
                );
                errored += 1;
            }
        }
    }
    tracing::info!(
        "ots upgrade cron: tick complete — {total} checked, {upgraded} upgraded, \
         {still_pending} still pending, {errored} errored"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_returns_none_when_no_calendars_configured() {
        // No outbound calls; bail before touching the pool.
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(pool, http, false);
        assert!(handle.is_none());
    }

    #[test]
    fn default_interval_constants_are_self_consistent() {
        // The floor must be at most the default — otherwise a fresh
        // install would silently get a tighter cadence than the
        // operator-readable default.
        const { assert!(MIN_UPGRADE_INTERVAL_SECS <= DEFAULT_UPGRADE_INTERVAL_SECS) };
        // OTS-side rate limits sit in the ~1/hour range; the floor
        // shouldn't be tighter than 60s.
        const { assert!(MIN_UPGRADE_INTERVAL_SECS >= 60) };
    }
}
