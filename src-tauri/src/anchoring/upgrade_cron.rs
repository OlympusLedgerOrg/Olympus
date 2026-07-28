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

use std::path::{Path, PathBuf};
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

const RETRY_BASE_SECS: i64 = 5 * 60;
const RETRY_MAX_SECS: i64 = 6 * 60 * 60;

fn retry_delay_secs(prior_attempts: i32) -> i64 {
    let exponent = u32::try_from(prior_attempts.max(0))
        .unwrap_or(u32::MAX)
        .min(16);
    RETRY_BASE_SECS
        .saturating_mul(1_i64 << exponent)
        .min(RETRY_MAX_SECS)
}

async fn schedule_retry(
    pool: &PgPool,
    row: &store::PendingOts,
    reason: &str,
) -> Result<(), String> {
    store::schedule_ots_retry(
        pool,
        row.id,
        row.lease_token,
        retry_delay_secs(row.upgrade_attempts),
        reason,
    )
    .await
    .map_err(|e| format!("schedule retry for {}: {e}", row.id))
}

/// Spawn the OTS evidence cron.
///
/// Two independent stages, mirroring the OpenTimestamps reference client's
/// separation of `ots upgrade` from `ots verify`:
///
///   1. **upgrade** — ask the calendars for the Bitcoin path and embed it in
///      the receipt. This is what makes a proof *self-contained*: once the
///      attestation is stored the evidence no longer depends on that calendar
///      still existing. It needs no trusted-header manifest.
///   2. **verify** — check an already-embedded attestation against an
///      operator-pinned, proof-of-work-validated mainnet header.
///
/// Both previously lived in one tick gated on the manifest, so a missing or
/// lagging manifest meant the cron never started at all and a successfully
/// fetched calendar attestation was discarded and re-fetched forever, leaving
/// the evidence permanently calendar-dependent. Each stage now runs on its own.
pub fn spawn(
    pool: PgPool,
    http: Arc<reqwest::Client>,
    ots_calendars_configured: bool,
    trusted_headers_path: Option<PathBuf>,
) -> Option<JoinHandle<()>> {
    if !ots_calendars_configured && trusted_headers_path.is_none() {
        tracing::info!(
            "ots evidence cron: neither OTS calendars nor a trusted Bitcoin header manifest \
             configured; cron not spawned"
        );
        return None;
    }
    if !ots_calendars_configured {
        tracing::info!(
            "ots evidence cron: no OTS calendars configured; running the verification stage only"
        );
    }
    if trusted_headers_path.is_none() {
        tracing::warn!(
            "ots evidence cron: no trusted Bitcoin header manifest configured; receipts will be \
             upgraded to self-contained proofs but not marked verified"
        );
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
            if ots_calendars_configured {
                if let Err(e) = upgrade_pending_receipts(&pool, &http).await {
                    tracing::warn!("ots evidence cron: upgrade stage failed: {}", e);
                }
            }
            if let Some(path) = trusted_headers_path.as_deref() {
                if let Err(e) = verify_upgraded_receipts(&pool, path).await {
                    tracing::warn!("ots evidence cron: verification stage failed: {}", e);
                }
            }
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    }))
}

/// One tick: list pending receipts, try to upgrade each, persist
/// successes. Failures are logged but don't abort the tick — a single
/// flaky calendar shouldn't lock the upgrade pipeline.
async fn upgrade_pending_receipts(pool: &PgPool, http: &reqwest::Client) -> Result<(), String> {
    let pending = store::claim_pending_ots(pool, PER_TICK_LIMIT)
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
                let reason = format!(
                    "anchored_hash has {} bytes; expected 32",
                    row.anchored_hash.len()
                );
                tracing::warn!(
                    "ots upgrade cron: row {} has anchored_hash of {} bytes (expected 32) — \
                     refusing to upgrade",
                    row.id,
                    row.anchored_hash.len()
                );
                if let Err(e) = schedule_retry(pool, &row, &reason).await {
                    tracing::warn!("ots upgrade cron: {e}");
                }
                errored += 1;
                continue;
            }
        };
        match ots::try_upgrade(http, &row.target, &row.receipt_blob, &original).await {
            Ok(Some(upgrade)) => {
                // Persist the embedded Bitcoin path immediately, WITHOUT
                // requiring a trusted-header manifest. This is the whole point
                // of the OpenTimestamps upgrade step: the receipt becomes
                // self-contained, so the evidence survives the calendar going
                // away. Verifying that attestation against a pinned mainnet
                // header is stage 2's job, and no `verified_at` is written here.
                match store::append_upgraded_receipt(
                    pool,
                    row.id,
                    row.lease_token,
                    &upgrade.receipt_blob,
                    upgrade.bitcoin_block_height,
                    &upgrade.bitcoin_merkle_root,
                )
                .await
                {
                    Ok(()) => upgraded += 1,
                    Err(e) => {
                        tracing::warn!(
                            "ots upgrade cron: persist upgraded blob for {} failed: {}",
                            row.id,
                            e
                        );
                        if let Err(retry_error) = schedule_retry(pool, &row, &e.to_string()).await {
                            tracing::warn!("ots upgrade cron: {retry_error}");
                        }
                        errored += 1;
                    }
                }
            }
            Ok(None) => {
                match schedule_retry(pool, &row, "calendar receipt remains pending").await {
                    Ok(()) => still_pending += 1,
                    Err(e) => {
                        tracing::warn!("ots upgrade cron: {e}");
                        errored += 1;
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "ots upgrade cron: calendar {} did not upgrade {}: {}",
                    row.target,
                    row.id,
                    e
                );
                if let Err(retry_error) = schedule_retry(pool, &row, &e.to_string()).await {
                    tracing::warn!("ots upgrade cron: {retry_error}");
                }
                errored += 1;
            }
        }
    }
    tracing::info!(
        "ots evidence cron: upgrade tick complete — {total} checked, {upgraded} upgraded, \
         {still_pending} still pending, {errored} errored"
    );
    Ok(())
}

/// Stage 2: re-parse each upgraded receipt's embedded Bitcoin attestation and,
/// when it matches an operator-pinned header, append verified evidence.
///
/// The stored blob is re-parsed rather than trusting the metadata summary
/// written at upgrade time, so what gets attested is exactly the receipt a
/// court would be handed.
async fn verify_upgraded_receipts(
    pool: &PgPool,
    trusted_headers_path: &Path,
) -> Result<(), String> {
    // Reload each tick so an operator can atomically replace the manifest with
    // newly confirmed headers without restarting Olympus. Invalid updates fail
    // closed before any row is leased or persisted as verified.
    let owned = trusted_headers_path.to_path_buf();
    let trusted_headers = tokio::task::spawn_blocking(move || {
        super::ots_bitcoin::TrustedBitcoinHeaders::load(&owned)
    })
    .await
    .map_err(|e| format!("load trusted Bitcoin headers: task join failed: {e}"))?
    .map_err(|e| format!("load trusted Bitcoin headers: {e}"))?;

    let claimed = store::claim_upgraded_unverified(pool, PER_TICK_LIMIT)
        .await
        .map_err(|e| format!("list upgraded receipts: {e}"))?;
    if claimed.is_empty() {
        tracing::debug!("ots evidence cron: no upgraded receipts awaiting verification");
        return Ok(());
    }
    let total = claimed.len();
    let mut verified = 0usize;
    let mut awaiting = 0usize;
    let mut errored = 0usize;
    for row in claimed {
        let original: [u8; 32] = match row.anchored_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                let reason = format!(
                    "anchored_hash has {} bytes; expected 32",
                    row.anchored_hash.len()
                );
                tracing::warn!("ots evidence cron: {reason} for {}", row.id);
                if let Err(e) = schedule_retry(pool, &row, &reason).await {
                    tracing::warn!("ots evidence cron: {e}");
                }
                errored += 1;
                continue;
            }
        };
        let claim =
            match super::ots_tree::require_bitcoin_after(&row.receipt_blob, &original, &original) {
                Ok(claim) => claim,
                Err(e) => {
                    let reason = format!("re-parse embedded Bitcoin attestation: {e}");
                    tracing::warn!("ots evidence cron: {reason} for {}", row.id);
                    if let Err(retry_error) = schedule_retry(pool, &row, &reason).await {
                        tracing::warn!("ots evidence cron: {retry_error}");
                    }
                    errored += 1;
                    continue;
                }
            };
        let header_verification =
            match trusted_headers.verify_attestation(claim.block_height, &claim.merkle_root) {
                Ok(verification) => verification,
                Err(e) => {
                    // Usually not a fault: the pinned manifest simply may not
                    // reach this height yet. The upgraded proof is already
                    // durable and calendar-independent, so the row just waits
                    // for a newer manifest instead of being discarded.
                    let reason = format!("trusted Bitcoin header verification: {e}");
                    tracing::debug!("ots evidence cron: {reason} for {}", row.id);
                    if let Err(retry_error) = schedule_retry(pool, &row, &reason).await {
                        tracing::warn!("ots evidence cron: {retry_error}");
                    }
                    awaiting += 1;
                    continue;
                }
            };
        match store::append_verified_evidence(
            pool,
            row.id,
            row.lease_token,
            claim.block_height,
            &header_verification,
        )
        .await
        {
            Ok(()) => verified += 1,
            Err(e) => {
                tracing::warn!(
                    "ots evidence cron: persist verified evidence for {} failed: {}",
                    row.id,
                    e
                );
                if let Err(retry_error) = schedule_retry(pool, &row, &e.to_string()).await {
                    tracing::warn!("ots evidence cron: {retry_error}");
                }
                errored += 1;
            }
        }
    }
    tracing::info!(
        "ots evidence cron: verification tick complete — {total} checked, {verified} verified, \
         {awaiting} awaiting a newer header manifest, {errored} errored"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_returns_none_when_neither_stage_is_configured() {
        // No outbound calls; bail before touching the pool.
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(pool, http, false, None);
        assert!(handle.is_none());
    }

    /// The upgrade stage must run without a trusted-header manifest.
    ///
    /// Embedding the calendar's Bitcoin path is what makes a receipt
    /// self-contained (the OpenTimestamps `upgrade` step), and that is valuable
    /// on its own — it is what stops the evidence depending on the calendar
    /// surviving. Gating it on the manifest previously meant the cron never
    /// started, so a fetched attestation was discarded and re-fetched forever.
    #[tokio::test]
    async fn spawn_runs_upgrade_stage_without_trusted_headers() {
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(pool, http, true, None).expect("upgrade stage must still be scheduled");
        handle.abort();
    }

    /// Symmetrically, the verification stage must run without calendars: an
    /// already-upgraded receipt needs no calendar to be checked against a
    /// pinned header.
    #[tokio::test]
    async fn spawn_runs_verification_stage_without_calendars() {
        let http = super::super::build_http_client(Duration::from_secs(5));
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid/db").unwrap();
        let handle = spawn(
            pool,
            http,
            false,
            Some(PathBuf::from("headers-manifest.json")),
        )
        .expect("verification stage must still be scheduled");
        handle.abort();
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

    #[test]
    fn retry_backoff_is_exponential_and_bounded() {
        assert_eq!(retry_delay_secs(0), 5 * 60);
        assert_eq!(retry_delay_secs(1), 10 * 60);
        assert_eq!(retry_delay_secs(2), 20 * 60);
        assert_eq!(retry_delay_secs(100), RETRY_MAX_SECS);
        assert_eq!(retry_delay_secs(i32::MAX), RETRY_MAX_SECS);
    }
}
