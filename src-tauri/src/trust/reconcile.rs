// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Startup reconciliation of the accepted trust chain (ADR-0041 §3/§4,
//! startup half of implementation-plan step 12).
//!
//! On boot, before any trust-dependent service is exposed:
//!
//! 1. Reconstruct + fully re-verify the accepted chain from the immutable
//!    rows ([`super::store::load_accepted_chain`] — fails closed on gaps,
//!    equivocation, linkage breaks, decreasing signed `activation_at`, or
//!    authorization that no longer verifies).
//! 2. Walk the contiguous Accepted-but-not-Active successors **strictly in
//!    sequence order**, atomically activating each one whose signed
//!    `activation_at` has been reached and whose freshness/coverage checks
//!    still pass. The walk stops at the first not-yet-eligible successor
//!    (that is a normal state, not an error) or the first hard failure.
//! 3. Judge the resulting Active snapshot against the continuous §4
//!    freshness conditions. No fresh Active snapshot ⇒ a typed error the
//!    caller escalates (production: `exit(2)`; dev: `tracing::error!` +
//!    legacy trust path — exactly `verify_ceremony_manifests`' split).
//!
//! There is deliberately **no mid-run scheduler** in this increment: an
//! `activation_at` that arrives while the process is up takes effect on the
//! next restart. The empty-chain case returns
//! [`TrustReconcileOutcome::NoAcceptedGenesis`] and changes nothing — the
//! legacy env-list trust path stays authoritative until the genesis CLI
//! (later PR) can create accepted state at all.

use sqlx::PgPool;

use super::config::{snapshot_freshness_violation, TrustFreshnessConfig};
use super::resolver::SnapshotTrustResolver;
use super::store::{activate_transition, load_accepted_chain, TrustTransitionError};

/// Outcome of a successful startup reconciliation.
#[derive(Debug)]
pub enum TrustReconcileOutcome {
    /// No accepted genesis exists. The snapshot machinery is inert; the
    /// caller keeps the legacy env-list path completely unchanged.
    NoAcceptedGenesis,
    /// An accepted chain exists and reconciled to a fresh Active snapshot.
    ChainActive {
        /// Resolver over the Active snapshot (not yet consumed by any
        /// verification site — consumer switchover is a later PR).
        resolver: SnapshotTrustResolver,
        /// How many transitions this reconciliation activated.
        activated_now: usize,
        /// Accepted-but-not-yet-eligible successors left pending.
        pending_successors: usize,
    },
}

/// Resolve the startup trust state for a server binary: env-resolved
/// freshness config, wall-clock `now`, and outcome logging — everything
/// except the fatality decision, which stays with the caller (this crate's
/// library code never exits the process; both `main.rs`'s bring-up and the
/// headless `olympus-server` escalate an `Err` themselves, keeping the two
/// binaries' semantics identical by construction).
///
/// * `Ok(None)` — no accepted genesis; legacy env-list trust path continues
///   unchanged (logged at `info`).
/// * `Ok(Some(resolver))` — accepted chain reconciled to a fresh Active
///   snapshot (logged at `info` with sequence/digest).
/// * `Err(_)` — accepted state exists but no fresh Active snapshot could be
///   established; production callers must treat this as fatal (`exit(2)`).
pub async fn startup_trust_resolver(
    pool: &PgPool,
    is_prod: bool,
) -> Result<Option<std::sync::Arc<SnapshotTrustResolver>>, TrustTransitionError> {
    let config = TrustFreshnessConfig::from_env();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    match reconcile_at_startup(pool, &config, now, is_prod).await? {
        TrustReconcileOutcome::NoAcceptedGenesis => {
            tracing::info!(
                "trust: no accepted trust-list genesis exists; the legacy \
                 OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON / bootstrap-key trust path remains \
                 authoritative (ADR-0041 genesis tooling has not been run)"
            );
            Ok(None)
        }
        TrustReconcileOutcome::ChainActive {
            resolver,
            activated_now,
            pending_successors,
        } => {
            use olympus_crypto::trust_list::TrustResolver as _;
            tracing::info!(
                "trust: accepted trust chain reconciled — Active snapshot sequence {} \
                 (digest {}), {} transition(s) activated at startup, {} accepted \
                 successor(s) pending activation",
                resolver.snapshot_sequence(),
                hex::encode(resolver.snapshot_digest()),
                activated_now,
                pending_successors,
            );
            Ok(Some(std::sync::Arc::new(resolver)))
        }
    }
}

/// Reconcile the accepted trust chain at startup. See the module docs.
///
/// `now` is the decision-time clock, injected for testability; callers pass
/// wall-clock seconds. Errors mean an accepted genesis EXISTS but no fresh
/// Active snapshot could be established — the caller decides fatality per
/// environment (the function itself never exits the process).
pub async fn reconcile_at_startup(
    pool: &PgPool,
    config: &TrustFreshnessConfig,
    now: i64,
    is_prod: bool,
) -> Result<TrustReconcileOutcome, TrustTransitionError> {
    let chain = load_accepted_chain(pool).await?;
    if chain.links.is_empty() {
        return Ok(TrustReconcileOutcome::NoAcceptedGenesis);
    }

    // Once accepted state exists, the freshness bounds become load-bearing:
    // running an unbounded trust list in production would disable the
    // rollback/staleness protection the chain is for (ADR-0041 §4).
    if is_prod {
        let errors = config.production_errors();
        if !errors.is_empty() {
            return Err(TrustTransitionError::MissingFreshnessConfig(errors));
        }
    }

    // Activate eligible successors strictly in sequence order, one atomic
    // activation per snapshot. Each `activate_transition` re-loads and
    // re-verifies the chain under the advisory lock, so this loop is safe
    // against concurrent writers.
    let mut activated_now = 0usize;
    loop {
        let chain = load_accepted_chain(pool).await?;
        let next_index = chain.active_len();
        let Some(link) = chain.links.get(next_index) else {
            break; // whole chain active
        };
        match activate_transition(pool, link.candidate_id, now, config, is_prod).await {
            Ok(()) => activated_now += 1,
            // Not yet eligible (or no longer activatable): stop walking.
            // Whether the resulting state is acceptable is judged below on
            // the final Active snapshot, not here — a stale *successor* must
            // not take the already-Active predecessor down with it.
            Err(TrustTransitionError::ActivationTimeNotReached { .. })
            | Err(TrustTransitionError::SnapshotNotFresh(_)) => break,
            Err(other) => return Err(other),
        }
    }

    let chain = load_accepted_chain(pool).await?;
    let pending_successors = chain.links.len() - chain.active_len();
    match chain.active() {
        None => Err(TrustTransitionError::NoFreshActiveSnapshot {
            earliest_pending_activation: chain.links.first().map(|l| l.activation_at),
        }),
        Some(active) => {
            if let Some(violation) = snapshot_freshness_violation(&active.snapshot, now, config) {
                return Err(violation.into());
            }
            Ok(TrustReconcileOutcome::ChainActive {
                resolver: SnapshotTrustResolver::new(
                    active.snapshot.clone(),
                    active.digest,
                    config.clone(),
                ),
                activated_now,
                pending_successors,
            })
        }
    }
}
