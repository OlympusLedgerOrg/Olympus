// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Public read-only "Monitor API" (ADR-0021): CT-inspired surfaces for
//! roots, proofs, and delayed-inclusion evidence, so a third party can
//! independently audit Olympus's operational behavior over HTTP without an
//! API key.
//!
//! Routes
//! ------
//! * `GET /monitor/checkpoints` — recent signed checkpoints for one shard,
//!   newest first (a "get-sth-history" equivalent).
//! * `GET /monitor/checkpoints/latest` — the single latest signed checkpoint
//!   for one shard (a "get-sth" equivalent).
//! * `GET /monitor/proof/{content_hash}` — the raw, offline-verifiable
//!   Poseidon ledger-snapshot inclusion witness for a committed record (a
//!   "get-proof-by-hash" equivalent). Serves exactly the evidence
//!   `POST /ingest/proofs/verify` already parses and verifies server-side —
//!   see `api::ingest::snapshot_evidence` — but returns the raw witness
//!   itself instead of only a verdict, so a monitor can check it without
//!   trusting this server's computation.
//! * `GET /monitor/mmd/{content_hash}` — Maximum Merge Delay evidence: how
//!   long after ingest the record's first covering signed checkpoint
//!   appeared, and whether that met the configured MMD policy
//!   (`OLYMPUS_MMD_SECONDS`, `crate::mmd::MmdPolicy`).
//!
//! **Scope note on what "root" means here.** Witness cosigning (ADR-0033,
//! `quorum::checkpoint`) and gossip/equivocation detection
//! (`federation::gossip`, `federation::equivocation`) already exist and are
//! documented in ADR-0021's update — this module does not duplicate them.
//! What this module serves is the **Poseidon ledger-snapshot tree**
//! (`crates/olympus-crypto::ledger_snapshot`, depth 20) that `own_checkpoints`
//! actually signs — NOT the separate BLAKE3 CD-HS-ST parser-bound SMT
//! (`crate::smt::tree::PersistentSmt`, depth 256) that ADR-0003/0004/0005
//! describe as the canonical per-leaf commitment. Nothing in this codebase
//! signs or checkpoints that second tree's root today, so a proof against it
//! would have no signed statement to verify against; serving one here would
//! misrepresent what a monitor can actually establish. See ADR-0021's
//! "Known limitation" note.
//!
//! Every route here takes only `RateLimit` (no `AuthenticatedKey`) and is
//! mounted on both the default loopback listener and, when the `federation`
//! feature is compiled, the Tor-facing listener (`public_router`) — nothing
//! served here reveals content, filenames, or holder identity, only
//! already-signed/public commitments and record identifiers the caller
//! already has (the same standard `redaction::issuer_key` and `ledger`'s
//! `public_router` routes apply).

mod checkpoints;
mod mmd;
mod proof;

use axum::{routing::get, Router};

use crate::state::AppState;

pub use checkpoints::{CheckpointSummary, CheckpointsResponse};
pub use mmd::MmdResponse;
pub use proof::MonitorProofResponse;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/monitor/checkpoints", get(checkpoints::list_checkpoints))
        .route(
            "/monitor/checkpoints/latest",
            get(checkpoints::latest_checkpoint),
        )
        .route("/monitor/proof/{content_hash}", get(proof::get_proof))
        .route("/monitor/mmd/{content_hash}", get(mmd::get_mmd_evidence))
}

/// Identical route set on the Tor-facing listener — every handler here is
/// already unauthenticated and non-identity-leaking, so the full set is safe
/// to expose to remote monitors, not just the loopback-reachable set.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    router()
}

#[cfg(test)]
mod tests {
    /// Every route this module defines must be present verbatim in
    /// `public_router()` — a Monitor API surface that is loopback-only
    /// defeats ADR-0021's point (a third-party monitor is, by definition,
    /// not running on the same machine).
    #[cfg(feature = "federation")]
    #[test]
    fn public_router_exposes_every_monitor_route() {
        let src = include_str!("mod.rs");
        let (_, after) = src
            .split_once("pub fn router()")
            .expect("router() must exist in this file — did it get renamed?");
        let router_body = after
            .split_once("\n}")
            .expect("router() body must be brace-terminated")
            .0;
        let routes: Vec<&str> = router_body
            .lines()
            .filter(|l| l.trim_start().starts_with(".route("))
            .collect();
        assert_eq!(routes.len(), 4, "expected exactly 4 routes in router()");

        let (_, after) = src
            .split_once("pub fn public_router()")
            .expect("public_router() must exist in this file — did it get renamed?");
        let public_body = after
            .split_once("\n}")
            .expect("public_router() body must be brace-terminated")
            .0;
        assert!(
            public_body.contains("router()"),
            "public_router() must delegate to router() so this test stays \
             meaningful without hand-listing routes twice; if it ever \
             stops delegating, replace this assertion with a route-by-route \
             text scan like ledger::mod's."
        );
    }
}
