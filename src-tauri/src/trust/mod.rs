// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0041 runtime trust-list state machine: persistence, reconciliation,
//! and the snapshot-backed [`TrustResolver`](olympus_crypto::trust_list::TrustResolver).
//!
//! # Step coverage (mirrors `olympus_crypto::trust_list`'s scope note)
//!
//! This module implements, of ADR-0041's implementation plan:
//!
//! * **step 8** — persistent accepted state, successor-uniqueness
//!   constraints, and append-only transition tables (migration `0063`;
//!   [`store`]);
//! * **step 5** — the snapshot-backed [`resolver::SnapshotTrustResolver`]
//!   behind the `TrustResolver` trait, including the continuous
//!   decision-time max-age check (security invariant 18);
//! * **step 11 (subset)** — startup freshness, rollback, coverage,
//!   policy-profile, and equivocation checks ([`store`]'s validation +
//!   [`reconcile`]);
//! * **step 12 (startup half only)** — [`reconcile::reconcile_at_startup`]
//!   atomically promotes contiguous Accepted snapshots whose signed
//!   `activation_at` has been reached. There is **no mid-run activation
//!   scheduler yet**: an accepted successor whose activation time arrives
//!   while the process is running becomes Active on the next restart, not
//!   mid-flight. That scheduler is a later PR.
//!
//! **Not implemented here** (later PRs): the genesis / recovery / inspection
//! CLIs (steps 7, 9, 14), consumer switchover onto the resolver (step 6 —
//! every consumer still reads the legacy `api::trusted_issuers` set),
//! bootstrap-key removal after genesis (step 10), purpose-typed
//! `ActiveSigners` + signer-activation records (step 13), and operational
//! docs/exercises (steps 15–17).
//!
//! # Behavior until genesis exists
//!
//! Because the genesis CLI has not landed, **no production database can
//! contain an accepted genesis yet**, and startup reconciliation is a
//! deliberate no-op in that state: it logs at `info` and leaves the legacy
//! `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` / bootstrap-key path completely
//! unchanged. Only once an accepted genesis exists does the snapshot chain
//! become authoritative — from then on a reconciliation failure is fatal in
//! production (`exit(2)`), mirroring `verify_ceremony_manifests`.

pub mod config;
pub mod reconcile;
pub mod resolver;
pub mod store;

pub use config::{FreshnessLimit, TrustFreshnessConfig};
pub use reconcile::{reconcile_at_startup, TrustReconcileOutcome};
pub use resolver::SnapshotTrustResolver;
pub use store::{
    accept_candidate, activate_transition, load_accepted_chain, stage_candidate, AcceptedChain,
    AcceptedLink, StagedCandidate, TrustTransitionError,
};
