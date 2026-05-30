//! Single integration-test binary for every Postgres-backed API suite.
//!
//! Each `tests/api_db/<route>.rs` module used to be its own
//! `tests/api_*_db.rs` binary — but cargo builds one embedded-Postgres
//! cluster *per binary*, so 8 binaries meant 8 `initdb`s plus 8 clusters
//! left running until process exit. Folding them into this one binary
//! means the shared `common` harness boots **one** cluster (via its
//! `OnceLock`) for all ~50 DB tests, and only one cluster lingers
//! afterwards — which also relieves the resource pressure that was
//! intermittently flaking the vendored `pg-embed` crate's own
//! `multiple_concurrent` test during the pre-push `cargo test --workspace`.
//!
//! `common` lives at `tests/common/mod.rs` and is pulled in here via an
//! explicit `#[path]`; the suite modules reference it as `crate::common`.
//!
//! Tests across these modules share ONE database, so each must stay
//! isolation-tolerant: unique-per-test identifiers (`common::unique_id`)
//! and no assertions that assume a pristine/exclusive DB. (The one
//! global-state assertion — `anchors` is empty — holds because no test
//! ever writes an anchor row.)

// NB: this file is the test binary's crate root, so `mod foo;` would
// resolve against `tests/` (the root file's directory), not `tests/api_db/`.
// Explicit `#[path]` points each module at its file under `tests/api_db/`
// (and the shared harness at `tests/common/mod.rs`).
#[path = "common/mod.rs"]
mod common;

#[path = "api_db/admin_users.rs"]
mod admin_users;
#[path = "api_db/anchors.rs"]
mod anchors;
#[path = "api_db/credentials.rs"]
mod credentials;
#[path = "api_db/ledger.rs"]
mod ledger;
#[path = "api_db/public_stats.rs"]
mod public_stats;
#[path = "api_db/redaction.rs"]
mod redaction;
#[path = "api_db/user_auth.rs"]
mod user_auth;
#[path = "api_db/zk_verify.rs"]
mod zk_verify;
