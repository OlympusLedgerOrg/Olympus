//! Ledger state, proof, activity, and document ingestion/verification routes.
//!
//! Ported from `api/routers/ledger.py`.
//!
//! Routes
//! ------
//! GET  /ledger/state                — global state root and summary
//! GET  /ledger/shard/{shard_id}     — per-shard state
//! GET  /ledger/proof/{commit_id}    — inclusion proof for a commit
//! GET  /ledger/activity             — human-readable activity feed
//! POST /ledger/ingest/simple        — user-friendly document ingestion
//! POST /ledger/verify/simple        — user-friendly document verification
//!
//! # State root
//!
//! The Tauri port stores `merkle_root` per commit row.  The shard state root is
//! the `merkle_root` from the most recent commit in that shard.  The global
//! state root is the BLAKE3 hash of all shard state roots concatenated in
//! lexicographic shard-ID order (single-shard deployments: state_root = global_root).
//!
//! # ZK proofs
//!
//! All `/proof/` responses use the non-development path from the Python router:
//! a 202 `pending` response with the stored `merkle_root` and empty
//! `merkle_proof`.  Full proof generation requires the Groth16 trusted-setup
//! ceremony and is deferred to a later phase.
//!
//! # Ingest scope
//!
//! `POST /ledger/ingest/simple` requires a valid API key with one of the
//! write-side scopes (`ingest`, `write`, `commit`, or `admin`).
//! `POST /ledger/verify/simple` is public (rate-limited only).
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

mod read;
mod simple;

use read::{get_commit_proof, get_ledger_activity, get_ledger_state, get_shard_state};
use simple::{simple_document_ingest, simple_document_verify};

// ── Constants ─────────────────────────────────────────────────────────────────
const DEFAULT_SHARD: &str = "0x4F3A";

/// BLAKE3 hex of 32 zero bytes — used as the "empty" state root.
const ZERO_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Shard-ID character allow-list: alphanumeric, colon, dot, underscore, hyphen.
fn valid_shard_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
}
// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── DB row (shared: read + simple) ──────────────────────────────────────────
#[derive(sqlx::FromRow)]
pub(super) struct DocCommitRow {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    request_id: Option<String>,
    pub(super) doc_hash: String,
    pub(super) commit_id: String,
    pub(super) epoch_timestamp: NaiveDateTime,
    pub(super) shard_id: String,
    pub(super) merkle_root: Option<String>,
    #[allow(dead_code)]
    zk_proof: Option<String>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LedgerStateResponse {
    pub global_state_root: String,
    pub shard_count: usize,
    pub total_commits: i64,
    pub last_epoch: Option<String>,
}

#[derive(Serialize)]
pub struct CommitSummary {
    pub commit_id: String,
    pub doc_hash: String,
    pub epoch: String,
    pub shard_id: String,
    pub merkle_root: Option<String>,
}

#[derive(Serialize)]
pub struct ShardStateResponse {
    pub shard_id: String,
    pub state_root: String,
    pub commit_count: i64,
    pub latest_commits: Vec<CommitSummary>,
}

#[derive(Serialize)]
pub struct ProofResponse {
    pub commit_id: String,
    pub shard_id: String,
    pub epoch: String,
    pub status: &'static str,
    pub reason: &'static str,
    pub merkle_root: Option<String>,
    pub merkle_proof: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ActivityItem {
    pub id: String,
    pub timestamp: String,
    pub activity_type: String,
    pub title: String,
    pub description: String,
    pub related_commit_id: Option<String>,
    pub related_request_id: Option<String>,
}

#[derive(Serialize)]
pub struct ActivityFeedResponse {
    pub items: Vec<ActivityItem>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct IngestionStep {
    pub step: u32,
    pub label: String,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Serialize)]
pub struct SimpleIngestionResponse {
    pub status: &'static str,
    pub commit_id: String,
    pub doc_hash: String,
    pub shard_id: String,
    pub epoch: String,
    pub message: String,
    pub steps: Vec<IngestionStep>,
}

#[derive(Serialize)]
pub struct SimpleVerificationResponse {
    pub verified: bool,
    pub commit_id: Option<String>,
    pub doc_hash: Option<String>,
    pub epoch: Option<String>,
    pub shard_id: Option<String>,
    pub merkle_root: Option<String>,
    pub message: String,
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActivityQuery {
    #[serde(default = "default_activity_limit")]
    pub limit: u32,
    pub activity_type: Option<String>,
}

fn default_activity_limit() -> u32 {
    50
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ledger/state", get(get_ledger_state))
        .route("/ledger/shard/{shard_id}", get(get_shard_state))
        .route("/ledger/proof/{commit_id}", get(get_commit_proof))
        .route("/ledger/activity", get(get_ledger_activity))
        .route("/ledger/ingest/simple", post(simple_document_ingest))
        .route("/ledger/verify/simple", post(simple_document_verify))
}

/// Verify/read-only subset of the ledger surface, safe to expose over the
/// federation Tor onion service. Excludes `/ledger/ingest/simple` — document
/// ingestion is an authority-bound write path and must never be remotely
/// reachable. Mirrors the `public_router()` convention in `zk`, `ingest`, and
/// `credentials`; its absence was the pre-existing `--features federation`
/// build break (#1109).
///
/// Also excludes `/ledger/activity`. Every route here confers no *authority* —
/// they are the same rate-limited reads the loopback listener already serves —
/// but authority is not the only thing that leaks. The activity feed carries
/// `ledger_activities.description`, which `/ledger/ingest/simple` fills with
/// the caller-supplied filename (`"Document '<filename>' recorded with
/// fingerprint <hash>"`, see `simple.rs`). Anywhere else in Olympus a document
/// contributes only its hash; publishing the *name* to anonymous onion clients
/// would hand out exactly the metadata the rest of the design is built to keep
/// local — a filename identifies a source about as well as the contents do.
/// The feed stays on the loopback listener, where it is operator-facing.
/// Re-adding it here is a privacy regression, not a routing tweak.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/ledger/state", get(get_ledger_state))
        .route("/ledger/shard/{shard_id}", get(get_shard_state))
        .route("/ledger/proof/{commit_id}", get(get_commit_proof))
        .route("/ledger/verify/simple", post(simple_document_verify))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `/ledger/activity` must never reach the anonymous onion surface.
    ///
    /// The feed returns `ledger_activities.description`, which
    /// `simple_document_ingest` fills with the caller-supplied filename, so
    /// exposing it publishes document *names* — metadata every other Olympus
    /// surface withholds by design.
    ///
    /// Scans this module's own source rather than the built `Router`.
    ///
    /// The authoritative check is
    /// `federation_router_tests::activity_feed_is_unroutable_on_the_tor_surface`
    /// below, which drives a real request. That one only compiles under
    /// `--features federation`, though, and CI's default job does not enable
    /// it, so this cheap textual guard runs everywhere and fails the *default*
    /// build if someone re-adds the route.
    ///
    /// It also rejects `merge`/`nest` inside `public_router`, because a text
    /// scan cannot see through them — a nested router could reintroduce
    /// `/ledger/activity` while this file never names it. Keeping the function
    /// to flat `.route(...)` calls is what makes the scan sound.
    #[test]
    fn tor_public_router_source_names_no_activity_route() {
        const SOURCE: &str = include_str!("mod.rs");

        let (_, after) = SOURCE
            .split_once("pub fn public_router()")
            .expect("public_router must exist in this file — did it get renamed?");
        let body = after
            .split_once("\n}")
            .expect("public_router body must be brace-terminated")
            .0;

        assert!(
            !body.contains("/ledger/activity"),
            "/ledger/activity is routed on the federation onion listener. It \
             returns caller-supplied document filenames (see \
             ledger/simple.rs::simple_document_ingest) and must stay on the \
             loopback listener only."
        );
        assert!(
            !body.contains(".merge(") && !body.contains(".nest("),
            "public_router composes another router, so this text scan can no \
             longer prove /ledger/activity is absent. Either keep the function \
             to flat .route(...) calls, or delete this test and rely on the \
             behavioural one — do not leave a guard that cannot see the routes."
        );
        // Guards the extractor above: if the body no longer contains any route
        // at all, the assertions pass vacuously and prove nothing.
        assert!(
            body.contains("/ledger/verify/simple"),
            "public_router body did not parse as expected — the assertions above \
             would pass vacuously. Fix the source scan."
        );
    }

    #[test]
    fn valid_shard_id_accepts_expected_patterns() {
        assert!(valid_shard_id("0x4F3A"));
        assert!(valid_shard_id("shard-1"));
        assert!(valid_shard_id("shard.us:east"));
        assert!(valid_shard_id("a"));
    }

    #[test]
    fn valid_shard_id_rejects_invalid() {
        assert!(!valid_shard_id(""));
        assert!(!valid_shard_id(&"a".repeat(129)));
        assert!(!valid_shard_id("shard/one"));
        assert!(!valid_shard_id("shard one"));
        assert!(!valid_shard_id("../escape"));
    }

    #[test]
    fn activity_limit_clamped() {
        let q = ActivityQuery {
            limit: 500,
            activity_type: None,
        };
        assert_eq!(q.limit.clamp(1, 200), 200);
    }
}

/// Behavioural counterpart to `tests::tor_public_router_source_names_no_activity_route`.
///
/// The text scan cannot see routes contributed by a merged or nested router.
/// This drives real requests through the actual `public_router()` value, so it
/// holds however the router is composed. It needs the `federation` feature,
/// since that is what compiles `public_router` at all.
#[cfg(all(test, feature = "federation"))]
mod federation_router_tests {
    use super::*;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn status_of(uri: &str) -> StatusCode {
        let app = public_router().with_state(AppState::new(None));
        app.oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router is infallible")
        .status()
    }

    #[tokio::test]
    async fn activity_feed_is_unroutable_on_the_tor_surface() {
        // 404 is specifically "no such route". A routed-but-failing handler
        // would answer 503 here (the test AppState carries no pool), so this
        // assertion cannot be satisfied by an unrelated error.
        assert_eq!(
            status_of("/ledger/activity?limit=5").await,
            StatusCode::NOT_FOUND,
            "/ledger/activity answered on the onion surface. It returns \
             caller-supplied document filenames (ledger/simple.rs) and must \
             stay on the loopback listener only."
        );
    }

    #[tokio::test]
    async fn routes_that_should_stay_public_still_answer() {
        // Positive control: proves the 404 above means "absent", not "the whole
        // router failed to build". SERVICE_UNAVAILABLE is the poolless
        // handler's own answer, so reaching it means the route resolved.
        assert_eq!(
            status_of("/ledger/state").await,
            StatusCode::SERVICE_UNAVAILABLE,
            "/ledger/state should resolve and then fail on the absent pool"
        );
    }
}
