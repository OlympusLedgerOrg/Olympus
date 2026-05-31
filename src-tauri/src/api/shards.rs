//! Shard registry — operator-controlled shard creation.
//!
//! First-use of a new `shard_id` is the moment a shard is created. This module
//! puts that under operator control: a shard must be registered (and active)
//! before the ingest write path will accept a commit into it, and a shard may
//! optionally be bound to an owner account so only that account (or an
//! `admin`-scoped key) can write to it.
//!
//! Two operator models are expressible through one mechanism:
//!   1. **Admin-gated creation** — register a shard before first use; ingest
//!      rejects unregistered shards (fail-closed).
//!   2. **Assigned namespace** — bind a shard to `owner_user_id`; only that
//!      account (or admin) may write to it.
//!
//! Enforcement is unconditional and fail-closed: [`authorize_write`] is called
//! on every `POST /ingest/files` write, and an unregistered/inactive shard, or
//! a writer who is not the shard's owner, is rejected with `403`.
//!
//! Registration is admin-gated through the shared [`require_admin_auth`] gate
//! (env `OLYMPUS_ADMIN_KEY` via `x-admin-key`, or an `admin`-role + `admin`-scope
//! API key) — the same gate the rest of `/admin/*` uses.
//!
//! Note: these handlers use sqlx's runtime query API (`query`/`query_as`) — the
//! same style as the rest of `api/` — so the new `shards` table needs no
//! compile-time offline query-cache entry.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::ingest::sanitize_shard;
use crate::api::middleware::auth::{require_admin_auth, AuthenticatedKey};
use crate::state::AppState;

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("shards: database error: {e}");
    match e {
        sqlx::Error::PoolClosed | sqlx::Error::PoolTimedOut => {
            err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
        }
        sqlx::Error::Io(_) => {
            err(StatusCode::SERVICE_UNAVAILABLE, "Database connection error.")
        }
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "Database error."),
    }
}

// ── Request / response types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterShardRequest {
    /// The `shard_id` to authorize. Must match the ingest validator
    /// (1–128 chars of `[A-Za-z0-9:._-]`).
    pub shard_id: String,
    /// Optional owner account. When set, only this `user_id` (or an
    /// `admin`-scoped key) may write to the shard.
    #[serde(default)]
    pub owner_user_id: Option<String>,
    /// Optional human-readable label.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ShardRecord {
    pub shard_id: String,
    pub owner_user_id: Option<String>,
    pub label: Option<String>,
    pub created_by: String,
    pub active: bool,
}

// ── Shard-id validation ───────────────────────────────────────────────────────

/// Delegates to the shared `sanitize_shard` validator in `api::ingest` to
/// ensure the registration path and the ingest write path enforce the same
/// rule (audit F-8): non-empty, ≤128 chars, `[A-Za-z0-9:._-]` only. A shard
/// that can be registered but never written (or vice-versa) would be a footgun.
fn valid_shard_id(s: &str) -> bool {
    sanitize_shard(s)
}

/// Normalise an optional string field: trim, then treat blank as absent.
fn norm_opt(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

// ── Route: POST /admin/shards — register (authorize) a shard ────────────────────

/// Register a shard. Admin-gated. Idempotency: registering an already-registered
/// `shard_id` returns `409 CONFLICT` rather than silently overwriting its
/// owner/label (the operator must be explicit about re-binding ownership).
async fn register_shard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterShardRequest>,
) -> Result<(StatusCode, Json<ShardRecord>), ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_auth(&headers, pool, &state.bjj_trusted_issuers).await?;

    let shard_id = req.shard_id.trim();
    if !valid_shard_id(shard_id) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "shard_id must be 1–128 chars of [A-Za-z0-9:._-].",
        ));
    }
    let owner = norm_opt(req.owner_user_id);
    let label = norm_opt(req.label);

    // Reject a binding to a non-existent owner up front. The `shards` table
    // intentionally has no FK on `owner_user_id` (the authorization model
    // compares `authed.user_id` strings, and a FK would couple shard lifecycle
    // to user-row deletion), so the existence check is enforced here instead.
    // Inline query to match the rest of `api/` — this codebase has no
    // repository layer; every handler uses sqlx directly.
    if let Some(ref owner_id) = owner {
        let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
            .bind(owner_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?;
        if exists.is_none() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "owner_user_id does not reference an existing user.",
            ));
        }
    }

    let rec: Option<ShardRecord> = sqlx::query_as::<_, ShardRecord>(
        r#"
        INSERT INTO shards (shard_id, owner_user_id, label, created_by)
        VALUES ($1, $2, $3, 'admin')
        ON CONFLICT (shard_id) DO NOTHING
        RETURNING shard_id, owner_user_id, label, created_by, active
        "#,
    )
    .bind(shard_id)
    .bind(owner.as_deref())
    .bind(label.as_deref())
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    match rec {
        Some(r) => Ok((StatusCode::CREATED, Json(r))),
        // ON CONFLICT DO NOTHING returned no row: shard already registered.
        None => Err(err(StatusCode::CONFLICT, "shard_id already registered.")),
    }
}

// ── Route: GET /admin/shards — list registered shards ───────────────────────────

async fn list_shards(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ShardRecord>>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_auth(&headers, pool, &state.bjj_trusted_issuers).await?;

    let rows: Vec<ShardRecord> = sqlx::query_as::<_, ShardRecord>(
        r#"
        SELECT shard_id, owner_user_id, label, created_by, active
        FROM shards
        ORDER BY created_at ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rows))
}

// ── Fail-closed write gate ──────────────────────────────────────────────────────

/// Authorize a write (ingest commit) to `shard_id`. Called unconditionally on
/// the ingest path — enforcement is always on (fail-closed).
///
/// Returns:
///   * `Ok(())` if the shard is registered + active and the writer is permitted;
///   * `403 FORBIDDEN` if the shard is unregistered/inactive (creating it
///     requires an operator) or the writer is not its assigned owner;
///   * `503` if the DB is unavailable; `500` on a query error.
///
/// `admin`-scoped keys bypass the owner check but still require the shard to be
/// registered and active — an admin can write into any registered shard, but
/// even an admin cannot conjure an unregistered one through the ingest path
/// (that must go through `POST /admin/shards`, keeping creation auditable).
pub async fn authorize_write(
    state: &AppState,
    authed: &AuthenticatedKey,
    shard_id: &str,
) -> Result<(), ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row: Option<(Option<String>, bool)> = sqlx::query_as(
        r#"SELECT owner_user_id, active FROM shards WHERE shard_id = $1"#,
    )
    .bind(shard_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Unregistered shard: first use must be authorized by an operator.
    let (owner_user_id, active) = row.ok_or_else(|| {
        err(
            StatusCode::FORBIDDEN,
            "shard_id is not registered — an operator must register it via POST /admin/shards \
             before it can be written to.",
        )
    })?;
    if !active {
        return Err(err(StatusCode::FORBIDDEN, "shard_id is deactivated."));
    }

    // Assigned-namespace enforcement. `admin`-scoped keys bypass the owner check.
    if let Some(owner) = owner_user_id {
        let is_owner = authed.user_id.to_string() == owner;
        if !is_owner && !authed.has_scope("admin") {
            return Err(err(
                StatusCode::FORBIDDEN,
                "API key is not authorized to write to this shard.",
            ));
        }
    }

    Ok(())
}

// ── Router ──────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route("/admin/shards", post(register_shard).get(list_shards))
}

// ── Tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_shard_id_accepts_legal_ids() {
        for s in ["files", "shard-1", "a.b_c", "ns:sub:1", &"x".repeat(128)] {
            assert!(valid_shard_id(s), "{s:?} should be valid");
        }
    }

    #[test]
    fn valid_shard_id_rejects_illegal_ids() {
        assert!(!valid_shard_id(""), "empty must be rejected");
        assert!(!valid_shard_id(&"x".repeat(129)), "over 128 chars rejected");
        for s in ["has space", "slash/here", "uni\u{00e9}code", "semi;colon", "back\\slash"] {
            assert!(!valid_shard_id(s), "{s:?} should be rejected");
        }
    }

    #[test]
    fn norm_opt_blanks_to_none() {
        assert_eq!(norm_opt(None), None);
        assert_eq!(norm_opt(Some("  ".to_owned())), None);
        assert_eq!(norm_opt(Some("".to_owned())), None);
        assert_eq!(norm_opt(Some("  abc ".to_owned())), Some("abc".to_owned()));
    }
}
