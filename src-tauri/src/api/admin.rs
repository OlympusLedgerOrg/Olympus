use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use super::auth::AuthedKey;
use super::error::ApiResult;
use super::state::AppState;

#[derive(Debug, Serialize)]
pub struct AdminStats {
    pub total_users: i64,
    pub total_api_keys: i64,
    pub total_doc_commits: i64,
    pub total_tsa_jobs_pending: i64,
    pub total_ledger_activities: i64,
}

pub async fn get_admin_stats(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
) -> ApiResult<Json<AdminStats>> {
    authed.require_scope("admin")?;

    let (users, api_keys, commits, tsa_pending, activities) = tokio::try_join!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL",
        )
        .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM doc_commits")
            .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tsa_jobs WHERE status = 'pending'",
        )
        .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ledger_activities")
            .fetch_one(&state.pool),
    )?;

    Ok(Json(AdminStats {
        total_users: users,
        total_api_keys: api_keys,
        total_doc_commits: commits,
        total_tsa_jobs_pending: tsa_pending,
        total_ledger_activities: activities,
    }))
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    authed: AuthedKey,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    authed.require_scope("admin")?;

    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT json_build_object('id', id, 'email', email, 'role', role, 'plan', plan, 'created_at', created_at) \
         FROM users ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}
