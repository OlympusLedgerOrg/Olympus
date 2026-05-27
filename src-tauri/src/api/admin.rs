//! Admin RBAC endpoints — platform statistics and customer management.
//!
//! Port of `api/routers/admin.py`.
//!
//! All endpoints require admin authority — either:
//!   (a) `X-Admin-Key` header matching `OLYMPUS_ADMIN_KEY`, or
//!   (b) a valid API key with the `admin` scope belonging to an `admin`-role user.
//!
//! Routes
//! ------
//! GET /api/admin/stats              — aggregated platform metrics
//! GET /api/admin/customers          — paginated customer list (newest first)
//! GET /api/admin/customers/export   — CSV download of all customers
//!
//! # MRR / purchases
//!
//! The Python router computes MRR from a `purchases` table.  The Tauri
//! embedded DB does not include purchases; `mrr` and `total_revenue` are
//! always 0.0 in this port.

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, Response, StatusCode},
    routing::get,
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::blake3_key_hash;
use crate::state::AppState;

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

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    role: String,
    plan: String,
    created_at: NaiveDateTime,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct PlatformStatsResponse {
    pub mrr: f64,
    pub total_revenue: f64,
    pub user_count: i64,
    pub conversion_rate: f64,
}

#[derive(Serialize)]
pub struct CustomerResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub plan: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct CustomerListResponse {
    pub items: Vec<CustomerResponse>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CustomerListParams {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
}

fn default_page() -> i64 {
    1
}
fn default_per_page() -> i64 {
    20
}

#[derive(Deserialize)]
pub struct ExportParams {
    #[serde(default = "default_max_rows")]
    pub max_rows: i64,
}

fn default_max_rows() -> i64 {
    50_000
}

// ── Admin authority guard ─────────────────────────────────────────────────────

/// Accept either the operator secret key or an admin-scoped API key.
///
/// Mirrors `require_admin_authority` in `api/routers/user_auth.py`.
async fn require_admin_authority(headers: &HeaderMap, pool: &sqlx::PgPool) -> Result<(), ApiError> {
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !admin_key.is_empty() && bool::from(provided.as_bytes().ct_eq(admin_key.as_bytes())) {
        return Ok(());
    }

    // Fall back to API-key auth with admin scope.
    let raw = headers
        .get("x-api-key")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
                .unwrap_or(s)
                .trim()
                .to_owned()
        });

    let Some(raw) = raw else {
        return Err(err(StatusCode::UNAUTHORIZED, "Admin access required."));
    };

    let key_hash = blake3_key_hash(&raw);
    let now = naive_utc();

    #[derive(sqlx::FromRow)]
    struct AdminCheck {
        scopes: String,
        user_role: Option<String>,
    }

    let row = sqlx::query_as::<_, AdminCheck>(
        r#"SELECT k.scopes, u.role AS user_role
           FROM api_keys k
           JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = $1
             AND k.revoked_at IS NULL
             AND (k.expires_at IS NULL OR k.expires_at > $2)"#,
    )
    .bind(&key_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Admin access required."))?;

    let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
    let is_admin_role = row.user_role.as_deref() == Some("admin");
    let has_admin_scope = scopes.iter().any(|s| s == "admin");

    // Deliberately AND, not OR: an `admin`-scoped key issued to a user who is
    // later demoted from the `admin` role must lose admin-route access at the
    // next request, even before the key is explicitly revoked. Keep both
    // checks — see audit L-API-3.
    if is_admin_role && has_admin_scope {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Admin access required."))
    }
}

// ── CSV helpers ───────────────────────────────────────────────────────────────

/// Prefix formula-triggering characters with a single quote so a spreadsheet
/// app does not interpret the cell as a formula. This is HALF of the defense
/// against CSV injection — it MUST be paired with the RFC 4180 quote-wrap in
/// `escape_csv_field` below. If a future refactor moves the prefix step OR
/// drops the quote-wrap step, a payload like `="foo,bar"` (containing a comma
/// inside the quoted form) could re-escape the wrapper and re-introduce the
/// formula trigger. Keep both steps in this order; covered by audit L-API-1.
/// Matches `_sanitize_csv_cell` in `api/routers/admin.py`.
fn sanitize_csv_cell(value: &str) -> String {
    const TRIGGERS: &[char] = &['=', '+', '-', '@', '\t', '\r', '\n'];
    if value.starts_with(TRIGGERS) {
        format!("'{value}")
    } else {
        value.to_owned()
    }
}

/// RFC 4180 CSV field encoding: wrap in double-quotes and double any internal quotes
/// when the field contains a comma, double-quote, CR, or LF.
fn escape_csv_field(value: &str) -> String {
    let sanitized = sanitize_csv_cell(value);
    if sanitized.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

// ── Route: GET /api/admin/stats ───────────────────────────────────────────────

async fn get_platform_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PlatformStatsResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_authority(&headers, pool).await?;

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let paid_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE plan != 'free'")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let conversion_rate = if user_count > 0 {
        paid_count as f64 / user_count as f64 * 100.0
    } else {
        0.0
    };

    Ok(Json(PlatformStatsResponse {
        mrr: 0.0,
        total_revenue: 0.0,
        user_count,
        conversion_rate,
    }))
}

// ── Route: GET /api/admin/customers ──────────────────────────────────────────

async fn list_customers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CustomerListParams>,
) -> Result<Json<CustomerListResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_authority(&headers, pool).await?;

    let page = params.page.max(1);
    let per_page =
        crate::api::pagination::clamp_with_log("GET /admin/customers", params.per_page, 1, 100);

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(db_err)?;

    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT id, email, role, plan, created_at
         FROM users
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(CustomerListResponse {
        items: rows.into_iter().map(customer_response).collect(),
        page,
        per_page,
        total,
    }))
}

fn customer_response(row: UserRow) -> CustomerResponse {
    CustomerResponse {
        id: row.id,
        email: row.email,
        role: row.role,
        plan: row.plan,
        created_at: row.created_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
    }
}

// ── Route: GET /api/admin/customers/export ────────────────────────────────────

async fn export_customers_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ExportParams>,
) -> Result<Response<Body>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;
    require_admin_authority(&headers, pool).await?;

    let max_rows = crate::api::pagination::clamp_with_log(
        "GET /admin/customers/export",
        params.max_rows,
        1,
        50_000,
    );
    // Clone the pool handle for the stream task — the handler returns the
    // response immediately and the stream is driven by hyper afterward, so
    // we can't borrow `pool` across that suspension point.
    let pool = pool.clone();

    // Audit finding F-6: stream rows out of Postgres via `fetch()` (cursor-
    // backed) instead of materializing the full Vec via `fetch_all`. Peak
    // memory is now one row, regardless of `max_rows`. The CSV header is
    // emitted as the first chunk; each subsequent chunk is one row.
    let row_stream = async_stream::stream! {
        // Header line: always succeeds.
        yield Ok::<_, sqlx::Error>(axum::body::Bytes::from_static(b"id,email,role,plan,created_at\n"));

        let mut rows = sqlx::query_as::<_, UserRow>(
            "SELECT id, email, role, plan, created_at
             FROM users
             ORDER BY created_at DESC
             LIMIT $1",
        )
        .bind(max_rows)
        .fetch(&pool);

        while let Some(row_res) = futures_util::StreamExt::next(&mut rows).await {
            match row_res {
                Ok(row) => {
                    let line = format!(
                        "{},{},{},{},{}\n",
                        row.id,
                        escape_csv_field(&row.email),
                        escape_csv_field(&row.role),
                        escape_csv_field(&row.plan),
                        row.created_at.format("%Y-%m-%dT%H:%M:%S"),
                    );
                    yield Ok(axum::body::Bytes::from(line));
                }
                Err(e) => {
                    // Propagate as a stream error; Body::from_stream converts
                    // it into a BoxError and hyper truncates the response.
                    yield Err(e);
                    break;
                }
            }
        }
    };
    // `async_stream::try_stream!` produces an `impl Stream<Item = Result<Bytes,
    // sqlx::Error>>` — exactly the TryStream shape `Body::from_stream` wants.
    // `sqlx::Error: std::error::Error + Send + Sync` satisfies `Into<BoxError>`.
    let body = Body::from_stream(row_stream);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/csv")
        .header("Content-Disposition", "attachment; filename=customers.csv")
        .body(body)
        // SAFETY: all header values are static ASCII strings; builder cannot fail.
        .expect("response builder uses static headers");

    Ok(response)
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/admin/stats", get(get_platform_stats))
        .route("/api/admin/customers", get(list_customers))
        .route("/api/admin/customers/export", get(export_customers_csv))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_csv_cell_prefixes_formula_chars() {
        assert_eq!(sanitize_csv_cell("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(sanitize_csv_cell("+cmd"), "'+cmd");
        assert_eq!(sanitize_csv_cell("-1"), "'-1");
        assert_eq!(sanitize_csv_cell("@user"), "'@user");
    }

    #[test]
    fn sanitize_csv_cell_leaves_safe_values_intact() {
        assert_eq!(sanitize_csv_cell("alice@example.com"), "alice@example.com");
        assert_eq!(sanitize_csv_cell("admin"), "admin");
        assert_eq!(sanitize_csv_cell(""), "");
    }

    #[test]
    fn escape_csv_field_wraps_commas_and_quotes() {
        assert_eq!(escape_csv_field("a,b"), "\"a,b\"");
        assert_eq!(escape_csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape_csv_field("line\nnew"), "\"line\nnew\"");
        assert_eq!(escape_csv_field("plain"), "plain");
    }

    #[test]
    fn escape_csv_field_combines_injection_and_quoting() {
        // formula trigger + comma → inject-prefix then RFC 4180 wrap
        assert_eq!(escape_csv_field("=A1,B2"), "\"'=A1,B2\"");
    }

    #[test]
    fn page_clamped_to_min_one() {
        let p = CustomerListParams {
            page: 0,
            per_page: 20,
        };
        assert_eq!(p.page.max(1), 1);
    }

    #[test]
    fn per_page_clamped() {
        let p = CustomerListParams {
            page: 1,
            per_page: 200,
        };
        assert_eq!(p.per_page.clamp(1, 100), 100);
    }
}
