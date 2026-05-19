//! Key management routes — port of selected endpoints from `api/routers/keys.py`.
//!
//! In scope for Phase 2B
//! ---------------------
//! POST   /key/admin/generate          — generate API key material (admin-protected)
//! POST   /key/admin/reload-keys       — verify admin auth + report DB key count
//! POST   /key/signing                 — register an Ed25519 signing key
//! GET    /key/signing                 — list caller's signing keys
//! DELETE /key/signing/{key_id}        — revoke a signing key
//! POST   /key/signing/dev-generate    — dev-only first-boot helper
//!
//! Deferred to a later phase
//! -------------------------
//! Credential issue/revoke, consent challenges, EVM mint-queue, wallet binding.
//! Those endpoints require additional DB tables (key_credentials,
//! credential_consents, evm_pending_ops, account_wallet_bindings) not yet
//! present in the Phase 2B schema.
//!
//! # Signing-key possession proof
//!
//! POST /key/signing requires an Ed25519 signature over the canonical JSON:
//! `{"domain":"OLYMPUS:SIGNING_KEY_BINDING:V1","label":"…","public_key":"…","purpose":"…"}`
//! (keys lexicographically sorted, no whitespace — matches `signing_key_binding_payload`
//! in the Python router).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::api::middleware::auth::{blake3_key_hash, AuthenticatedKey, RateLimit};
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────────

const SIGNING_KEY_BINDING_DOMAIN: &str = "OLYMPUS:SIGNING_KEY_BINDING:V1";

const VALID_SIGNING_KEY_PURPOSES: &[&str] =
    &["dataset", "witness", "federation", "operator"];

const VALID_SCOPES: &[&str] =
    &["read", "write", "ingest", "commit", "verify", "admin"];

// ── Error helpers ─────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn err_code(status: StatusCode, detail: &str, code: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail, "code": code})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SigningKeyRow {
    key_id: Uuid,
    user_id: Uuid,
    public_key: String,
    label: String,
    purpose: String,
    created_at: NaiveDateTime,
    revoked_at: Option<NaiveDateTime>,
    replaced_by_key_id: Option<Uuid>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct GenerateKeyResponse {
    pub raw_key: String,
    pub key_hash: String,
    pub key_id: String,
    pub scopes: Vec<String>,
    pub expires_at: String,
    /// JSON blob ready to paste into `OLYMPUS_API_KEYS_JSON`.
    pub env_entry: String,
}

#[derive(Serialize)]
pub struct SigningKeyResponse {
    pub key_id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub label: String,
    pub purpose: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub replaced_by_key_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct SigningKeyDevGenerateResponse {
    pub key_id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub label: String,
    pub purpose: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub replaced_by_key_id: Option<Uuid>,
    /// Private key returned **once only** — dev bootstrap, never in production.
    pub private_key: String,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateKeyRequest {
    pub name: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_expiry")]
    pub expires_at: String,
}

fn default_scopes() -> Vec<String> {
    vec!["ingest".to_owned(), "verify".to_owned()]
}
fn default_expiry() -> String {
    "2099-01-01T00:00:00Z".to_owned()
}

#[derive(Deserialize)]
pub struct SigningKeyRegisterRequest {
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    #[serde(default = "default_label")]
    pub label: String,
    #[serde(default = "default_purpose")]
    pub purpose: String,
    /// Ed25519 signature over `signing_key_binding_payload(…)` — proves key possession.
    pub proof_signature: Option<String>,
}

fn default_label() -> String {
    "default".to_owned()
}
fn default_purpose() -> String {
    "dataset".to_owned()
}

#[derive(Deserialize)]
pub struct SigningKeyDevGenerateRequest {
    #[serde(default = "default_dev_label")]
    pub label: String,
    #[serde(default = "default_purpose")]
    pub purpose: String,
}

fn default_dev_label() -> String {
    "dev-first-boot".to_owned()
}

// ── Helper: admin key guard ───────────────────────────────────────────────────

fn require_admin_key(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    let admin_key = std::env::var("OLYMPUS_ADMIN_KEY").unwrap_or_default();
    if admin_key.is_empty() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin key not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        ));
    }
    let provided = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Constant-time comparison — prevents timing oracle on admin key.
    if !bool::from(provided.as_bytes().ct_eq(admin_key.as_bytes())) {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid admin key."));
    }
    Ok(())
}

// ── Helper: signing key payload + verification ────────────────────────────────

/// Canonical JSON payload the holder signs to prove Ed25519 key possession.
/// Matches `signing_key_binding_payload` in `api/routers/keys.py`:
/// keys are lexicographically sorted, no whitespace.
fn signing_key_binding_payload(public_key: &str, label: &str, purpose: &str) -> Vec<u8> {
    // Manual construction matches Python's `json.dumps(…, sort_keys=True,
    // separators=(",", ":"))` which produces the same canonical bytes.
    let payload = serde_json::json!({
        "domain": SIGNING_KEY_BINDING_DOMAIN,
        "label": label,
        "public_key": public_key,
        "purpose": purpose,
    });
    // serde_json serialises object keys in insertion order; use a BTreeMap to
    // guarantee lexicographic ordering matching Python's sort_keys=True.
    let ordered: std::collections::BTreeMap<&str, &serde_json::Value> = payload
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    serde_json::to_vec(&ordered).expect("BTreeMap<&str,&Value> always serialises")
}

/// Verify an Ed25519 possession proof for a signing-key registration request.
fn verify_signing_key_possession(
    public_key_hex: &str,
    label: &str,
    purpose: &str,
    signature_hex: Option<&str>,
) -> Result<(), ApiError> {
    let sig_hex = signature_hex.ok_or_else(|| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof_signature is required to register a signing key.",
            "SIGNING_KEY_SIGNATURE_REQUIRED",
        )
    })?;

    let pk_bytes = hex::decode(public_key_hex).map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be hex-encoded.",
            "INVALID_PUBLIC_KEY",
        )
    })?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be a 32-byte Ed25519 public key.",
            "INVALID_PUBLIC_KEY",
        )
    })?;

    let sig_bytes = hex::decode(sig_hex).map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof_signature must be hex-encoded.",
            "SIGNING_KEY_SIGNATURE_INVALID",
        )
    })?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof_signature must be a 64-byte Ed25519 signature.",
            "SIGNING_KEY_SIGNATURE_INVALID",
        )
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key is not a valid Ed25519 public key.",
            "INVALID_PUBLIC_KEY",
        )
    })?;
    let signature = Signature::from_bytes(&sig_array);
    let message = signing_key_binding_payload(public_key_hex, label, purpose);

    verifying_key.verify(&message, &signature).map_err(|_| {
        err_code(
            StatusCode::FORBIDDEN,
            "Invalid Ed25519 signing-key proof.",
            "SIGNING_KEY_SIGNATURE_INVALID",
        )
    })
}

// ── Helper: row → response ────────────────────────────────────────────────────

fn signing_key_response(row: &SigningKeyRow) -> SigningKeyResponse {
    SigningKeyResponse {
        key_id: row.key_id,
        user_id: row.user_id,
        public_key: row.public_key.clone(),
        label: row.label.clone(),
        purpose: row.purpose.clone(),
        created_at: row.created_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        revoked_at: row
            .revoked_at
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string()),
        replaced_by_key_id: row.replaced_by_key_id,
    }
}

fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── Route: POST /key/admin/generate ──────────────────────────────────────────

/// Generate a new API key and return the raw key + BLAKE3 hash + env-var entry.
///
/// Protected by `X-Admin-Key`.  The raw key is returned once — the caller must
/// store it.  The `env_entry` field is the JSON blob to add to
/// `OLYMPUS_API_KEYS_JSON` (legacy env-var auth path) or to feed into
/// `POST /auth/admin/users` for DB-backed auth.
///
/// This endpoint performs no DB write — it is a pure key-material generator.
async fn admin_generate_key(
    headers: HeaderMap,
    _rl: RateLimit,
    Json(body): Json<GenerateKeyRequest>,
) -> Result<Json<GenerateKeyResponse>, ApiError> {
    require_admin_key(&headers)?;

    // Validate scopes.
    let valid_set: std::collections::HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let unknown: Vec<&str> = body
        .scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !valid_set.contains(*s))
        .collect();
    if !unknown.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("Unknown scope(s): {}", unknown.join(", ")),
        ));
    }

    // Validate expires_at parses.
    let normalised = body.expires_at.replace('Z', "+00:00");
    chrono::DateTime::parse_from_rfc3339(&normalised).map_err(|_| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("expires_at must be ISO 8601, e.g. 2027-01-01T00:00:00Z"),
        )
    })?;

    let mut raw_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_bytes);
    let raw_key = hex::encode(raw_bytes);
    let key_hash = blake3_key_hash(&raw_key);

    let entry = serde_json::json!({
        "key_hash": key_hash,
        "key_id":   body.name,
        "scopes":   body.scopes,
        "expires_at": body.expires_at,
    });

    Ok(Json(GenerateKeyResponse {
        raw_key,
        key_hash,
        key_id: body.name.clone(),
        scopes: body.scopes,
        expires_at: body.expires_at,
        env_entry: serde_json::to_string(&entry).expect("json serialisation"),
    }))
}

// ── Route: POST /key/admin/reload-keys ───────────────────────────────────────

/// Verify admin auth and report the current active API-key count from the DB.
///
/// The Python counterpart hot-reloads `OLYMPUS_API_KEYS_JSON` from the
/// environment (env-var-based auth).  The Tauri version is DB-backed and has
/// no in-memory key store to reload; this endpoint acts as an admin-verified
/// health check and returns the live DB count.
async fn admin_reload_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    _rl: RateLimit,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin_key(&headers)?;

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND expires_at > NOW()",
    )
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(serde_json::json!({
        "reloaded": true,
        "key_count": count,
    })))
}

// ── Route: POST /key/signing ──────────────────────────────────────────────────

/// Register an Ed25519 public signing key to the authenticated DB account.
///
/// Requires `proof_signature` — an Ed25519 signature of
/// `signing_key_binding_payload(public_key, label, purpose)` — to prove the
/// caller controls the corresponding private key.
///
/// Idempotent: re-registering the same key for the same account returns the
/// existing row.  Registering a key that already belongs to a different account
/// returns 409.
async fn register_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<SigningKeyRegisterRequest>,
) -> Result<(StatusCode, Json<SigningKeyResponse>), ApiError> {
    // Validate public_key format first.
    let pk_bytes = hex::decode(&body.public_key).map_err(|_| {
        err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be hex-encoded.",
            "INVALID_PUBLIC_KEY",
        )
    })?;
    if pk_bytes.len() != 32 {
        return Err(err_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key must be a 32-byte Ed25519 public key.",
            "INVALID_PUBLIC_KEY",
        ));
    }
    let public_key_hex = body.public_key.to_lowercase();

    let label = body.label.trim().to_owned();
    if label.is_empty() || label.len() > 128 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1–128 characters.",
        ));
    }
    if !VALID_SIGNING_KEY_PURPOSES.contains(&body.purpose.as_str()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "purpose must be one of: {}",
                VALID_SIGNING_KEY_PURPOSES.join(", ")
            ),
        ));
    }

    // Verify Ed25519 possession proof.
    verify_signing_key_possession(
        &public_key_hex,
        &label,
        &body.purpose,
        body.proof_signature.as_deref(),
    )?;

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    // Idempotency check — return existing active row for the same public key.
    let existing = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE public_key = $1",
    )
    .bind(&public_key_hex)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if let Some(row) = existing {
        if row.user_id != auth.user_id {
            return Err(err(StatusCode::CONFLICT, "Signing key already registered."));
        }
        if row.revoked_at.is_some() {
            return Err(err(StatusCode::CONFLICT, "Signing key has been revoked."));
        }
        return Ok((StatusCode::OK, Json(signing_key_response(&row))));
    }

    let key_id = Uuid::new_v4();
    let now = naive_utc();

    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(key_id)
    .bind(auth.user_id)
    .bind(&public_key_hex)
    .bind(&label)
    .bind(&body.purpose)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let row = SigningKeyRow {
        key_id,
        user_id: auth.user_id,
        public_key: public_key_hex,
        label,
        purpose: body.purpose,
        created_at: now,
        revoked_at: None,
        replaced_by_key_id: None,
    };
    Ok((StatusCode::CREATED, Json(signing_key_response(&row))))
}

// ── Route: GET /key/signing ───────────────────────────────────────────────────

/// List all signing keys registered to the authenticated account.
async fn list_signing_keys(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
) -> Result<Json<Vec<SigningKeyResponse>>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let rows = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE user_id = $1
         ORDER BY created_at",
    )
    .bind(auth.user_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    Ok(Json(rows.iter().map(signing_key_response).collect()))
}

// ── Route: DELETE /key/signing/{key_id} ──────────────────────────────────────

/// Revoke a signing key.  Accepts an optional `replaced_by_key_id` query param
/// to record the superseding key (matches the Python `replaced_by_key_id`
/// query parameter).
async fn revoke_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(key_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<RevokeSigningKeyParams>,
) -> Result<Json<SigningKeyResponse>, ApiError> {
    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    let row = sqlx::query_as::<_, SigningKeyRow>(
        "SELECT key_id, user_id, public_key, label, purpose,
                created_at, revoked_at, replaced_by_key_id
         FROM account_signing_keys
         WHERE key_id = $1 AND user_id = $2",
    )
    .bind(key_id)
    .bind(auth.user_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Signing key not found."))?;

    if row.revoked_at.is_some() {
        return Err(err(StatusCode::CONFLICT, "Signing key already revoked."));
    }

    // Validate replacement key exists and belongs to the same user.
    if let Some(replacement_id) = params.replaced_by_key_id {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM account_signing_keys
             WHERE key_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(replacement_id)
        .bind(auth.user_id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
        if exists == 0 {
            return Err(err(
                StatusCode::NOT_FOUND,
                "Replacement signing key not found.",
            ));
        }
    }

    let now = naive_utc();
    sqlx::query(
        "UPDATE account_signing_keys
         SET revoked_at = $1,
             replaced_by_key_id = $2,
             revoked_by_key_id = $3
         WHERE key_id = $4",
    )
    .bind(now)
    .bind(params.replaced_by_key_id)
    .bind(auth.db_id)  // the api_keys.id that performed the revocation
    .bind(key_id)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let updated = SigningKeyRow {
        revoked_at: Some(now),
        replaced_by_key_id: params.replaced_by_key_id,
        ..row
    };
    Ok(Json(signing_key_response(&updated)))
}

#[derive(Deserialize)]
pub struct RevokeSigningKeyParams {
    pub replaced_by_key_id: Option<Uuid>,
}

// ── Route: POST /key/signing/dev-generate ─────────────────────────────────────

/// Dev-only first-boot helper: generate an Ed25519 keypair, register the
/// public key, and return the **private key once only**.
///
/// Only active when `OLYMPUS_ENV=development` AND
/// `OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP=1`.
async fn dev_generate_signing_key(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<SigningKeyDevGenerateRequest>,
) -> Result<(StatusCode, Json<SigningKeyDevGenerateResponse>), ApiError> {
    let dev_mode = std::env::var("OLYMPUS_ENV").ok().as_deref() == Some("development");
    let bootstrap_allowed = std::env::var("OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP")
        .ok()
        .as_deref()
        == Some("1");
    if !dev_mode || !bootstrap_allowed {
        return Err(err(StatusCode::NOT_FOUND, "Not found."));
    }

    let pool = state.pool.as_ref().ok_or_else(|| {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable.")
    })?;

    // Generate Ed25519 keypair.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let private_key_hex = hex::encode(signing_key.to_bytes());

    let label = body.label.trim().to_owned();
    let key_id = Uuid::new_v4();
    let now = naive_utc();

    sqlx::query(
        "INSERT INTO account_signing_keys
             (key_id, user_id, public_key, label, purpose, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(key_id)
    .bind(auth.user_id)
    .bind(&public_key_hex)
    .bind(&label)
    .bind(&body.purpose)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db_err)?;

    tracing::warn!(
        "Dev-generated signing key {} for user={}; private key returned once only",
        key_id,
        auth.user_id,
    );

    Ok((
        StatusCode::CREATED,
        Json(SigningKeyDevGenerateResponse {
            key_id,
            user_id: auth.user_id,
            public_key: public_key_hex,
            label,
            purpose: body.purpose,
            created_at: now.format("%Y-%m-%dT%H:%M:%S").to_string(),
            revoked_at: None,
            replaced_by_key_id: None,
            private_key: private_key_hex,
        }),
    ))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/key/admin/generate", post(admin_generate_key))
        .route("/key/admin/reload-keys", post(admin_reload_keys))
        .route("/key/signing", post(register_signing_key).get(list_signing_keys))
        .route("/key/signing/dev-generate", post(dev_generate_signing_key))
        .route("/key/signing/{key_id}", delete(revoke_signing_key))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_key_binding_payload_is_sorted_json() {
        let payload = signing_key_binding_payload("aabbcc", "my-label", "dataset");
        let s = std::str::from_utf8(&payload).unwrap();
        // Keys must appear in lexicographic order: domain, label, public_key, purpose.
        let domain_pos = s.find("\"domain\"").unwrap();
        let label_pos = s.find("\"label\"").unwrap();
        let pk_pos = s.find("\"public_key\"").unwrap();
        let purpose_pos = s.find("\"purpose\"").unwrap();
        assert!(domain_pos < label_pos, "domain before label");
        assert!(label_pos < pk_pos, "label before public_key");
        assert!(pk_pos < purpose_pos, "public_key before purpose");
    }

    #[test]
    fn signing_key_binding_payload_contains_domain() {
        let payload = signing_key_binding_payload("aa", "lbl", "dataset");
        let s = std::str::from_utf8(&payload).unwrap();
        assert!(s.contains(SIGNING_KEY_BINDING_DOMAIN));
    }

    #[test]
    fn verify_possession_rejects_missing_signature() {
        let result = verify_signing_key_possession("aabb", "lbl", "dataset", None);
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn verify_possession_rejects_bad_hex_key() {
        let result =
            verify_signing_key_possession("not-hex!!", "lbl", "dataset", Some("aabb"));
        assert!(result.is_err());
    }

    #[test]
    fn verify_possession_roundtrip() {
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let label = "test";
        let purpose = "dataset";
        let message = signing_key_binding_payload(&pk_hex, label, purpose);
        let sig = signing_key.sign(&message);
        let sig_hex = hex::encode(sig.to_bytes());
        assert!(
            verify_signing_key_possession(&pk_hex, label, purpose, Some(&sig_hex)).is_ok(),
            "valid proof must pass"
        );
    }

    #[test]
    fn verify_possession_rejects_wrong_message() {
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        // Sign the wrong message (different purpose).
        let wrong_message = signing_key_binding_payload(&pk_hex, "label", "witness");
        let sig = signing_key.sign(&wrong_message);
        let sig_hex = hex::encode(sig.to_bytes());
        assert!(
            verify_signing_key_possession(&pk_hex, "label", "dataset", Some(&sig_hex)).is_err(),
            "proof over wrong message must fail"
        );
    }
}
