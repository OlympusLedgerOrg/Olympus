//! Shared types and helpers for the `/key/*` routes: constants, error
//! helpers, DB row / request / response types, the Ed25519 possession-proof
//! payload + verification, and label/purpose validation.

use axum::{http::StatusCode, Json};
use chrono::{NaiveDateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Constants ─────────────────────────────────────────────────────────────────

pub(super) const SIGNING_KEY_BINDING_DOMAIN: &str = "OLYMPUS:SIGNING_KEY_BINDING:V1";

pub(super) const VALID_SIGNING_KEY_PURPOSES: &[&str] =
    &["dataset", "witness", "federation", "operator"];

pub(super) const VALID_SCOPES: &[&str] = &[
    "read", "write", "ingest", "commit", "verify", "prove", "admin",
];

// ── Error helpers ─────────────────────────────────────────────────────────────

pub(super) type ApiError = (StatusCode, Json<serde_json::Value>);

pub(super) fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

pub(super) fn err_code(status: StatusCode, detail: &str, code: &str) -> ApiError {
    (
        status,
        Json(serde_json::json!({"detail": detail, "code": code})),
    )
}

pub(super) fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── DB row types ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub(super) struct SigningKeyRow {
    pub(super) key_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) public_key: String,
    pub(super) label: String,
    pub(super) purpose: String,
    pub(super) created_at: NaiveDateTime,
    pub(super) revoked_at: Option<NaiveDateTime>,
    pub(super) replaced_by_key_id: Option<Uuid>,
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

// Dev-only DTO: carries a private key in its body, so it is gated behind the
// opt-in `dev-signing-route` feature (see `dev_generate_signing_key`, `router`).
#[cfg(feature = "dev-signing-route")]
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

#[cfg(feature = "dev-signing-route")]
#[derive(Deserialize)]
pub struct SigningKeyDevGenerateRequest {
    #[serde(default = "default_dev_label")]
    pub label: String,
    #[serde(default = "default_purpose")]
    pub purpose: String,
}

#[cfg(feature = "dev-signing-route")]
fn default_dev_label() -> String {
    "dev-first-boot".to_owned()
}

// ── Helper: signing key payload + verification ────────────────────────────────

/// Canonical JSON payload the holder signs to prove Ed25519 key possession.
/// Matches `signing_key_binding_payload` in `api/routers/keys.py`:
/// keys are lexicographically sorted, no whitespace.
pub(super) fn signing_key_binding_payload(public_key: &str, label: &str, purpose: &str) -> Vec<u8> {
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
pub(super) fn verify_signing_key_possession(
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

pub(super) fn signing_key_response(row: &SigningKeyRow) -> SigningKeyResponse {
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

pub(super) fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── Helper: shared label + purpose validation ────────────────────────────────

/// Validate a signing-key `label` and `purpose`, shared by the public
/// registration path and the dev-only bootstrap path so both persist rows that
/// satisfy the same constraints. Trims the label, enforces 1–128 characters,
/// and requires `purpose` to be one of `VALID_SIGNING_KEY_PURPOSES`. Returns
/// the normalized (trimmed) label on success.
pub(super) fn validate_signing_key_label_purpose(
    label: &str,
    purpose: &str,
) -> Result<String, ApiError> {
    let label = label.trim().to_owned();
    if label.is_empty() || label.len() > 128 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1–128 characters.",
        ));
    }
    if !VALID_SIGNING_KEY_PURPOSES.contains(&purpose) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "purpose must be one of: {}",
                VALID_SIGNING_KEY_PURPOSES.join(", ")
            ),
        ));
    }
    Ok(label)
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
        let result = verify_signing_key_possession("not-hex!!", "lbl", "dataset", Some("aabb"));
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
