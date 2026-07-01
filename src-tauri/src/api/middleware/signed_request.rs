//! ADR-0036 signed request envelope extractor.
//!
//! The extractor is intentionally not wired onto mutating routes yet. It is the
//! reusable verification boundary those routes can adopt incrementally.

use axum::{
    body::Bytes,
    extract::{FromRef, FromRequest, Request},
    http::{Method, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use olympus_crypto::{
    request_envelope::{signed_request_message, REQUEST_V1_DOMAIN_SEPARATOR, REQUEST_V1_PREFIX},
    signature_envelope::{
        SignatureAlgorithm, SignatureEnvelopeError, SignatureEnvelopeV2, SignatureVerificationMode,
        VerifiedEnvelope,
    },
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;

const DEFAULT_FRESHNESS_SECS: i64 = 300;
const MAX_FRESHNESS_SECS: i64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequestV1 {
    pub operator_id: String,
    pub key_id: String,
    pub method: String,
    pub path: String,
    pub body_hash: [u8; 32],
    pub timestamp_utc: i64,
    pub nonce: String,
    pub scope: String,
}

impl SignedRequestV1 {
    pub fn message(&self) -> [u8; 32] {
        signed_request_message(
            self.operator_id.as_bytes(),
            self.key_id.as_bytes(),
            self.method.as_bytes(),
            self.path.as_bytes(),
            &self.body_hash,
            self.timestamp_utc,
            self.nonce.as_bytes(),
            self.scope.as_bytes(),
        )
    }
}

pub struct VerifiedSignedRequest<T> {
    pub payload: T,
    pub request: SignedRequestV1,
    pub verified: VerifiedEnvelope,
}

impl<T> VerifiedSignedRequest<T> {
    pub fn require_scope(&self, scope: &str) -> Result<(), SignedRequestRejection> {
        if self.request.scope == scope {
            Ok(())
        } else {
            Err(SignedRequestRejection::forbidden(
                "Signed scope is insufficient.",
            ))
        }
    }
}

#[derive(Debug)]
pub struct SignedRequestRejection {
    status: StatusCode,
    detail: &'static str,
}

impl SignedRequestRejection {
    fn bad_request(detail: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            detail,
        }
    }

    fn unauthorized(detail: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            detail,
        }
    }

    fn forbidden(detail: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            detail,
        }
    }

    fn conflict(detail: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            detail,
        }
    }

    fn unavailable(detail: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            detail,
        }
    }

    fn internal(detail: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail,
        }
    }
}

impl axum::response::IntoResponse for SignedRequestRejection {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(json!({
                "detail": self.detail,
                "code": "SIGNED_REQUEST_REJECTED",
            })),
        )
            .into_response()
    }
}

impl<S, T> FromRequest<S> for VerifiedSignedRequest<T>
where
    S: Send + Sync,
    AppState: FromRef<S>,
    T: DeserializeOwned,
{
    type Rejection = SignedRequestRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        let app_state = AppState::from_ref(state);
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| SignedRequestRejection::bad_request("Invalid request body."))?;

        let parsed = parse_wire_envelope(&body, &method, &path)?;
        let request_message = parsed.request.message();
        if parsed.signature.payload_digest != request_message {
            return Err(SignedRequestRejection::unauthorized(
                "Signature payload digest does not match signed request.",
            ));
        }
        if parsed.signature.domain_separator.as_str() != REQUEST_V1_DOMAIN_SEPARATOR {
            return Err(SignedRequestRejection::unauthorized(
                "Signature envelope domain is not OLY:REQUEST:V1.",
            ));
        }

        let verified = parsed
            .signature
            .verify(SignatureVerificationMode::ClassicalRequired)
            .map_err(map_signature_error)?;

        let pool = app_state.pool.as_ref().ok_or_else(|| {
            SignedRequestRejection::unavailable("Database unavailable for replay cache.")
        })?;
        reserve_nonce(pool, &parsed.request, &request_message).await?;

        if parsed
            .signature
            .suite
            .descriptor()
            .algorithms
            .contains(&SignatureAlgorithm::MlDsa65)
        {
            let sig = parsed.signature.clone();
            let hybrid = tokio::task::spawn_blocking(move || {
                sig.verify(SignatureVerificationMode::HybridRequired)
            })
            .await
            .map_err(|_| SignedRequestRejection::internal("Hybrid verifier task failed."))?;

            if let Err(e) = hybrid {
                let _ = rollback_nonce(pool, &parsed.request).await;
                return Err(map_signature_error(e));
            }
        }

        let payload = serde_json::from_slice::<T>(&parsed.payload_canonical)
            .map_err(|_| SignedRequestRejection::bad_request("Invalid payload schema."))?;

        Ok(Self {
            payload,
            request: parsed.request,
            verified,
        })
    }
}

#[derive(Debug)]
struct ParsedEnvelope {
    request: SignedRequestV1,
    signature: SignatureEnvelopeV2,
    payload_canonical: Vec<u8>,
}

#[derive(Deserialize)]
struct WireEnvelope {
    request: WireSignedRequestV1,
    signature: SignatureEnvelopeV2,
    payload_canonical_b64: String,
}

#[derive(Deserialize)]
struct WireSignedRequestV1 {
    operator_id: String,
    key_id: String,
    method: String,
    path: String,
    body_hash_hex: String,
    timestamp_utc: i64,
    nonce: String,
    scope: String,
}

fn parse_wire_envelope(
    body: &[u8],
    actual_method: &Method,
    actual_path: &str,
) -> Result<ParsedEnvelope, SignedRequestRejection> {
    let wire: WireEnvelope = serde_json::from_slice(body)
        .map_err(|_| SignedRequestRejection::bad_request("Malformed signed request envelope."))?;

    let payload_canonical = B64
        .decode(wire.payload_canonical_b64.as_bytes())
        .map_err(|_| SignedRequestRejection::bad_request("Payload is not valid base64."))?;
    let recanonicalized = olympus_crypto::canonical::canonicalize_bytes(&payload_canonical)
        .map_err(|_| SignedRequestRejection::bad_request("Payload is not canonical JSON."))?;
    if recanonicalized != payload_canonical {
        return Err(SignedRequestRejection::bad_request(
            "Payload must be JCS canonical JSON.",
        ));
    }

    let body_hash = parse_hex32(&wire.request.body_hash_hex)?;
    let expected_body_hash = *blake3::hash(&payload_canonical).as_bytes();
    if body_hash != expected_body_hash {
        return Err(SignedRequestRejection::unauthorized(
            "Signed body hash does not match payload.",
        ));
    }

    if wire.request.method != actual_method.as_str() || wire.request.path != actual_path {
        return Err(SignedRequestRejection::unauthorized(
            "Signed method/path does not match request.",
        ));
    }
    for field in [
        wire.request.operator_id.as_str(),
        wire.request.key_id.as_str(),
        wire.request.method.as_str(),
        wire.request.path.as_str(),
        wire.request.nonce.as_str(),
        wire.request.scope.as_str(),
    ] {
        if field.is_empty() {
            return Err(SignedRequestRejection::bad_request(
                "Signed request fields must be non-empty.",
            ));
        }
    }

    let request = SignedRequestV1 {
        operator_id: wire.request.operator_id,
        key_id: wire.request.key_id,
        method: wire.request.method,
        path: wire.request.path,
        body_hash,
        timestamp_utc: wire.request.timestamp_utc,
        nonce: wire.request.nonce,
        scope: wire.request.scope,
    };
    enforce_freshness(request.timestamp_utc)?;

    Ok(ParsedEnvelope {
        request,
        signature: wire.signature,
        payload_canonical,
    })
}

fn parse_hex32(s: &str) -> Result<[u8; 32], SignedRequestRejection> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SignedRequestRejection::bad_request(
            "body_hash_hex must be 32-byte lowercase hex.",
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out)
        .map_err(|_| SignedRequestRejection::bad_request("body_hash_hex is malformed."))?;
    Ok(out)
}

fn enforce_freshness(timestamp_utc: i64) -> Result<(), SignedRequestRejection> {
    let now = chrono::Utc::now().timestamp();
    let window = signed_request_freshness_secs();
    if timestamp_utc < now.saturating_sub(window) || timestamp_utc > now.saturating_add(window) {
        return Err(SignedRequestRejection::unauthorized(
            "Signed request timestamp is outside the freshness window.",
        ));
    }
    Ok(())
}

fn signed_request_freshness_secs() -> i64 {
    std::env::var("OLYMPUS_SIGNED_REQUEST_FRESHNESS_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0)
        .map(|v| v.min(MAX_FRESHNESS_SECS))
        .unwrap_or(DEFAULT_FRESHNESS_SECS)
}

async fn reserve_nonce(
    pool: &sqlx::PgPool,
    request: &SignedRequestV1,
    request_digest: &[u8; 32],
) -> Result<(), SignedRequestRejection> {
    let expires_at =
        chrono::Utc::now().naive_utc() + chrono::Duration::seconds(signed_request_freshness_secs());
    let result = sqlx::query(
        "INSERT INTO signed_request_nonces
            (key_id, nonce, operator_id, scope, request_digest, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (key_id, nonce) DO NOTHING",
    )
    .bind(&request.key_id)
    .bind(&request.nonce)
    .bind(&request.operator_id)
    .bind(&request.scope)
    .bind(request_digest.as_slice())
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!("signed request replay-cache insert failed: {e}");
        SignedRequestRejection::internal("Replay cache unavailable.")
    })?;

    if result.rows_affected() == 0 {
        return Err(SignedRequestRejection::conflict(
            "Signed request nonce has already been used.",
        ));
    }
    Ok(())
}

async fn rollback_nonce(pool: &sqlx::PgPool, request: &SignedRequestV1) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM signed_request_nonces WHERE key_id = $1 AND nonce = $2")
        .bind(&request.key_id)
        .bind(&request.nonce)
        .execute(pool)
        .await?;
    Ok(())
}

fn map_signature_error(e: SignatureEnvelopeError) -> SignedRequestRejection {
    match e {
        SignatureEnvelopeError::UnsupportedAlgorithm(SignatureAlgorithm::MlDsa65) => {
            SignedRequestRejection::unauthorized("ML-DSA-65 verification is not enabled.")
        }
        _ => SignedRequestRejection::unauthorized("Signature verification failed."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use olympus_crypto::signature_envelope::{
        DomainSeparator, SignatureComponent, SignatureEnvelopeV2, SignatureSuite,
    };
    use serde_json::json;

    fn signed_envelope_body(method: &str, path: &str, payload: &[u8]) -> Vec<u8> {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let body_hash = *blake3::hash(payload).as_bytes();
        let request = SignedRequestV1 {
            operator_id: "operator-a".to_string(),
            key_id: "key-1".to_string(),
            method: method.to_string(),
            path: path.to_string(),
            body_hash,
            timestamp_utc: chrono::Utc::now().timestamp(),
            nonce: "nonce-123".to_string(),
            scope: "ingest".to_string(),
        };
        let signature = SignatureEnvelopeV2::sign_ed25519(
            DomainSeparator::new(REQUEST_V1_DOMAIN_SEPARATOR).unwrap(),
            request.message(),
            &sk,
        );
        serde_json::to_vec(&json!({
            "request": {
                "operator_id": request.operator_id,
                "key_id": request.key_id,
                "method": request.method,
                "path": request.path,
                "body_hash_hex": hex::encode(request.body_hash),
                "timestamp_utc": request.timestamp_utc,
                "nonce": request.nonce,
                "scope": request.scope,
            },
            "signature": signature,
            "payload_canonical_b64": B64.encode(payload),
        }))
        .unwrap()
    }

    #[test]
    fn parse_wire_envelope_accepts_valid_classical_request() {
        let payload = br#"{"a":1,"b":true}"#;
        let body = signed_envelope_body("POST", "/ingest/files", payload);
        let parsed = parse_wire_envelope(&body, &Method::POST, "/ingest/files").unwrap();
        assert_eq!(parsed.payload_canonical, payload);
        assert_eq!(parsed.request.scope, "ingest");
        assert_eq!(
            parsed.signature.domain_separator.as_str(),
            REQUEST_V1_DOMAIN_SEPARATOR
        );
    }

    #[test]
    fn parse_wire_envelope_rejects_path_swap() {
        let payload = br#"{"a":1}"#;
        let body = signed_envelope_body("POST", "/ingest/files", payload);
        let err = parse_wire_envelope(&body, &Method::POST, "/admin/shards").unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn parse_wire_envelope_rejects_noncanonical_payload() {
        let payload = br#"{ "b": true, "a": 1 }"#;
        let body = signed_envelope_body("POST", "/ingest/files", payload);
        let err = parse_wire_envelope(&body, &Method::POST, "/ingest/files").unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn hybrid_shape_is_classically_verifiable_before_hybrid_required_fails() {
        let payload = br#"{"a":1}"#;
        let mut body: serde_json::Value =
            serde_json::from_slice(&signed_envelope_body("POST", "/ingest/files", payload))
                .unwrap();
        let signature = body.get_mut("signature").unwrap();
        signature["suite"] = json!("hybrid-ed25519-ml-dsa65");
        signature["signatures"]
            .as_array_mut()
            .unwrap()
            .push(json!(SignatureComponent {
                algorithm: SignatureAlgorithm::MlDsa65,
                public_key: vec![0x22; 1952],
                signature: vec![0x33; 3309],
            }));
        let body = serde_json::to_vec(&body).unwrap();
        let parsed = parse_wire_envelope(&body, &Method::POST, "/ingest/files").unwrap();
        assert_eq!(parsed.signature.suite, SignatureSuite::HybridEd25519MlDsa65);
        assert!(parsed
            .signature
            .verify(SignatureVerificationMode::ClassicalRequired)
            .is_ok());
        assert!(matches!(
            parsed
                .signature
                .verify(SignatureVerificationMode::HybridRequired),
            Err(SignatureEnvelopeError::UnsupportedAlgorithm(
                SignatureAlgorithm::MlDsa65
            ))
        ));
    }

    #[test]
    fn request_prefix_is_pinned_to_adr_0036() {
        assert_eq!(REQUEST_V1_PREFIX, b"OLY:REQUEST:V1");
    }
}
