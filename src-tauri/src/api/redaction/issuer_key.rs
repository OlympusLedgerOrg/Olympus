//! `GET /redaction/issuer-key` — publish this instance's Ed25519 **verifying
//! key** (ADR-0030).
//!
//! V3 redaction bundles are signed with `state.ingest_signing_key`
//! (`OLYMPUS_INGEST_SIGNING_KEY`); the matching public key is what a recipient /
//! auditor feeds into `bundle_v3::verify` (or the in-app `verifyRedactionBundleV3`)
//! to check the signature. The public key is, by definition, public — so this
//! endpoint is **unauthenticated**, mirroring `/public/stats`, and lets the
//! Redaction-audit UI pre-fill the trust anchor instead of requiring manual hex
//! entry.
//!
//! Trust note: this key is self-reported by the producing instance, so it is a
//! *convenience* anchor for auditing an instance's own output. An independent
//! auditor verifying a bundle from an untrusted source must still obtain the
//! issuer key out-of-band; the UI keeps the field editable for exactly that.

use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::SigningKey;
use serde::Serialize;

use crate::state::AppState;

use super::types::{err, ApiError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerKeyResponse {
    /// The Ed25519 verifying key (32 bytes, lowercase hex) that signs V3
    /// redaction bundles produced by this instance.
    pub ed25519_pubkey_hex: String,
}

/// Return the Ed25519 public key matching the bundle signing key.
///
/// `503` if no ingest signing key is configured (same condition under which
/// `/redaction/redact` cannot sign a bundle).
pub async fn get_issuer_key(
    State(state): State<AppState>,
) -> Result<Json<IssuerKeyResponse>, ApiError> {
    let signing_key = state.ingest_signing_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Redaction signing key unavailable: set OLYMPUS_INGEST_SIGNING_KEY \
             (or OLYMPUS_DEV_SIGNING_KEY=true in dev).",
        )
    })?;
    let vk = SigningKey::from_bytes(&signing_key).verifying_key();
    Ok(Json(IssuerKeyResponse {
        ed25519_pubkey_hex: hex::encode(vk.to_bytes()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_503_without_signing_key() {
        let state = AppState::new(None);
        let res = get_issuer_key(State(state)).await;
        let (status, _) = res.expect_err("must 503 without a signing key");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn returns_pubkey_matching_signing_key() {
        let seed = [7u8; 32];
        let mut state = AppState::new(None);
        state.ingest_signing_key = Some(seed);
        let Json(body) = get_issuer_key(State(state))
            .await
            .expect("must return the public key");
        // The handler's hex must equal the verifying key derived from the seed.
        let expected = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert_eq!(body.ed25519_pubkey_hex, expected);
        assert_eq!(body.ed25519_pubkey_hex.len(), 64);
    }
}
