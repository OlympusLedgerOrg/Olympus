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
//!
//! Historical keys (docs/key-rotation.md): every distinct ingest signing
//! pubkey this instance has ever loaded is recorded in `account_signing_keys`
//! (`purpose = 'ingest_signing'`, migration 0057) by
//! `bootstrap::ensure_ingest_signing_key`. `history` below surfaces that
//! registry so a verifier who only has this live endpoint — not an
//! out-of-band archive of retired keys — can still resolve which key signed
//! an older bundle, closing the gap `docs/key-rotation.md` previously
//! documented as unresolved ("Redaction bundles: `GET /redaction/issuer-key`
//! serves only the current key").

use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::SigningKey;
use serde::Serialize;

use crate::state::{self, AppState};

use super::types::{err, ApiError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerKeyHistoryEntry {
    /// Ed25519 verifying key (32 bytes, lowercase hex) that was active
    /// during this window.
    pub ed25519_pubkey_hex: String,
    /// RFC 3339 timestamp this key became active, or `null` if unbounded
    /// (the first-ever registered key, or any key registered before its
    /// exact activation time was known).
    pub valid_from: Option<String>,
    /// RFC 3339 timestamp this key was superseded, or `null` if it is the
    /// currently active key.
    pub valid_until: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerKeyResponse {
    /// The Ed25519 verifying key (32 bytes, lowercase hex) that signs V3
    /// redaction bundles produced by this instance. Unchanged field —
    /// existing consumers (the Redaction-audit UI's auto-fill) need no
    /// changes.
    pub ed25519_pubkey_hex: String,
    /// Every distinct ingest signing pubkey this instance has ever loaded,
    /// oldest first, including the current one (whose `validUntil` is
    /// `null`). Empty if the registry is unavailable (no DB pool) or has no
    /// rows yet (pre-registry installs that haven't restarted since
    /// upgrading) — callers should treat an empty history as "unknown", not
    /// as "no prior keys existed".
    pub history: Vec<IssuerKeyHistoryEntry>,
}

/// Return the Ed25519 public key matching the bundle signing key, plus its
/// registry history if a DB pool is available.
///
/// `503` if no ingest signing key is configured (same condition under which
/// `/redaction/redact` cannot sign a bundle).
pub async fn get_issuer_key(
    State(state): State<AppState>,
) -> Result<Json<IssuerKeyResponse>, ApiError> {
    let signing_key = state::secret_bytes(&state.ingest_signing_key).ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Redaction signing key unavailable: set OLYMPUS_INGEST_SIGNING_KEY \
             (or OLYMPUS_DEV_SIGNING_KEY=true in dev).",
        )
    })?;
    let vk = SigningKey::from_bytes(signing_key).verifying_key();
    let ed25519_pubkey_hex = hex::encode(vk.to_bytes());

    let history = match state.pool.as_ref() {
        Some(pool) => fetch_history(pool).await.unwrap_or_else(|e| {
            tracing::warn!("get_issuer_key: reading ingest-signing-key history: {e}");
            Vec::new()
        }),
        None => Vec::new(),
    };

    Ok(Json(IssuerKeyResponse {
        ed25519_pubkey_hex,
        history,
    }))
}

async fn fetch_history(pool: &sqlx::PgPool) -> Result<Vec<IssuerKeyHistoryEntry>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        public_key: String,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT public_key, valid_from, valid_until FROM account_signing_keys \
         WHERE purpose = 'ingest_signing' \
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| IssuerKeyHistoryEntry {
            ed25519_pubkey_hex: r.public_key,
            valid_from: r.valid_from.map(|t| t.to_rfc3339()),
            valid_until: r.valid_until.map(|t| t.to_rfc3339()),
        })
        .collect())
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
        state.ingest_signing_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(seed)));
        let Json(body) = get_issuer_key(State(state))
            .await
            .expect("must return the public key");
        // The handler's hex must equal the verifying key derived from the seed.
        let expected = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert_eq!(body.ed25519_pubkey_hex, expected);
        assert_eq!(body.ed25519_pubkey_hex.len(), 64);
    }

    #[tokio::test]
    async fn history_is_empty_without_a_pool() {
        // AppState::new(None) has no DB pool — the handler must degrade to
        // live-key-only rather than error, per the doc comment on `history`.
        let seed = [3u8; 32];
        let mut state = AppState::new(None);
        state.ingest_signing_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(seed)));
        let Json(body) = get_issuer_key(State(state))
            .await
            .expect("must return the public key even with no pool");
        assert!(
            body.history.is_empty(),
            "no pool means no history, not an error"
        );
    }
}
