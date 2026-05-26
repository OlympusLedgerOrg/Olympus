//! Federation quorum co-signing protocol.
//!
//! When a node issues a credential with `quorum: true`, it collects co-
//! signatures from its trusted peers over Tor so the credential can satisfy an
//! M-of-N federation quorum (see [`crate::quorum`]). This module has two sides:
//!
//!   * [`cosign_credential`] — the Tor-exposed `POST /federation/cosign`
//!     endpoint. A peer independently recomputes the credential's `commit_id`
//!     from the request fields (it never signs an opaque digest it didn't
//!     derive), authenticates the requester as one of *its own* trusted peers
//!     via the requester's quorum signature, and only then returns its own
//!     BJJ-EdDSA signature over the quorum message.
//!
//!   * [`collect_cosignatures`] — the issuing-node client. It signs the quorum
//!     message itself (its authority signature both authenticates the request
//!     and is one of the quorum signers), then asks each trusted peer to
//!     co-sign, verifying every returned signature against the peer's *pinned*
//!     pubkey before counting it.
//!
//! The endpoint requires NO API key — it is peer-facing and authenticated
//! cryptographically by the requester's quorum signature, exactly like
//! `receive_checkpoint`.

use std::time::Duration;

use axum::{extract::State, http::StatusCode, Json};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};

use crate::api::credentials::{compute_commit_id, compute_commit_id_for_commitment};
use crate::quorum::{quorum_cosign_message, CollectedSignature, QuorumSigner};
use crate::state::AppState;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

/// Per-request budget for an outbound co-sign call. Tor adds round-trips, so
/// this matches the gossip loop's generous timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a peer's co-sign response body — a few hundred bytes of JSON.
const MAX_COSIGN_BYTES: usize = 64 * 1024;
/// `Host` header for Tor-routed requests (the onion proxy targets loopback).
const LOOPBACK_HOST: &str = "127.0.0.1";

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

/// Co-sign request envelope. Carries everything a peer needs to (a) recompute
/// `commit_id` independently and (b) authenticate the requester.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignRequest {
    pub holder_key: String,
    pub credential_type: String,
    pub issued_at_unix: i64,
    /// Plaintext details (plaintext credential). Mutually exclusive with the
    /// commitment fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Pedersen commitment coordinates (committed credential). When present,
    /// `commit_id` is recomputed over the commitment, not the (absent) details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_y: Option<String>,
    /// Hex `commit_id` the requester claims — bound by independent recompute.
    pub commit_id: String,
    /// Requester's BJJ authority pubkey + quorum signature (authn token).
    pub requester_pubkey_x: String,
    pub requester_pubkey_y: String,
    pub requester_r8x: String,
    pub requester_r8y: String,
    pub requester_s: String,
}

/// Co-sign response: the peer's own BJJ pubkey + signature over the quorum
/// message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignResponse {
    pub signer_pubkey_x: String,
    pub signer_pubkey_y: String,
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Recompute the `commit_id` a co-sign request binds, dispatching on whether it
/// carries a Pedersen commitment or plaintext details. Returns the 32-byte
/// digest, or `None` if the request is internally inconsistent.
fn recompute_commit_id(req: &CosignRequest) -> Option<[u8; 32]> {
    match (req.commitment_x.as_deref(), req.commitment_y.as_deref()) {
        (Some(cx), Some(cy)) => Some(compute_commit_id_for_commitment(
            &req.holder_key,
            &req.credential_type,
            req.issued_at_unix,
            cx,
            cy,
        )),
        (None, None) => {
            let details = req.details.clone().unwrap_or_else(|| serde_json::json!({}));
            Some(compute_commit_id(
                &req.holder_key,
                &req.credential_type,
                req.issued_at_unix,
                &details,
            ))
        }
        // Exactly one commitment coordinate present — malformed.
        _ => None,
    }
}

/// `POST /federation/cosign` — independently verify a peer's credential and
/// return this node's quorum co-signature.
pub async fn cosign_credential(
    State(state): State<AppState>,
    Json(req): Json<CosignRequest>,
) -> Result<Json<CosignResponse>, ApiError> {
    let config = state
        .federation_config
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Federation not enabled"))?;
    if !config.enabled {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "Federation not enabled"));
    }
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))?;
    let bjj_key = state
        .bjj_authority_key
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ authority key not loaded"))?;
    let bjj_pubkey = state
        .bjj_authority_pubkey
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ authority pubkey not loaded"))?;

    // 1. Recompute commit_id from the request fields and require it to match
    //    the claimed value. The co-signer signs what IT derived, never an
    //    opaque blob handed to it.
    let commit_id = recompute_commit_id(&req)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed request (commitment fields)"))?;
    if hex::encode(commit_id) != req.commit_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "commit_id does not match the supplied credential fields",
        ));
    }

    let msg = quorum_cosign_message(&commit_id);

    // 2. Authenticate the requester: its quorum signature must verify over the
    //    quorum message, and its pubkey must be one of THIS node's trusted
    //    peers. Both gates fail closed.
    let requester = parse_pubkey(&req.requester_pubkey_x, &req.requester_pubkey_y)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester pubkey"))?;
    let requester_sig = parse_sig(&req.requester_r8x, &req.requester_r8y, &req.requester_s)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester signature"))?;
    if !baby_jubjub::verify_signature(&requester, &requester_sig, msg) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "requester signature does not verify over the quorum message",
        ));
    }
    if !requester_is_trusted_peer(pool, &req.requester_pubkey_x, &req.requester_pubkey_y).await? {
        return Err(err(
            StatusCode::FORBIDDEN,
            "requester is not a trusted peer of this node",
        ));
    }

    // 3. Co-sign the quorum message with this node's authority key.
    let sig = baby_jubjub::sign(&bjj_key, msg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    Ok(Json(CosignResponse {
        signer_pubkey_x: super::checkpoint::fr_to_decimal(&bjj_pubkey.x),
        signer_pubkey_y: super::checkpoint::fr_to_decimal(&bjj_pubkey.y),
        r8x: super::checkpoint::fr_to_decimal(&sig.r8x),
        r8y: super::checkpoint::fr_to_decimal(&sig.r8y),
        s: super::checkpoint::fr_to_decimal(&sig.s),
    }))
}

/// Is `(x, y)` a trusted peer's pinned pubkey? Compares against normalised
/// (canonical-decimal) coordinates so non-canonical encodings can't sneak past.
async fn requester_is_trusted_peer(
    pool: &sqlx::PgPool,
    x: &str,
    y: &str,
) -> Result<bool, ApiError> {
    let want = normalize_pair(x, y)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester pubkey"))?;
    let peers: Vec<(String, String)> = sqlx::query_as(
        "SELECT bjj_pubkey_x, bjj_pubkey_y FROM peer_nodes WHERE trust_status = 'trusted'",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    Ok(peers
        .iter()
        .filter_map(|(px, py)| normalize_pair(px, py))
        .any(|got| got == want))
}

/// Collect quorum co-signatures from trusted peers over Tor.
///
/// The issuing node signs the quorum message with its own authority key first
/// (that signature is the requester-authentication token AND one of the quorum
/// signers — added by the caller, not here). This function returns only the
/// *remote* peers' verified co-signatures, stopping once `threshold_remaining`
/// have been gathered.
///
/// Every returned signature is verified against the peer's PINNED pubkey (from
/// `peer_nodes`), never the pubkey the response claims — a peer can only
/// contribute a signature attributed to its registered identity.
#[allow(clippy::too_many_arguments)]
pub async fn collect_cosignatures(
    state: &AppState,
    commit_id: &[u8; 32],
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    details: Option<&serde_json::Value>,
    commitment: Option<(&str, &str)>,
    threshold_remaining: usize,
) -> Result<Vec<CollectedSignature>, String> {
    if threshold_remaining == 0 {
        return Ok(Vec::new());
    }
    let bjj_key = state
        .bjj_authority_key
        .ok_or_else(|| "BJJ authority key not loaded".to_owned())?;

    let handle = state
        .tor_handle
        .get()
        .ok_or_else(|| "Tor transport not ready (hidden service still bootstrapping)".to_owned())?;
    let client = handle.checkpoint_http_client();

    let pool = state.pool.as_ref().ok_or_else(|| "DB unavailable".to_owned())?;

    let msg = quorum_cosign_message(commit_id);
    // The issuing node's own quorum signature authenticates the request to peers.
    let requester_sig =
        baby_jubjub::sign(&bjj_key, msg).map_err(|e| format!("BJJ sign: {e}"))?;
    let requester_pubkey = state
        .bjj_authority_pubkey
        .as_ref()
        .ok_or_else(|| "BJJ authority pubkey not loaded".to_owned())?;

    let req = CosignRequest {
        holder_key: holder_key.to_owned(),
        credential_type: credential_type.to_owned(),
        issued_at_unix,
        details: details.cloned(),
        commitment_x: commitment.map(|(x, _)| x.to_owned()),
        commitment_y: commitment.map(|(_, y)| y.to_owned()),
        commit_id: hex::encode(commit_id),
        requester_pubkey_x: super::checkpoint::fr_to_decimal(&requester_pubkey.x),
        requester_pubkey_y: super::checkpoint::fr_to_decimal(&requester_pubkey.y),
        requester_r8x: super::checkpoint::fr_to_decimal(&requester_sig.r8x),
        requester_r8y: super::checkpoint::fr_to_decimal(&requester_sig.r8y),
        requester_s: super::checkpoint::fr_to_decimal(&requester_sig.s),
    };
    let body = serde_json::to_vec(&req).map_err(|e| format!("serialize: {e}"))?;

    let peers = super::peer::list_trusted_peers(pool)
        .await
        .map_err(|e| format!("list peers: {e}"))?;

    let mut collected: Vec<CollectedSignature> = Vec::new();
    for p in &peers {
        if collected.len() >= threshold_remaining {
            break;
        }
        match request_cosign(&client, &p.onion_address, &body).await {
            Ok(resp) => {
                // Verify against the PINNED peer pubkey, not the response's
                // claimed signer — bind the contribution to the peer identity.
                let Some(pinned) = parse_pubkey(&p.bjj_pubkey_x, &p.bjj_pubkey_y) else {
                    continue;
                };
                let Some(sig) = parse_sig(&resp.r8x, &resp.r8y, &resp.s) else {
                    continue;
                };
                if baby_jubjub::verify_signature(&pinned, &sig, msg) {
                    collected.push(CollectedSignature {
                        signer: QuorumSigner {
                            x: p.bjj_pubkey_x.clone(),
                            y: p.bjj_pubkey_y.clone(),
                        },
                        r8x: resp.r8x,
                        r8y: resp.r8y,
                        s: resp.s,
                    });
                } else {
                    tracing::debug!(
                        "federation: co-sign from {} did not verify against pinned pubkey",
                        p.onion_address
                    );
                }
            }
            Err(e) => {
                tracing::debug!("federation: co-sign request to {} failed: {e}", p.onion_address);
            }
        }
    }
    Ok(collected)
}

/// POST a co-sign request to one peer over Tor and parse its response.
async fn request_cosign(
    client: &super::tor::TorHttpClient,
    onion_address: &str,
    body: &[u8],
) -> Result<CosignResponse, String> {
    let uri = format!("http://{onion_address}/federation/cosign");
    let request = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(hyper::header::HOST, LOOPBACK_HOST)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_vec())))
        .map_err(|e| format!("build request: {e}"))?;

    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|e| format!("HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("peer returned {}", resp.status()));
    }
    let bytes = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(resp.into_body(), MAX_COSIGN_BYTES).collect(),
    )
    .await
    .map_err(|_| "timed out reading body".to_string())?
    .map_err(|e| format!("read body: {e}"))?
    .to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| format!("parse response: {e}"))
}

// ── Fr parsing helpers (strict, via zk::proof::parse_fr) ────────────────────

fn parse_pubkey(x: &str, y: &str) -> Option<BabyJubJubPubKey> {
    Some(BabyJubJubPubKey {
        x: crate::zk::proof::parse_fr(x).ok()?,
        y: crate::zk::proof::parse_fr(y).ok()?,
    })
}

fn parse_sig(r8x: &str, r8y: &str, s: &str) -> Option<BabyJubJubSignature> {
    Some(BabyJubJubSignature {
        r8x: crate::zk::proof::parse_fr(r8x).ok()?,
        r8y: crate::zk::proof::parse_fr(r8y).ok()?,
        s: crate::zk::proof::parse_fr(s).ok()?,
    })
}

fn normalize_pair(x: &str, y: &str) -> Option<(String, String)> {
    let px = crate::zk::proof::parse_fr(x).ok()?;
    let py = crate::zk::proof::parse_fr(y).ok()?;
    Some((
        super::checkpoint::fr_to_decimal(&px),
        super::checkpoint::fr_to_decimal(&py),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recompute_commit_id_plaintext_matches_credentials_helper() {
        let req = CosignRequest {
            holder_key: "alice".into(),
            credential_type: "press_credential".into(),
            issued_at_unix: 1_700_000_000,
            details: Some(serde_json::json!({"role": "journalist"})),
            commitment_x: None,
            commitment_y: None,
            commit_id: String::new(),
            requester_pubkey_x: "1".into(),
            requester_pubkey_y: "2".into(),
            requester_r8x: "0".into(),
            requester_r8y: "0".into(),
            requester_s: "0".into(),
        };
        let got = recompute_commit_id(&req).expect("recompute");
        let expected = compute_commit_id(
            "alice",
            "press_credential",
            1_700_000_000,
            &serde_json::json!({"role": "journalist"}),
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn recompute_commit_id_rejects_half_commitment() {
        let req = CosignRequest {
            holder_key: "a".into(),
            credential_type: "t".into(),
            issued_at_unix: 1,
            details: None,
            commitment_x: Some("1".into()),
            commitment_y: None,
            commit_id: String::new(),
            requester_pubkey_x: "1".into(),
            requester_pubkey_y: "2".into(),
            requester_r8x: "0".into(),
            requester_r8y: "0".into(),
            requester_s: "0".into(),
        };
        assert!(recompute_commit_id(&req).is_none());
    }

    #[test]
    fn recompute_commit_id_commitment_matches_helper() {
        let req = CosignRequest {
            holder_key: "a".into(),
            credential_type: "t".into(),
            issued_at_unix: 17,
            details: None,
            commitment_x: Some("123".into()),
            commitment_y: Some("456".into()),
            commit_id: String::new(),
            requester_pubkey_x: "1".into(),
            requester_pubkey_y: "2".into(),
            requester_r8x: "0".into(),
            requester_r8y: "0".into(),
            requester_s: "0".into(),
        };
        let got = recompute_commit_id(&req).expect("recompute");
        let expected = compute_commit_id_for_commitment("a", "t", 17, "123", "456");
        assert_eq!(got, expected);
    }
}
