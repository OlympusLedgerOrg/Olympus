// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Checkpoint-quorum co-signing protocol (ADR-0033 "Remaining producer work").
//!
//! Mirrors [`super::cosign`] (the SBT-credential quorum co-sign protocol)
//! applied to a checkpoint `(chain_id, epoch, root)` instead of a credential
//! `commit_id`. Two sides:
//!
//!   * [`checkpoint_cosign`] — the Tor-exposed `POST /federation/checkpoint-cosign`
//!     endpoint. A peer authenticates the requester as one of *its own*
//!     trusted peers via the requester's quorum signature, then — the one
//!     property this protocol needs beyond the credential path, since there
//!     is no local computation to independently recompute a `ledger_root`
//!     from — requires that it has **already independently received and
//!     verified** a matching checkpoint from that exact requester via the
//!     ordinary gossip pull (`peer_checkpoints`, `verified = true`). Only
//!     then does it return its own BJJ-EdDSA signature over the quorum
//!     message. Without this gate a peer would blindly co-sign any
//!     `(chain_id, epoch, root)` triple a requester cared to ask for.
//!
//!   * [`collect_and_store_checkpoint_quorum`] — the per-round entry point the
//!     gossip loop calls after attempting to push this node's checkpoint to
//!     every trusted peer (so, for any peer the push reached, an honest
//!     peer's synchronous `receive_checkpoint` handler has already verified-
//!     and-stored it before collection asks it for a co-signature — see
//!     [`super::verify::verify_and_store`]; a peer the push failed to reach
//!     just rejects this round's request and the next round tries again).
//!     Self-signs first (that signature both authenticates the request and
//!     is one of the quorum signers), collects remaining co-signatures from
//!     trusted peers up to the pinned threshold, pins `(threshold, signers)`
//!     on the `own_checkpoints` row on the **first attempt** (not the first
//!     time the threshold is met — see the function doc for why), and
//!     persists every collected signature.
//!
//! The endpoint requires NO API key — same posture as `/federation/cosign` and
//! `/federation/checkpoint`: peer-facing, authenticated cryptographically by
//! the requester's quorum signature over the message it's asking to be
//! co-signed.

use std::time::Duration;

use ark_bn254::Fr;
use axum::{extract::State, http::StatusCode, Json};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};

use crate::quorum::checkpoint::{checkpoint_quorum_message, cosign_checkpoint};
use crate::quorum::{self, CollectedSignature, QuorumSigner};
use crate::state::AppState;
use crate::zk::proof::{fr_to_decimal, parse_fr};
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

/// Per-request budget for an outbound checkpoint co-sign call. Matches
/// [`super::cosign::REQUEST_TIMEOUT`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a peer's co-sign response body.
pub(crate) const MAX_CHECKPOINT_COSIGN_BYTES: usize = 64 * 1024;
/// Upper bound on a requester-supplied signer set, checked before any
/// authentication runs. A checkpoint quorum is an operator-curated peer set
/// (in practice single digits); without this bound, `MAX_CHECKPOINT_COSIGN_BYTES`
/// of JSON alone still fits thousands of `QuorumSigner` entries, letting an
/// unauthenticated caller on the Tor route force `checkpoint_quorum_message`
/// to fold a large set before the signature/trust checks below ever run.
const MAX_REQUEST_SIGNERS: usize = 64;
const LOOPBACK_HOST: &str = "127.0.0.1";

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

/// Co-sign request envelope for a checkpoint `(chain_id, epoch, root)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointCosignRequest {
    /// `fr_to_decimal(chain_id)` — the issuing ledger identity
    /// (`authority_pubkey_hash`).
    pub chain_id_dec: String,
    /// The checkpoint height (`tree_size`).
    pub epoch: i64,
    /// `fr_to_decimal(root)` — the checkpoint's Poseidon `ledger_root`.
    pub root_dec: String,
    /// Pinned quorum parameters the co-sign message binds (mirrors R3-01 for
    /// the SBT quorum path): the peer derives the quorum message from these,
    /// so a requester can only obtain a co-signature over the exact
    /// `(threshold, signer-set)` it will pin on the checkpoint row.
    pub threshold: u32,
    #[serde(default)]
    pub signers: Vec<QuorumSigner>,
    /// Requester's BJJ authority pubkey + quorum signature (authn token).
    pub requester_pubkey_x: String,
    pub requester_pubkey_y: String,
    pub requester_r8x: String,
    pub requester_r8y: String,
    pub requester_s: String,
}

/// Co-sign response: the peer's own BJJ pubkey + signature over the
/// checkpoint-quorum message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointCosignResponse {
    pub signer_pubkey_x: String,
    pub signer_pubkey_y: String,
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// `POST /federation/checkpoint-cosign` — authenticate the requester, require
/// that this node has already independently verified a matching checkpoint
/// from it, and return this node's checkpoint-quorum co-signature.
pub async fn checkpoint_cosign(
    State(state): State<AppState>,
    Json(req): Json<CheckpointCosignRequest>,
) -> Result<Json<CheckpointCosignResponse>, ApiError> {
    let config = state
        .federation_config
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Federation not enabled"))?;
    if !config.enabled {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Federation not enabled",
        ));
    }
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))?;
    let bjj_key = *crate::state::secret_bytes(&state.bjj_authority_key).ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority key not loaded",
        )
    })?;
    let bjj_pubkey = state.bjj_authority_pubkey.as_ref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority pubkey not loaded",
        )
    })?;

    if req.signers.len() > MAX_REQUEST_SIGNERS {
        return Err(err(StatusCode::BAD_REQUEST, "signer set too large"));
    }
    let chain_id = parse_fr(&req.chain_id_dec)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "malformed chain_id"))?;
    let root =
        parse_fr(&req.root_dec).map_err(|_| err(StatusCode::BAD_REQUEST, "malformed root"))?;

    // The message binds the requester-supplied quorum params (threshold +
    // signer set); we co-sign exactly what the requester will pin, so a
    // later tamper to either breaks every signature (mirrors R3-01).
    let msg = checkpoint_quorum_message(&chain_id, req.epoch, &root, req.threshold, &req.signers);

    // 1. Authenticate the requester: its quorum signature must verify over
    //    the checkpoint-quorum message, and its pubkey must be one of THIS
    //    node's trusted peers. Both gates fail closed.
    let requester = parse_pubkey(&req.requester_pubkey_x, &req.requester_pubkey_y)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester pubkey"))?;
    let requester_sig = parse_sig(&req.requester_r8x, &req.requester_r8y, &req.requester_s)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester signature"))?;
    if !baby_jubjub::verify_signature(&requester, &requester_sig, msg) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "requester signature does not verify over the checkpoint-quorum message",
        ));
    }
    if !requester_is_trusted_peer(pool, &req.requester_pubkey_x, &req.requester_pubkey_y).await? {
        return Err(err(
            StatusCode::FORBIDDEN,
            "requester is not a trusted peer",
        ));
    }

    // 2. The property this protocol needs beyond the credential co-sign path:
    //    there is no local computation that independently recomputes a
    //    `ledger_root` from request fields, so instead require that we have
    //    ALREADY independently verified a checkpoint matching this exact
    //    identity FROM this exact requester via ordinary gossip pull. Without
    //    this, a peer would sign any (chain_id, epoch, root) triple a
    //    requester cared to ask for — a blind co-sign.
    if !requester_has_verified_matching_checkpoint(
        pool,
        &req.requester_pubkey_x,
        &req.requester_pubkey_y,
        &req.chain_id_dec,
        req.epoch,
        &req.root_dec,
    )
    .await?
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "no independently verified checkpoint matches this identity from this requester",
        ));
    }

    // 3. Co-sign the checkpoint-quorum message with this node's authority key.
    let sig = baby_jubjub::sign(&bjj_key, msg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    Ok(Json(CheckpointCosignResponse {
        signer_pubkey_x: fr_to_decimal(&bjj_pubkey.x),
        signer_pubkey_y: fr_to_decimal(&bjj_pubkey.y),
        r8x: fr_to_decimal(&sig.r8x),
        r8y: fr_to_decimal(&sig.r8y),
        s: fr_to_decimal(&sig.s),
    }))
}

/// Is `(x, y)` a trusted, non-removed peer's pinned pubkey? Compares against
/// normalised (canonical-decimal) coordinates.
async fn requester_is_trusted_peer(
    pool: &sqlx::PgPool,
    x: &str,
    y: &str,
) -> Result<bool, ApiError> {
    let (nx, ny) =
        normalize_pair(x, y).ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed pubkey"))?;
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1::bigint FROM peer_nodes
          WHERE trust_status = 'trusted'
            AND removed_at IS NULL
            AND bjj_pubkey_x = $1
            AND bjj_pubkey_y = $2",
    )
    .bind(&nx)
    .bind(&ny)
    .fetch_optional(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    Ok(row.is_some())
}

/// Has this node already stored a `verified = true` checkpoint from the peer
/// identified by `(requester_x, requester_y)` matching the exact
/// `(chain_id_dec, epoch, root_dec)` identity? This is the independent-
/// verification gate: it never trusts the request's own claim, only what our
/// own `receive_checkpoint`/gossip-pull path already checked and stored.
async fn requester_has_verified_matching_checkpoint(
    pool: &sqlx::PgPool,
    requester_x: &str,
    requester_y: &str,
    chain_id_dec: &str,
    epoch: i64,
    root_dec: &str,
) -> Result<bool, ApiError> {
    let (nx, ny) = normalize_pair(requester_x, requester_y)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "malformed requester pubkey"))?;
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1::bigint FROM peer_checkpoints
          WHERE signer_pubkey_x = $1
            AND signer_pubkey_y = $2
            AND authority_pubkey_hash = $3
            AND tree_size = $4
            AND ledger_root = $5
            AND verified = TRUE
          LIMIT 1",
    )
    .bind(&nx)
    .bind(&ny)
    .bind(chain_id_dec)
    .bind(epoch)
    .bind(root_dec)
    .fetch_optional(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    Ok(row.is_some())
}

/// Collect checkpoint-quorum co-signatures from trusted peers over Tor.
///
/// Returns only the *remote* peers' verified co-signatures — the caller adds
/// its own self-signature separately (mirrors [`super::cosign::collect_cosignatures`]).
/// Every returned signature is verified against the peer's PINNED pubkey
/// (from `peer_nodes`), never the pubkey the response claims.
#[allow(clippy::too_many_arguments)]
async fn collect_checkpoint_cosignatures(
    pool: &sqlx::PgPool,
    bjj_key: &[u8; 32],
    client: &super::tor::TorHttpClient,
    chain_id: &Fr,
    epoch: i64,
    root: &Fr,
    threshold: u32,
    signers: &[QuorumSigner],
    threshold_remaining: usize,
) -> Result<Vec<CollectedSignature>, String> {
    if threshold_remaining == 0 {
        return Ok(Vec::new());
    }

    let msg = checkpoint_quorum_message(chain_id, epoch, root, threshold, signers);
    // The issuing node's own quorum signature authenticates the request to peers.
    let requester_sig = baby_jubjub::sign(bjj_key, msg).map_err(|e| format!("BJJ sign: {e}"))?;
    let requester_pubkey =
        BabyJubJubPubKey::from_private(bjj_key).map_err(|e| format!("derive pubkey: {e}"))?;

    let req = CheckpointCosignRequest {
        chain_id_dec: fr_to_decimal(chain_id),
        epoch,
        root_dec: fr_to_decimal(root),
        threshold,
        signers: signers.to_vec(),
        requester_pubkey_x: fr_to_decimal(&requester_pubkey.x),
        requester_pubkey_y: fr_to_decimal(&requester_pubkey.y),
        requester_r8x: fr_to_decimal(&requester_sig.r8x),
        requester_r8y: fr_to_decimal(&requester_sig.r8y),
        requester_s: fr_to_decimal(&requester_sig.s),
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
        match request_checkpoint_cosign(client, &p.onion_address, &body).await {
            Ok(resp) => {
                // Verify against the PINNED peer pubkey, not the response's
                // claimed signer.
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
                        "federation: checkpoint co-sign from {} did not verify against pinned pubkey",
                        p.onion_address
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    "federation: checkpoint co-sign request to {} failed: {e}",
                    p.onion_address
                );
            }
        }
    }
    Ok(collected)
}

/// POST a checkpoint co-sign request to one peer over Tor and parse its
/// response.
async fn request_checkpoint_cosign(
    client: &super::tor::TorHttpClient,
    onion_address: &str,
    body: &[u8],
) -> Result<CheckpointCosignResponse, String> {
    let uri = format!("http://{onion_address}/federation/checkpoint-cosign");
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
        Limited::new(resp.into_body(), MAX_CHECKPOINT_COSIGN_BYTES).collect(),
    )
    .await
    .map_err(|_| "timed out reading body".to_string())?
    .map_err(|e| format!("read body: {e}"))?
    .to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| format!("parse response: {e}"))
}

/// Per-round entry point: collect and pin checkpoint-quorum co-signatures for
/// this node's latest gossipable checkpoint.
///
/// Called by the gossip loop after attempting to push our checkpoint to every
/// trusted peer, so for any peer that push reached, its synchronous
/// `receive_checkpoint` handler has already verified-and-stored it by the
/// time this asks for a co-signature (see the module doc). No-ops (not an
/// error) when: there is no gossipable checkpoint yet, there are fewer than
/// two pinned signers (no trusted peers — a 1-of-1 "quorum" would be a
/// self-satisfied no-op not worth persisting), the configured threshold
/// exceeds the signer set (mathematically unsatisfiable — logged, not
/// pinned, so a later signer-set change gets a fresh attempt instead of a
/// permanently-stuck pin), or the checkpoint's quorum is already satisfied
/// by previously-collected signatures.
///
/// Pins `(threshold, signers)` on the **first attempt**, not the first time
/// the threshold is met. This is deliberate, not a shortcut: pinning is what
/// lets signatures accumulate ACROSS gossip rounds against the same signed
/// message (a later round reuses the pinned values instead of recomputing
/// fresh ones from `trusted_signer_set`, which could legitimately drift if a
/// peer is added/removed between rounds). Deferring the pin until success
/// would mean each unsatisfied round signs a *different* message — nothing
/// from an earlier round would ever count toward a later one, i.e. the
/// checkpoint could never accumulate its way to quorum at all.
pub async fn collect_and_store_checkpoint_quorum(
    pool: &sqlx::PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    client: &super::tor::TorHttpClient,
) -> Result<(), String> {
    let Some(row) = crate::anchoring::own_checkpoint::fetch_latest_gossipable(pool).await? else {
        return Ok(());
    };
    let Some(authority_pubkey_hash) = row.authority_pubkey_hash.as_deref() else {
        return Ok(());
    };
    let chain_id = parse_fr(authority_pubkey_hash).map_err(|e| format!("parse chain_id: {e}"))?;
    let root = parse_fr(&row.ledger_root).map_err(|e| format!("parse root: {e}"))?;
    let epoch = row.tree_size;

    // Reuse the already-pinned (threshold, signers) if this checkpoint has
    // been attempted before; otherwise compute fresh ones. Pinning happens
    // once, below, via `set_checkpoint_quorum_params`'s one-shot guard. Fail
    // closed on a corrupt pinned value rather than silently treating it as
    // "no signers" — that would fall through the `signers.len() < 2` no-op
    // below and mask the corruption as ordinary no-peers-configured.
    let (threshold, signers): (u32, Vec<QuorumSigner>) = match (
        row.checkpoint_quorum_threshold,
        &row.checkpoint_quorum_signers,
    ) {
        (Some(t), Some(s)) => (
            t.max(1) as u32,
            serde_json::from_value(s.clone())
                .map_err(|e| format!("pinned checkpoint_quorum_signers is corrupt: {e}"))?,
        ),
        _ => {
            let threshold = crate::quorum::checkpoint::configured_checkpoint_threshold();
            let signers = quorum::trusted_signer_set(pool, bjj_pubkey)
                .await
                .map_err(|e| format!("trusted signer set: {e}"))?;
            (threshold, signers)
        }
    };

    // No trusted peers: a 1-of-1 "quorum" is self-satisfied and not worth
    // persisting every round.
    if signers.len() < 2 {
        return Ok(());
    }
    // A threshold above the signer set can never be satisfied
    // (`verify_checkpoint_quorum` requires `valid_signatures >= threshold`,
    // bounded above by `signers.len()`). Skip rather than pin an
    // unsatisfiable configuration — the one-shot guard would lock it in
    // until an operator manually intervenes.
    if threshold as usize > signers.len() {
        tracing::warn!(
            "federation: checkpoint quorum threshold {threshold} exceeds the {} pinned \
             signers; skipping collection for checkpoint {} until the signer set grows",
            signers.len(),
            row.id
        );
        return Ok(());
    }

    // Skip if already satisfied by previously-collected signatures — avoids
    // a redundant Tor round-trip to every peer on every gossip tick.
    let existing = crate::quorum::checkpoint::load_checkpoint_quorum_signatures(pool, row.id)
        .await
        .map_err(|e| format!("load existing signatures: {e}"))?;
    if crate::quorum::checkpoint::verify_checkpoint_quorum(
        &chain_id, epoch, &root, &signers, threshold, &existing,
    )
    .satisfied
    {
        return Ok(());
    }

    let self_sig = cosign_checkpoint(bjj_key, &chain_id, epoch, &root, threshold, &signers)
        .map_err(|e| format!("self-sign checkpoint quorum: {e}"))?;
    let mut collected = vec![self_sig];

    let remaining = (threshold as usize).saturating_sub(collected.len());
    if remaining > 0 {
        match collect_checkpoint_cosignatures(
            pool, bjj_key, client, &chain_id, epoch, &root, threshold, &signers, remaining,
        )
        .await
        {
            Ok(mut remote) => collected.append(&mut remote),
            Err(e) => tracing::debug!("federation: checkpoint quorum peer collection failed: {e}"),
        }
    }

    crate::anchoring::own_checkpoint::set_checkpoint_quorum_params(
        pool, row.id, threshold, &signers,
    )
    .await
    .map_err(|e| format!("pin checkpoint quorum params: {e}"))?;
    crate::quorum::checkpoint::store_checkpoint_quorum_signatures(pool, row.id, &collected)
        .await
        .map_err(|e| format!("store checkpoint quorum signatures: {e}"))?;
    Ok(())
}

fn parse_pubkey(x: &str, y: &str) -> Option<BabyJubJubPubKey> {
    Some(BabyJubJubPubKey {
        x: parse_fr(x).ok()?,
        y: parse_fr(y).ok()?,
    })
}

fn parse_sig(r8x: &str, r8y: &str, s: &str) -> Option<BabyJubJubSignature> {
    Some(BabyJubJubSignature {
        r8x: parse_fr(r8x).ok()?,
        r8y: parse_fr(r8y).ok()?,
        s: parse_fr(s).ok()?,
    })
}

fn normalize_pair(x: &str, y: &str) -> Option<(String, String)> {
    let px = parse_fr(x).ok()?;
    let py = parse_fr(y).ok()?;
    Some((fr_to_decimal(&px), fr_to_decimal(&py)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_cosign_request_round_trips_through_json() {
        let req = CheckpointCosignRequest {
            chain_id_dec: "7".into(),
            epoch: 42,
            root_dec: "123456".into(),
            threshold: 2,
            signers: vec![QuorumSigner {
                x: "1".into(),
                y: "2".into(),
            }],
            requester_pubkey_x: "3".into(),
            requester_pubkey_y: "4".into(),
            requester_r8x: "5".into(),
            requester_r8y: "6".into(),
            requester_s: "7".into(),
        };
        let bytes = serde_json::to_vec(&req).expect("serialize");
        let back: CheckpointCosignRequest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back.chain_id_dec, "7");
        assert_eq!(back.epoch, 42);
        assert_eq!(back.root_dec, "123456");
        assert_eq!(back.threshold, 2);
        assert_eq!(back.signers, req.signers);
    }

    /// The request's message construction must exactly match what a peer
    /// re-derives on receipt — i.e. `collect_checkpoint_cosignatures`'s wire
    /// fields feed [`checkpoint_quorum_message`] byte-for-byte the same way
    /// the handler does when it parses them back. This pins that both sides
    /// go through the same `fr_to_decimal`/`parse_fr` round trip rather than,
    /// say, one side using raw decimal digits and the other a hex encoding.
    #[test]
    fn wire_decimal_round_trip_matches_direct_fr_construction() {
        let chain_id = Fr::from(7u64);
        let root = Fr::from(123456u64);
        let signers = vec![QuorumSigner {
            x: "1".into(),
            y: "2".into(),
        }];

        let direct = checkpoint_quorum_message(&chain_id, 42, &root, 2, &signers);

        let chain_id_dec = fr_to_decimal(&chain_id);
        let root_dec = fr_to_decimal(&root);
        let reparsed_chain = parse_fr(&chain_id_dec).expect("parse chain_id_dec");
        let reparsed_root = parse_fr(&root_dec).expect("parse root_dec");
        let via_wire = checkpoint_quorum_message(&reparsed_chain, 42, &reparsed_root, 2, &signers);

        assert_eq!(direct, via_wire);
    }
}
