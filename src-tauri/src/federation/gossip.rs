//! Background gossip loop — periodically exchange checkpoints with trusted peers.
//!
//! Outbound requests are routed through this node's embedded Tor client
//! (see [`super::tor`]). A plain `reqwest`/`hyper` client cannot resolve a
//! `.onion` host — the [`TorHttpClient`] connects via `arti` instead, so the
//! URI authority (`<peer>.onion`) drives Tor routing.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use sqlx::PgPool;

use super::checkpoint::{self, PeerCheckpoint};
use super::peer::{self, PeerNode};
use super::tor::{TorHandle, TorHttpClient};
use super::FederationConfig;
use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// Per-request wall-clock budget for an outbound gossip call. Tor adds
/// several round-trips of latency, so this is deliberately generous.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on a peer's checkpoint response body. A `PeerCheckpoint` is a
/// few hundred bytes of JSON; cap the read so a hostile peer can't stream an
/// unbounded body into our heap.
const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;

/// `Host` header sent on every outbound gossip request.
///
/// The peer is reached through its Tor hidden service, which proxies the
/// accepted stream to a loopback port guarded by `server::validate_loopback_host`.
/// That guard rejects any `Host` that isn't loopback, so federation requests
/// must present a loopback `Host` even though the URI authority is the peer's
/// `.onion` (the authority drives Tor routing; the header satisfies the guard).
const LOOPBACK_HOST: &str = "127.0.0.1";

/// Spawn the background gossip task. Returns a `JoinHandle` for shutdown.
///
/// `tor` is held for the task's lifetime so the hidden service stays up and
/// the Tor-routed HTTP client keeps working.
pub fn spawn(
    pool: PgPool,
    config: FederationConfig,
    bjj_key: [u8; 32],
    bjj_pubkey: BabyJubJubPubKey,
    tor: Arc<TorHandle>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = tor.checkpoint_http_client();
        let interval = Duration::from_secs(config.sync_interval_secs);
        tracing::info!(
            "federation: gossip loop started (interval={}s)",
            config.sync_interval_secs
        );

        loop {
            tokio::time::sleep(interval).await;

            if let Err(e) = sync_round(&pool, &config, &bjj_key, &bjj_pubkey, &client).await {
                tracing::warn!("federation: gossip round failed: {}", e);
            }
        }
    })
}

/// One gossip round: push our checkpoint to all trusted peers, pull theirs.
async fn sync_round(
    pool: &PgPool,
    config: &FederationConfig,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    client: &TorHttpClient,
) -> Result<(), String> {
    let peers = peer::list_trusted_peers(pool)
        .await
        .map_err(|e| format!("list peers: {e}"))?;

    if peers.is_empty() {
        return Ok(());
    }

    // Build our own checkpoint.
    let own_checkpoint = checkpoint::build_own_checkpoint(pool, bjj_key, bjj_pubkey).await?;

    for p in &peers {
        // Push our checkpoint to the peer.
        if let Some(ref cp) = own_checkpoint {
            if let Err(e) = push_checkpoint(client, &p.onion_address, cp).await {
                tracing::debug!("federation: push to {} failed: {e}", p.onion_address);
            }
        }

        // Pull the peer's latest checkpoint.
        // Audit L-F2: persist pull failures to peer_nodes so admin tooling
        // can show "this peer has been failing for N rounds" without
        // operators having to tail logs. On success, touch_last_seen
        // clears the error fields so a recovered peer shows healthy
        // immediately.
        match pull_checkpoint(client, &p.onion_address).await {
            Ok(Some(remote_cp)) => {
                match process_received_checkpoint(pool, config, p, &remote_cp).await {
                    Ok(()) => {
                        let _ = peer::touch_last_seen(pool, p.id).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "federation: process checkpoint from {} failed: {e}",
                            p.onion_address
                        );
                        let _ = peer::record_pull_error(
                            pool,
                            p.id,
                            &format!("process: {e}"),
                        )
                        .await;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("federation: pull from {} failed: {e}", p.onion_address);
                let _ = peer::record_pull_error(pool, p.id, &format!("pull: {e}")).await;
            }
        }
    }

    Ok(())
}

/// Push our checkpoint to a peer's federation endpoint over Tor.
async fn push_checkpoint(
    client: &TorHttpClient,
    onion_address: &str,
    cp: &PeerCheckpoint,
) -> Result<(), String> {
    // CLAUDE.md invariant: federation wire bytes are JCS / RFC 8785.
    // Routed through the shared `canonical_checkpoint_bytes` helper so
    // push (here) and the GET-latest emission in `api.rs` produce
    // byte-identical encodings for the same logical checkpoint.
    let body = checkpoint::canonical_checkpoint_bytes(cp)?;
    let uri = format!("http://{onion_address}/federation/checkpoint");
    let req = Request::builder()
        .method(Method::POST)
        .uri(&uri)
        .header(hyper::header::HOST, LOOPBACK_HOST)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("build request: {e}"))?;

    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(req))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|e| format!("HTTP: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("peer returned {}", resp.status()));
    }
    Ok(())
}

/// Pull the latest checkpoint from a peer over Tor.
async fn pull_checkpoint(
    client: &TorHttpClient,
    onion_address: &str,
) -> Result<Option<PeerCheckpoint>, String> {
    let uri = format!("http://{onion_address}/federation/checkpoint/latest");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .header(hyper::header::HOST, LOOPBACK_HOST)
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("build request: {e}"))?;

    let resp = tokio::time::timeout(REQUEST_TIMEOUT, client.request(req))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|e| format!("HTTP: {e}"))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(format!("peer returned {}", status));
    }

    // CodeRabbit follow-up: the outer `tokio::time::timeout` only bounds
    // header receipt via `client.request`; without wrapping the body
    // collect, a peer that sends headers fast but stalls mid-body would
    // hang the gossip pull worker until the underlying TCP stack gives
    // up. Bound the body read against the same REQUEST_TIMEOUT so slow
    // peers cannot stall the pull loop.
    let bytes = tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(resp.into_body(), MAX_CHECKPOINT_BYTES).collect(),
    )
    .await
    .map_err(|_| "request timed out while reading body".to_string())?
    .map_err(|e| format!("read body: {e}"))?
    .to_bytes();

    // Strict JCS-on-receive: reject any envelope whose bytes are not
    // byte-exact RFC 8785 canonical JSON. Pairs with
    // `canonical_checkpoint_bytes` on the emit side so the federation
    // wire is canonical end-to-end (CLAUDE.md invariant).
    let cp = checkpoint::parse_canonical_checkpoint(&bytes)?;
    Ok(Some(cp))
}

/// Verify and store a checkpoint received from a peer.
///
/// Audit H-11 / H-5 / H-12: delegates the entire verify-then-store
/// pipeline (BJJ signature → unified Groth16 vkey [no fallback] →
/// equivocation → conditional auto-block → store) to the shared
/// `super::verify::verify_and_store`. The push handler in `api.rs`
/// uses the same call, so push and pull can never drift.
async fn process_received_checkpoint(
    pool: &PgPool,
    config: &FederationConfig,
    peer: &PeerNode,
    cp: &PeerCheckpoint,
) -> Result<(), String> {
    super::verify::verify_and_store(pool, config, peer, cp).await?;
    Ok(())
}
