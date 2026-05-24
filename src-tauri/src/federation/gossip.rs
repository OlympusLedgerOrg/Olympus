//! Background gossip loop — periodically exchange checkpoints with trusted peers.

use sqlx::PgPool;

use super::checkpoint::{self, PeerCheckpoint};
use super::peer::{self, PeerNode};
use super::FederationConfig;
use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// Spawn the background gossip task. Returns a `JoinHandle` for shutdown.
pub fn spawn(
    pool: PgPool,
    config: FederationConfig,
    bjj_key: [u8; 32],
    bjj_pubkey: BabyJubJubPubKey,
    http_client: reqwest::Client,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(config.sync_interval_secs);
        tracing::info!(
            "federation: gossip loop started (interval={}s)",
            config.sync_interval_secs
        );

        loop {
            tokio::time::sleep(interval).await;

            if let Err(e) = sync_round(&pool, &config, &bjj_key, &bjj_pubkey, &http_client).await
            {
                tracing::warn!("federation: gossip round failed: {e}");
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
    http: &reqwest::Client,
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
            if let Err(e) = push_checkpoint(http, &p.onion_address, cp).await {
                tracing::debug!("federation: push to {} failed: {e}", p.onion_address);
            }
        }

        // Pull the peer's latest checkpoint.
        match pull_checkpoint(http, &p.onion_address).await {
            Ok(Some(remote_cp)) => {
                if let Err(e) = process_received_checkpoint(pool, config, p, &remote_cp).await {
                    tracing::warn!(
                        "federation: process checkpoint from {} failed: {e}",
                        p.onion_address
                    );
                }
                let _ = peer::touch_last_seen(pool, p.id).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("federation: pull from {} failed: {e}", p.onion_address);
            }
        }
    }

    Ok(())
}

/// Push our checkpoint to a peer's federation endpoint.
async fn push_checkpoint(
    http: &reqwest::Client,
    onion_address: &str,
    cp: &PeerCheckpoint,
) -> Result<(), String> {
    let url = format!("http://{}/federation/checkpoint", onion_address);
    let resp = http
        .post(&url)
        .json(cp)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("HTTP: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("peer returned {}", resp.status()));
    }
    Ok(())
}

/// Pull the latest checkpoint from a peer.
async fn pull_checkpoint(
    http: &reqwest::Client,
    onion_address: &str,
) -> Result<Option<PeerCheckpoint>, String> {
    let url = format!("http://{}/federation/checkpoint/latest", onion_address);
    let resp = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("HTTP: {e}"))?;

    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("peer returned {}", resp.status()));
    }

    let cp: PeerCheckpoint = resp.json().await.map_err(|e| format!("parse: {e}"))?;
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
