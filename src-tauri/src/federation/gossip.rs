//! Background gossip loop — periodically exchange checkpoints with trusted peers.

use sqlx::PgPool;
use std::sync::Arc;

use super::checkpoint::{self, PeerCheckpoint};
use super::equivocation;
use super::peer;
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
                if let Err(e) =
                    process_received_checkpoint(pool, config, p.id, &remote_cp).await
                {
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
async fn process_received_checkpoint(
    pool: &PgPool,
    config: &FederationConfig,
    peer_id: uuid::Uuid,
    cp: &PeerCheckpoint,
) -> Result<(), String> {
    // Verify the Groth16 proof if present.
    let verified = if cp.groth16_proof.is_null() {
        false
    } else {
        verify_checkpoint_proof(cp)?
    };

    // Check for equivocation before storing.
    let equivocated =
        equivocation::check_and_flag(pool, peer_id, cp.checkpoint_timestamp, &cp.ledger_root)
            .await
            .map_err(|e| format!("equivocation check: {e}"))?;

    if equivocated && config.auto_block_equivocators {
        let _ = equivocation::auto_block_peer(pool, peer_id).await;
    }

    checkpoint::store_peer_checkpoint(pool, peer_id, cp, verified)
        .await
        .map_err(|e| format!("store: {e}"))?;

    Ok(())
}

/// Verify a checkpoint's Groth16 proof against the embedded unified circuit vkey.
fn verify_checkpoint_proof(cp: &PeerCheckpoint) -> Result<bool, String> {
    use crate::zk::proof::{parse_fr, parse_signals_slice};

    let signals = parse_signals_slice(&cp.public_signals)
        .map_err(|e| format!("signal parse: {e}"))?;

    let proof_json =
        serde_json::to_string(&cp.groth16_proof).map_err(|e| format!("proof json: {e}"))?;

    // Use the existence verifier as a stand-in; in production the unified
    // circuit verifier would be used once the unified vkey is embedded.
    // TODO: Switch to unified_verifier() when the unified vkey is available.
    let verifier = crate::zk::verify::existence_verifier()
        .map_err(|e| format!("verifier init: {e}"))?;

    verifier
        .verify(&proof_json, &signals)
        .map_err(|e| format!("verify: {e}"))
}
