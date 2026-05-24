//! Verify-then-store pipeline for inbound peer checkpoints.
//!
//! Audit H-11 / M-5 / H-12 share a root cause: `receive_checkpoint`
//! (push) and `process_received_checkpoint` (pull) each had their own
//! ad-hoc handling that skipped signature verification, ran equivocation
//! detection on unverified data, and silently fell back to the wrong
//! Groth16 verifier on missing artifacts. Centralise the contract here
//! so push and pull both get the same gates in the same order:
//!
//!   1. **BJJ signature must verify** against the peer's pinned pubkey
//!      and a canonical message digest (`Poseidon(ledger_root,
//!      checkpoint_timestamp)`). A missing or invalid signature fails
//!      closed — store nothing, run no equivocation logic.
//!   2. **Groth16 proof must verify** under the **unified** circuit's
//!      vkey. The historical `.or_else(existence_verifier)` fallback
//!      (audit H-5) is removed — different circuits have incompatible
//!      public-signal shapes, and silently demoting creates a
//!      verification hole. If the unified vkey isn't staged, the call
//!      surfaces a hard error instead.
//!   3. **Equivocation detection** runs only on verified checkpoints.
//!      The previous code flagged any conflict, then optionally
//!      auto-blocked the peer — letting an attacker who knew a peer's
//!      pubkey-but-not-priv-key push a forged equivocation and get the
//!      peer auto-blocked (audit H-12 / F-3).
//!   4. **Auto-block** still gates on the config flag, but only fires
//!      when (a) the inbound checkpoint verified AND (b) equivocation
//!      was detected. Both must be true. `auto_block_equivocators` also
//!      defaults to `false` now (audit H-12 default change).

use ark_bn254::Fr;
use sqlx::PgPool;
use uuid::Uuid;

use super::checkpoint::{self, PeerCheckpoint};
use super::equivocation;
use super::peer::PeerNode;
use super::FederationConfig;
use crate::zk::witness::baby_jubjub::{
    self, BabyJubJubPubKey, BabyJubJubSignature,
};

/// Outcome of [`verify_and_store`]. Caller can use these flags for
/// metrics / response bodies; the function itself is fail-closed and
/// will Err out on any verification failure before storing.
#[derive(Debug)]
pub struct VerifyOutcome {
    pub checkpoint_id: Uuid,
    /// Always `true` on success — kept in the response shape so a
    /// future "store-as-unverified" mode (e.g. backfill) can flip it
    /// without changing the API.
    pub signature_verified: bool,
    /// `true` iff the Groth16 proof verified under the unified circuit.
    /// `false` when `groth16_proof` is JSON null.
    pub proof_verified: bool,
    /// `true` iff this checkpoint conflicts with a previously-stored one
    /// from the same peer at the same timestamp. Only meaningful when
    /// `signature_verified == true`.
    pub equivocation_detected: bool,
    /// Whether the auto-block actually fired. Always implies
    /// `signature_verified && equivocation_detected &&
    /// config.auto_block_equivocators`.
    pub auto_blocked: bool,
}

/// Verify a checkpoint received from `peer` and, only if verification
/// succeeds, persist it + run equivocation detection.
///
/// Used by both the push handler (`api::receive_checkpoint`) and the
/// pull loop (`gossip::process_received_checkpoint`).
pub async fn verify_and_store(
    pool: &PgPool,
    config: &FederationConfig,
    peer: &PeerNode,
    cp: &PeerCheckpoint,
) -> Result<VerifyOutcome, String> {
    // 1. BJJ signature — fail closed on any missing or invalid field.
    verify_checkpoint_signature(peer, cp)?;

    // 2. Groth16 proof — only if attached. Use ONLY the unified verifier
    //    (audit H-5: no silent fallback to the existence verifier).
    let proof_verified = if cp.groth16_proof.is_null() {
        false
    } else {
        let cp_clone = cp.clone();
        tokio::task::spawn_blocking(move || verify_checkpoint_proof(&cp_clone))
            .await
            .map_err(|e| format!("verify join: {e}"))?
            .map_err(|e| format!("Groth16 verify: {e}"))?
    };

    // 3. Equivocation detection (only on verified checkpoints).
    let equivocated = equivocation::check_and_flag(
        pool,
        peer.id,
        cp.checkpoint_timestamp,
        &cp.ledger_root,
    )
    .await
    .map_err(|e| format!("equivocation check: {e}"))?;

    // 4. Auto-block — only when BOTH the sig was valid AND equivocation
    //    was detected AND the operator opted in.
    let auto_blocked = if equivocated && config.auto_block_equivocators {
        equivocation::auto_block_peer(pool, peer.id)
            .await
            .map_err(|e| format!("auto-block: {e}"))?;
        true
    } else {
        false
    };

    // 5. Store — flag the row as `verified = proof_verified` so the UI
    //    can distinguish "sig OK, proof OK" from "sig OK, proof absent".
    let checkpoint_id = checkpoint::store_peer_checkpoint(pool, peer.id, cp, proof_verified)
        .await
        .map_err(|e| format!("store: {e}"))?;

    Ok(VerifyOutcome {
        checkpoint_id,
        signature_verified: true,
        proof_verified,
        equivocation_detected: equivocated,
        auto_blocked,
    })
}

/// Verify the BJJ-EdDSA signature on a peer checkpoint.
///
/// Returns `Ok(())` on success; otherwise an explanatory `Err(String)`.
/// Fails closed on:
///   - missing `bjj_signature` block,
///   - any signature/pubkey field that isn't a parseable Fr,
///   - signature verification rejection by `baby_jubjub::verify_signature`
///     (which itself enforces R8 + pubkey subgroup membership before
///     delegating to iden3 — audit M-1).
fn verify_checkpoint_signature(peer: &PeerNode, cp: &PeerCheckpoint) -> Result<(), String> {
    let sig_wire = cp
        .bjj_signature
        .as_ref()
        .ok_or_else(|| "checkpoint missing bjj_signature".to_owned())?;

    // Parse the peer's pinned pubkey (from peer_nodes row).
    let px = crate::zk::proof::parse_fr(&peer.bjj_pubkey_x)
        .map_err(|e| format!("peer pubkey x parse: {e}"))?;
    let py = crate::zk::proof::parse_fr(&peer.bjj_pubkey_y)
        .map_err(|e| format!("peer pubkey y parse: {e}"))?;
    let pubkey = BabyJubJubPubKey { x: px, y: py };

    // Parse signature components.
    let r8x = crate::zk::proof::parse_fr(&sig_wire.r8x)
        .map_err(|e| format!("sig r8x parse: {e}"))?;
    let r8y = crate::zk::proof::parse_fr(&sig_wire.r8y)
        .map_err(|e| format!("sig r8y parse: {e}"))?;
    let s = crate::zk::proof::parse_fr(&sig_wire.s)
        .map_err(|e| format!("sig s parse: {e}"))?;
    let signature = BabyJubJubSignature { r8x, r8y, s };

    // Canonical message: Poseidon(ledger_root, checkpoint_timestamp).
    // Matches the producer in `checkpoint::build_own_checkpoint` —
    // changing this format requires bumping the wire version on both sides.
    let ledger_root = crate::zk::proof::parse_fr(&cp.ledger_root)
        .map_err(|e| format!("ledger_root parse: {e}"))?;
    let ts_fr = Fr::from(cp.checkpoint_timestamp as u64);
    let msg = crate::zk::poseidon::hash2(ledger_root, ts_fr)
        .map_err(|e| format!("poseidon: {e}"))?;

    if !baby_jubjub::verify_signature(&pubkey, &signature, msg) {
        return Err("BJJ signature verification failed".to_owned());
    }
    Ok(())
}

/// Verify the Groth16 proof attached to a peer checkpoint against the
/// **unified** circuit's vkey.
///
/// Audit H-5: the previous implementation chained
/// `.or_else(existence_verifier)` so it could "fall back" if the
/// unified vkey wasn't staged. That's a verification hole — the two
/// circuits expose different public-signal shapes, so demoting silently
/// would still produce a `verifier.verify()` call against the wrong
/// constraint system and might erroneously accept. Hard-error instead;
/// the operator gets a clean message and the gossip stops, rather than
/// passing forged checkpoints through.
fn verify_checkpoint_proof(cp: &PeerCheckpoint) -> Result<bool, String> {
    use crate::zk::proof::parse_signals_slice;

    let signals =
        parse_signals_slice(&cp.public_signals).map_err(|e| format!("signal parse: {e}"))?;
    let proof_json =
        serde_json::to_string(&cp.groth16_proof).map_err(|e| format!("proof json: {e}"))?;

    let verifier = crate::zk::verify::unified_verifier()
        .map_err(|e| format!("unified verifier init: {e}"))?;
    verifier
        .verify(&proof_json, &signals)
        .map_err(|e| format!("verify: {e}"))
}
